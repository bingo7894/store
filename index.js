const express = require("express");
const { Pool } = require("pg");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const cookieParser = require("cookie-parser");
const path = require("path");
const stripe = require("stripe")("sk_test_");

// ===== CONFIGURATION =====
const app = express();
const PORT = 8000;
const secret = "mysecret";
const stripeWebhookSecret = "whsec_a";

// ===== DATABASE CONNECTION =====
const pool = new Pool({
  user: "postgres",
  host: "localhost",
  database: "users",
  password: "Di7gmrsko8",
  port: 5432,
});

// ===== MIDDLEWARE SETUP =====
// [แก้ไข] Stripe Webhook: ส่วนนี้คือหัวใจของการแก้ไขปัญหา
app.post(
  "/api/stripe-webhook",
  express.raw({ type: "application/json" }),
  async (req, res) => {
    const sig = req.headers["stripe-signature"];
    let event;

    try {
      event = stripe.webhooks.constructEvent(
        req.body,
        sig,
        stripeWebhookSecret
      );
    } catch (err) {
      console.error(`Webhook signature verification failed.`, err.message);
      return res.status(400).send(`Webhook Error: ${err.message}`);
    }

    if (event.type === "payment_intent.succeeded") {
      const paymentIntent = event.data.object;
      console.log("✅ PaymentIntent was successful!", paymentIntent.id);

      const userId = paymentIntent.metadata.userId;
      if (!userId) {
        console.error("Error: Missing userId in payment intent metadata.");
        return res.status(200).json({ received: true });
      }

      const client = await pool.connect();
      try {
        await client.query("BEGIN"); // เริ่ม Transaction

        const existingOrder = await client.query(
          "SELECT id FROM orders WHERE stripe_payment_intent_id = $1",
          [paymentIntent.id]
        );

        if (existingOrder.rows.length > 0) {
          console.log(
            `Order for PaymentIntent ${paymentIntent.id} already exists.`
          );
        } else {
          // --- [จุดแก้ไขที่ 1] ---
          // 1. ดึงข้อมูลโปรไฟล์ (ที่อยู่) ของ User ณ เวลาที่จ่ายเงินสำเร็จ
          const userProfileRes = await client.query(
            // ใช้ CONCAT เพื่อรวม firstname และ lastname
            "SELECT CONCAT(firstname, ' ', lastname) AS full_name, phone, address FROM users WHERE id = $1",
            [userId]
          );

          if (userProfileRes.rows.length === 0) {
            throw new Error(
              `User with ID ${userId} not found for order creation.`
            );
          }
          const userProfile = userProfileRes.rows[0];

          // 2. ดึงข้อมูลสินค้าในตะกร้า (เหมือนเดิม)
          const cartRes = await client.query(
            `SELECT ci.product_id, ci.quantity, p.price FROM cart_items ci JOIN products p ON ci.product_id = p.id WHERE ci.user_id = $1 AND p.is_active = TRUE`,
            [userId]
          );
          const cartItems = cartRes.rows;
          if (cartItems.length === 0) {
            throw new Error("Cannot create order from an empty cart.");
          }

          // --- [จุดแก้ไขที่ 2] ---
          // 3. สร้าง Order โดย "Snapshot" ข้อมูลที่อยู่ลงไปในตาราง orders
          const totalAmount = paymentIntent.amount / 100;
          const orderInsertRes = await client.query(
            `INSERT INTO orders (user_id, total_amount, stripe_payment_intent_id, status, recipient_name, recipient_phone, shipping_address) 
             VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id`,
            [
              userId,
              totalAmount,
              paymentIntent.id,
              "paid",
              userProfile.full_name, // <-- บันทึกชื่อผู้รับ
              userProfile.phone, // <-- บันทึกเบอร์โทร
              userProfile.address, // <-- บันทึกที่อยู่
            ]
          );
          const newOrderId = orderInsertRes.rows[0].id;

          // 4. บันทึกรายการสินค้า (เหมือนเดิม)
          const orderItemPromises = cartItems.map((item) => {
            return client.query(
              "INSERT INTO order_items (order_id, product_id, quantity, price_at_purchase) VALUES ($1, $2, $3, $4)",
              [newOrderId, item.product_id, item.quantity, item.price]
            );
          });
          await Promise.all(orderItemPromises);

          // 5. ล้างตะกร้า (เหมือนเดิม)
          await client.query("DELETE FROM cart_items WHERE user_id = $1", [
            userId,
          ]);
          console.log(
            `Order ${newOrderId} created successfully for user ${userId}.`
          );
        }
        await client.query("COMMIT");
      } catch (err) {
        await client.query("ROLLBACK");
        console.error("Error creating order:", err);
        return res.status(500).json({ error: "Failed to process order." });
      } finally {
        client.release();
      }
    }
    res.status(200).json({ received: true });
  }
);

app.use(
  cors({
    credentials: true,
    origin: ["http://localhost:8000", "http://127.0.0.1:8000"],
  })
);
app.use(express.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, "public")));
app.use("/static", express.static(path.join(__dirname, "src")));

// ===== AUTHENTICATION MIDDLEWARE =====
const checkAuth = (req, res, next) => {
  const token = req.cookies.token;
  if (!token) {
    return res
      .status(401)
      .json({ message: "No token provided, authentication required" });
  }
  try {
    const decoded = jwt.verify(token, secret);
    req.userId = decoded.userId;
    req.userRole = decoded.role;
    next();
  } catch (error) {
    return res.status(401).json({ message: "Invalid or expired token" });
  }
};

const checkAdmin = (req, res, next) => {
  if (req.userRole !== "admin") {
    return res
      .status(403)
      .json({ message: "Forbidden: Admin access required" });
  }
  next();
};

// ===== API ROUTES =====

// --- Authentication Routes ---
app.post("/api/register", async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res
        .status(400)
        .json({ message: "Email and password are required" });
    }
    const passwordHash = await bcrypt.hash(password, 10);
    await pool.query("INSERT INTO users (email, password) VALUES ($1, $2)", [
      email,
      passwordHash,
    ]);
    res.status(201).json({ message: "Registration successful" });
  } catch (error) {
    console.error("Registration error:", error);
    if (error.code === "23505") {
      return res.status(409).json({ message: "Email already exists" });
    }
    res.status(500).json({ error: "Internal Server Error" });
  }
});

app.post("/api/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const result = await pool.query("SELECT * FROM users WHERE email = $1", [
      email,
    ]);
    if (result.rows.length === 0) {
      return res.status(404).json({ message: "User not found" });
    }
    const user = result.rows[0];
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ message: "Incorrect password" });
    }
    const token = jwt.sign(
      { userId: user.id, email: user.email, role: user.role },
      secret,
      { expiresIn: "1h" }
    );
    res.cookie("token", token, {
      maxAge: 3600000,
      httpOnly: true,
      sameSite: "strict",
    });
    res.json({ message: "Login successful" });
  } catch (error) {
    console.error("Login error:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

app.post("/api/logout", (req, res) => {
  res.clearCookie("token");
  res.json({ message: "Logout successful" });
});

app.get("/api/users/me", checkAuth, async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT id, email, role FROM users WHERE id = $1",
      [req.userId]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ message: "User not found" });
    }
    res.json(result.rows[0]);
  } catch (error) {
    console.error("Get user error:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

// --- User Profile Routes ---
app.get("/api/profile", checkAuth, async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT email, firstname, lastname, phone, address FROM users WHERE id = $1",
      [req.userId]
    );
    res.json(result.rows[0] || {});
  } catch (err) {
    console.error("Error fetching profile:", err);
    res.status(500).json({ message: "Internal Server Error" });
  }
});

app.put("/api/profile", checkAuth, async (req, res) => {
  try {
    const { firstname, lastname, phone, address } = req.body;
    if (!firstname || !lastname || !phone || !address) {
      return res.status(400).json({ message: "กรุณากรอกข้อมูลให้ครบถ้วน" });
    }
    await pool.query(
      "UPDATE users SET firstname = $1, lastname = $2, phone = $3, address = $4 WHERE id = $5",
      [firstname, lastname, phone, address, req.userId]
    );
    res.json({ message: "Profile updated successfully" });
  } catch (err) {
    console.error("Error updating profile:", err);
    res.status(500).json({ message: "Internal Server Error" });
  }
});

// --- Public Product Routes ---
app.get("/api/products", async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT * FROM products WHERE is_active = TRUE ORDER BY created_at DESC"
    );
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: "Internal Server Error" });
  }
});

app.get("/api/products/:id", async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT * FROM products WHERE id = $1 AND is_active = TRUE",
      [req.params.id]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ message: "Product not found" });
    }
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: "Internal Server Error" });
  }
});

// --- Cart Routes (User) ---
app.get("/api/cart", checkAuth, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT ci.product_id, ci.quantity, p.name, p.price, p.image_url FROM cart_items ci JOIN products p ON ci.product_id = p.id WHERE ci.user_id = $1 AND p.is_active = TRUE`,
      [req.userId]
    );
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: "Internal Server Error" });
  }
});

app.post("/api/cart", checkAuth, async (req, res) => {
  try {
    const { productId, quantity } = req.body;
    const result = await pool.query(
      `INSERT INTO cart_items (user_id, product_id, quantity) VALUES ($1, $2, $3) ON CONFLICT (user_id, product_id) DO UPDATE SET quantity = cart_items.quantity + EXCLUDED.quantity RETURNING *`,
      [req.userId, productId, quantity]
    );
    res
      .status(201)
      .json({ message: "Product added to cart", item: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: "Internal Server Error" });
  }
});

app.put("/api/cart/:productId", checkAuth, async (req, res) => {
  try {
    const { productId } = req.params;
    const { quantity } = req.body;
    if (quantity <= 0) {
      return res
        .status(400)
        .json({ message: "Quantity must be a positive number." });
    }
    const result = await pool.query(
      "UPDATE cart_items SET quantity = $1 WHERE user_id = $2 AND product_id = $3 RETURNING *",
      [quantity, req.userId, productId]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ message: "Cart item not found" });
    }
    res.status(200).json({ message: "Quantity updated", item: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: "Internal Server Error" });
  }
});

app.delete("/api/cart/:productId", checkAuth, async (req, res) => {
  try {
    await pool.query(
      "DELETE FROM cart_items WHERE user_id = $1 AND product_id = $2",
      [req.userId, req.params.productId]
    );
    res.status(200).json({ message: "Product removed from cart" });
  } catch (err) {
    res.status(500).json({ error: "Internal Server Error" });
  }
});

app.get("/api/cart/summary", checkAuth, async (req, res) => {
  try {
    const query = `
      SELECT 
        ci.product_id, 
        ci.quantity, 
        p.name, 
        p.price
      FROM cart_items ci
      JOIN products p ON ci.product_id = p.id
      WHERE ci.user_id = $1 AND p.is_active = TRUE;
    `;
    const result = await pool.query(query, [req.userId]);
    const items = result.rows;

    if (items.length === 0) {
      return res.json({ items: [], total: 0 });
    }

    const total = items.reduce((sum, item) => {
      return sum + item.price * item.quantity;
    }, 0);

    res.json({ items, total });
  } catch (err) {
    console.error("Get cart summary error:", err);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

// --- Order Routes (User) ---
app.get("/api/orders", checkAuth, async (req, res) => {
  try {
    // --- [จุดแก้ไขที่ 3] ---
    // ดึงข้อมูลที่อยู่จากตาราง orders โดยตรง ไม่ต้อง JOIN users เพื่อเอาที่อยู่แล้ว
    const ordersRes = await pool.query(
      `SELECT
        id as order_id,
        total_amount,
        status,
        tracking_number,
        created_at,
        recipient_name,
        recipient_phone,
        shipping_address
      FROM orders
      WHERE user_id = $1
      ORDER BY created_at DESC`,
      [req.userId]
    );
    const orders = ordersRes.rows;

    if (orders.length === 0) {
      return res.json([]);
    }

    const orderDetailsPromises = orders.map(async (order) => {
      const itemsRes = await pool.query(
        `SELECT
          oi.quantity,
          oi.price_at_purchase as price,
          p.name,
          p.image_url
        FROM order_items oi
        JOIN products p ON oi.product_id = p.id
        WHERE oi.order_id = $1`,
        [order.order_id]
      );
      return { ...order, items: itemsRes.rows };
    });

    const fullOrders = await Promise.all(orderDetailsPromises);
    res.json(fullOrders);
  } catch (err) {
    console.error("Error fetching user orders:", err);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

// [เพิ่ม] API สำหรับดึงข้อมูล Order เดียว เพื่อใช้ในหน้า order-details.html
app.get("/api/orders/:id", checkAuth, async (req, res) => {
  try {
    const { id } = req.params;

    // ดึงข้อมูลหลักของ Order
    const orderRes = await pool.query(
      `SELECT
        o.id as order_id,
        o.total_amount,
        o.status,
        o.tracking_number,
        o.created_at,
        o.recipient_name,
        o.recipient_phone,
        o.shipping_address,
        u.email 
      FROM orders o
      JOIN users u ON o.user_id = u.id
      WHERE o.id = $1 AND o.user_id = $2`, // ตรวจสอบว่าเป็นเจ้าของ order จริง
      [id, req.userId]
    );

    if (orderRes.rows.length === 0) {
      return res
        .status(404)
        .json({ message: "Order not found or access denied." });
    }

    const order = orderRes.rows[0];

    // ดึงรายการสินค้าของ Order นั้น
    const itemsRes = await pool.query(
      `SELECT
        oi.quantity,
        oi.price_at_purchase as price,
        p.name,
        p.image_url
      FROM order_items oi
      JOIN products p ON oi.product_id = p.id
      WHERE oi.order_id = $1`,
      [id]
    );

    const fullOrderDetails = { ...order, items: itemsRes.rows };
    res.json(fullOrderDetails);
  } catch (err) {
    console.error(`Error fetching order details for ID ${req.params.id}:`, err);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

// --- Payment Routes (User) ---
app.post("/api/create-payment-intent", checkAuth, async (req, res) => {
  try {
    const cartRes = await pool.query(
      `SELECT SUM(p.price * ci.quantity) as total FROM cart_items ci JOIN products p ON ci.product_id = p.id WHERE ci.user_id = $1`,
      [req.userId]
    );
    const totalAmount = cartRes.rows[0].total;
    if (!totalAmount || totalAmount <= 0) {
      return res.status(400).json({ error: "Cart is empty" });
    }
    const amountInSatang = Math.round(totalAmount * 100);
    const paymentIntent = await stripe.paymentIntents.create({
      amount: amountInSatang,
      currency: "thb",
      automatic_payment_methods: { enabled: true },
      metadata: { userId: req.userId },
    });
    res.send({ clientSecret: paymentIntent.client_secret });
  } catch (err) {
    res.status(500).json({ error: "Internal Server Error" });
  }
});

// ===== ADMIN API ROUTES =====
const adminRouter = express.Router();
adminRouter.use(checkAuth, checkAdmin);

// --- Product Management Routes (Admin) ---
adminRouter.post("/products", async (req, res) => {
  try {
    const {
      name,
      type,
      price,
      old_price,
      image_url,
      description,
      author,
      stock,
    } = req.body;
    if (!name || !price || !image_url) {
      return res
        .status(400)
        .json({ message: "Name, price, and image_url are required." });
    }
    const result = await pool.query(
      `INSERT INTO products (name, type, price, old_price, image_url, description, author, stock) VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING *`,
      [name, type, price, old_price, image_url, description, author, stock]
    );
    res.status(201).json({
      message: "Product created successfully",
      product: result.rows[0],
    });
  } catch (err) {
    res.status(500).json({ error: "Internal Server Error" });
  }
});

adminRouter.put("/products/:id", async (req, res) => {
  try {
    const { id } = req.params;
    const {
      name,
      type,
      price,
      old_price,
      image_url,
      description,
      author,
      stock,
    } = req.body;
    const result = await pool.query(
      `UPDATE products SET name = $1, type = $2, price = $3, old_price = $4, image_url = $5, description = $6, author = $7, stock = $8 WHERE id = $9 RETURNING *`,
      [name, type, price, old_price, image_url, description, author, stock, id]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ message: "Product not found" });
    }
    res.json({
      message: "Product updated successfully",
      product: result.rows[0],
    });
  } catch (err) {
    res.status(500).json({ error: "Internal Server Error" });
  }
});

adminRouter.delete("/products/:id", async (req, res) => {
  try {
    const result = await pool.query(
      "UPDATE products SET is_active = false WHERE id = $1 RETURNING *",
      [req.params.id]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ message: "Product not found" });
    }
    res.json({ message: "Product deactivated successfully" });
  } catch (err) {
    res.status(500).json({ error: "Internal Server Error" });
  }
});

// --- Order Management Routes (Admin) ---
adminRouter.get("/paid-orders", async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT o.id AS order_id, u.email AS user_email, o.total_amount, o.tracking_number, o.created_at, o.status FROM orders o JOIN users u ON o.user_id = u.id WHERE o.status = 'paid' ORDER BY o.created_at ASC`
    );
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: "Internal Server Error" });
  }
});

adminRouter.get("/shipped-orders", async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT o.id AS order_id, u.email AS user_email, o.total_amount, o.tracking_number, o.created_at, o.status FROM orders o JOIN users u ON o.user_id = u.id WHERE o.status = 'shipped' ORDER BY o.created_at DESC`
    );
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: "Internal Server Error" });
  }
});

adminRouter.put("/orders/:orderId/tracking", async (req, res) => {
  try {
    const { orderId } = req.params;
    const { trackingNumber } = req.body;
    if (!trackingNumber) {
      return res.status(400).json({ message: "Tracking number is required." });
    }
    const result = await pool.query(
      `UPDATE orders SET tracking_number = $1, status = 'shipped' WHERE id = $2 RETURNING *`,
      [trackingNumber, orderId]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ message: "Order not found." });
    }
    res.json({ message: "Order updated successfully", order: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: "Internal Server Error" });
  }
});

// Use the admin router for all routes starting with /api/admin
app.use("/api/admin", adminRouter);

// ===== HTML PAGE SERVING =====
// Serve public pages
app.get("/home", (req, res) =>
  res.sendFile(path.join(__dirname, "src", "home.html"))
);
app.get("/product.html", (req, res) =>
  res.sendFile(path.join(__dirname, "src", "product.html"))
);

// Serve pages that require login
app.get("/orders", (req, res) =>
  res.sendFile(path.join(__dirname, "src", "Order.html"))
);
app.get("/order-details.html", (req, res) =>
  res.sendFile(path.join(__dirname, "src", "order-details.html"))
);
app.get("/checkout", (req, res) =>
  res.sendFile(path.join(__dirname, "src", "checkout.html"))
);
app.get("/payment-success.html", (req, res) =>
  res.sendFile(path.join(__dirname, "src", "payment-success.html"))
);
app.get("/profile.html", (req, res) =>
  res.sendFile(path.join(__dirname, "src", "profile.html"))
);

// Serve admin pages
app.get("/admin/create-book", (req, res) =>
  res.sendFile(path.join(__dirname, "src", "CreateBook.html"))
);
app.get("/admin/books", (req, res) =>
  res.sendFile(path.join(__dirname, "src", "AdminManageBooks.html"))
);
app.get("/admin/edit-book", (req, res) =>
  res.sendFile(path.join(__dirname, "src", "EditBook.html"))
);
app.get("/admin/check-paid", (req, res) =>
  res.sendFile(path.join(__dirname, "src", "AdminCheckPaid.html"))
);
app.get("/admin/shipped", (req, res) =>
  res.sendFile(path.join(__dirname, "src", "AdminShippedOrders.html"))
);

// ===== SERVER START =====
app.listen(PORT, () => console.log(`Server is running on port ${PORT}`));
