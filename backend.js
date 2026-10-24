const path = require("node:path");
const { promisify } = require("node:util");
const { createHash, randomBytes, scrypt, timingSafeEqual } = require("node:crypto");
const express = require("express");
const mysql = require("mysql2/promise");
require("dotenv").config();

const app = express();
const port = Number(process.env.PORT || 5000);
const sessionCookieName = "swiftcart_session";
const sessionDurationSeconds = 60 * 60 * 24 * 30;
const scryptAsync = promisify(scrypt);
const pool = mysql.createPool({
    host: process.env.DB_HOST || "localhost",
    port: Number(process.env.DB_PORT || 3306),
    user: process.env.DB_USER || "root",
    password: process.env.DB_PASSWORD || "root",
    database: process.env.DB_NAME || "swiftcart_db",
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});

const hubMapPositions = {
    "ind-04": { x: 0.35, y: 0.32, radiusKm: 2.2 },
    "ind-02": { x: 0.65, y: 0.52, radiusKm: 2.0 },
    "ind-07": { x: 0.42, y: 0.76, radiusKm: 2.4 },
    "ind-09": { x: 0.22, y: 0.18, radiusKm: 2.8 }
};
const publicPages = new Map([
    ["index.html", "index.html"],
    ["swiftcart_app.html", "index.html"],
    ["admin_analytics.html", "admin_analytics.html"],
    ["profile.html", "profile.html"],
    ["rider_tracking.html", "rider_tracking.html"]
]);

app.use(express.json({ limit: "10kb" }));

app.get("/api/health", async (req, res, next) => {
    try {
        const [tables] = await pool.query(`
            SELECT TABLE_NAME AS tableName
            FROM information_schema.TABLES
            WHERE TABLE_SCHEMA = DATABASE()
              AND TABLE_NAME IN (
                  'customers', 'customer_sessions', 'orders',
                  'order_items', 'products', 'purchase_orders', 'dark_stores'
              )
        `);
        const [columns] = await pool.query(`
            SELECT TABLE_NAME AS tableName, COLUMN_NAME AS columnName
            FROM information_schema.COLUMNS
            WHERE TABLE_SCHEMA = DATABASE()
              AND (
                  (TABLE_NAME = 'customers' AND COLUMN_NAME IN ('phone', 'full_name', 'address', 'password_hash'))
                  OR (TABLE_NAME = 'customer_sessions' AND COLUMN_NAME IN ('token_hash', 'customer_phone', 'expires_at'))
                  OR (TABLE_NAME = 'orders' AND COLUMN_NAME IN ('order_id', 'customer_phone', 'order_status'))
                  OR (TABLE_NAME = 'order_items' AND COLUMN_NAME IN ('order_id', 'product_id', 'qty'))
                  OR (TABLE_NAME = 'products' AND COLUMN_NAME IN ('id', 'price', 'stock'))
              )
        `);
        const existingTables = new Set(tables.map((row) => row.tableName));
        const existingColumns = new Set(columns.map((row) => `${row.tableName}.${row.columnName}`));
        const requiredTables = [
            "customers", "customer_sessions", "orders",
            "order_items", "products", "purchase_orders", "dark_stores"
        ];
        const requiredColumns = [
            "customers.phone", "customers.full_name", "customers.address", "customers.password_hash",
            "customer_sessions.token_hash", "customer_sessions.customer_phone", "customer_sessions.expires_at",
            "orders.order_id", "orders.customer_phone", "orders.order_status",
            "order_items.order_id", "order_items.product_id", "order_items.qty",
            "products.id", "products.price", "products.stock"
        ];
        const missingSchema = [
            ...requiredTables.filter((table) => !existingTables.has(table)),
            ...requiredColumns.filter((column) => !existingColumns.has(column))
        ];
        if (missingSchema.length) {
            return res.status(503).json({
                status: "error",
                database: "connected",
                error: "The database schema is incomplete. Run database.sql and restart the server.",
                missingSchema
            });
        }
        res.json({ status: "ok", database: "connected" });
    } catch (error) {
        next(error);
    }
});

function normalizePhone(value) {
    const phone = String(value || "").trim();
    if (!/^\+?[\d\s()-]{8,20}$/.test(phone)) {
        return null;
    }

    const digits = phone.replace(/\D/g, "");
    return digits.length >= 10 && digits.length <= 15 ? digits : null;
}

function validateCustomer(value, phoneValue = value?.phone) {
    const name = String(value?.name || "").trim();
    const phone = normalizePhone(phoneValue);
    const email = String(value?.email || "").trim();
    const address = String(value?.address || "").trim();

    if (name.length < 2 || name.length > 255 || !phone ||
        (email && (email.length > 255 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))) ||
        address.length < 5 || address.length > 2000) {
        return null;
    }

    return { name, phone, email: email || null, address };
}

function validatePassword(value) {
    return typeof value === "string" && value.length >= 8 && value.length <= 128;
}

async function hashPassword(password) {
    const salt = randomBytes(16).toString("hex");
    const derivedKey = await scryptAsync(password, salt, 64);
    return `scrypt$${salt}$${derivedKey.toString("hex")}`;
}

async function verifyPassword(password, storedHash) {
    const [algorithm, salt, key] = String(storedHash || "").split("$");
    if (algorithm !== "scrypt" || !salt || !/^[a-f0-9]{128}$/i.test(key || "")) {
        return false;
    }
    const derivedKey = await scryptAsync(password, salt, 64);
    return timingSafeEqual(derivedKey, Buffer.from(key, "hex"));
}

function phoneAliases(phone) {
    const aliases = new Set([phone]);
    if (phone.length === 10) {
        aliases.add(`91${phone}`);
    } else if (phone.length === 11 && phone.startsWith("0")) {
        aliases.add(phone.slice(1));
        aliases.add(`91${phone.slice(1)}`);
    } else if (phone.length === 12 && phone.startsWith("91")) {
        aliases.add(phone.slice(2));
    }
    return [...aliases];
}

async function findCustomerByPhone(phone) {
    const aliases = phoneAliases(phone);
    const placeholders = aliases.map(() => "?").join(", ");
    const [[customer]] = await pool.execute(
        `SELECT phone, full_name, email, address, password_hash
         FROM customers WHERE phone IN (${placeholders}) LIMIT 1`,
        aliases
    );
    return customer || null;
}

function readSessionToken(req) {
    const cookies = String(req.headers.cookie || "").split(";");
    const sessionCookie = cookies.find((cookie) => cookie.trim().startsWith(`${sessionCookieName}=`));
    return sessionCookie ? decodeURIComponent(sessionCookie.trim().slice(sessionCookieName.length + 1)) : null;
}

function sessionCookie(token, maxAge = sessionDurationSeconds) {
    const secure = process.env.NODE_ENV === "production" ? "; Secure" : "";
    return `${sessionCookieName}=${encodeURIComponent(token)}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${maxAge}${secure}`;
}

function hashSessionToken(token) {
    return createHash("sha256").update(token).digest("hex");
}

async function getAuthenticatedCustomer(req) {
    const token = readSessionToken(req);
    if (!token) {
        return null;
    }

    const [[customer]] = await pool.execute(
        `SELECT c.phone, c.full_name AS name, c.email, c.address
         FROM customer_sessions s
         JOIN customers c ON c.phone = s.customer_phone
         WHERE s.token_hash = ? AND s.expires_at > CURRENT_TIMESTAMP`,
        [hashSessionToken(token)]
    );
    return customer || null;
}

async function createCustomerSession(phone, res) {
    const token = randomBytes(32).toString("hex");
    const expiresAt = new Date(Date.now() + sessionDurationSeconds * 1000);
    await pool.execute(
        `INSERT INTO customer_sessions (token_hash, customer_phone, expires_at)
         VALUES (?, ?, ?)`,
        [hashSessionToken(token), phone, expiresAt]
    );
    res.setHeader("Set-Cookie", sessionCookie(token));
}

async function getCustomerOrders(phone) {
    const [orders] = await pool.execute(
        `SELECT order_id AS orderId, order_status AS orderStatus,
                payment_status AS paymentStatus, total_amount AS totalAmount,
                created_at AS createdAt
         FROM orders WHERE customer_phone = ? ORDER BY created_at DESC LIMIT 50`,
        [phone]
    );

    if (orders.length) {
        const orderIds = orders.map((order) => order.orderId);
        const placeholders = orderIds.map(() => "?").join(", ");
        const [orderItems] = await pool.execute(
            `SELECT order_id AS orderId, product_name AS productName, qty, price
             FROM order_items WHERE order_id IN (${placeholders}) ORDER BY id`,
            orderIds
        );
        const itemsByOrder = new Map();
        for (const item of orderItems) {
            const list = itemsByOrder.get(item.orderId) || [];
            list.push(item);
            itemsByOrder.set(item.orderId, list);
        }
        for (const order of orders) {
            order.items = itemsByOrder.get(order.orderId) || [];
        }
    }

    return orders;
}

app.post("/api/auth/register", async (req, res, next) => {
    const customer = validateCustomer(req.body?.profile);
    const password = req.body?.password;
    if (!customer || !validatePassword(password)) {
        return res.status(400).json({
            error: "Enter a valid name, phone, delivery address, and a password of at least 8 characters."
        });
    }
    try {
        if (await findCustomerByPhone(customer.phone)) {
            return res.status(409).json({ error: "An account with this phone number already exists. Sign in instead." });
        }

        const passwordHash = await hashPassword(password);
        await pool.execute(
            `INSERT INTO customers (phone, full_name, email, address, password_hash)
             VALUES (?, ?, ?, ?, ?)`,
            [customer.phone, customer.name, customer.email, customer.address, passwordHash]
        );
        await createCustomerSession(customer.phone, res);
        res.status(201).json({ customer });
    } catch (error) {
        if (error.code === "ER_DUP_ENTRY") {
            return res.status(409).json({ error: "An account with this phone number already exists. Sign in instead." });
        }
        next(error);
    }
});

app.post("/api/auth/login", async (req, res, next) => {
    const phone = normalizePhone(req.body?.phone);
    const password = req.body?.password;
    if (!phone || typeof password !== "string" || password.length > 128) {
        return res.status(400).json({ error: "Enter a valid phone number and password." });
    }

    try {
        const existingCustomer = await findCustomerByPhone(phone);
        if (!existingCustomer || !await verifyPassword(password, existingCustomer.password_hash)) {
            return res.status(401).json({ error: "Phone number or password is incorrect." });
        }

        await createCustomerSession(existingCustomer.phone, res);
        const [[customer]] = await pool.execute(
            "SELECT phone, full_name AS name, email, address FROM customers WHERE phone = ?",
            [existingCustomer.phone]
        );
        res.json({ customer });
    } catch (error) {
        next(error);
    }
});

app.post("/api/auth/logout", async (req, res, next) => {
    try {
        const token = readSessionToken(req);
        if (token) {
            await pool.execute(
                "DELETE FROM customer_sessions WHERE token_hash = ?",
                [hashSessionToken(token)]
            );
        }
        res.setHeader("Set-Cookie", sessionCookie("", 0));
        res.json({ message: "Signed out." });
    } catch (error) {
        next(error);
    }
});

app.get("/api/me", async (req, res, next) => {
    try {
        const customer = await getAuthenticatedCustomer(req);
        if (!customer) {
            return res.status(401).json({ error: "Sign in to view your account." });
        }
        const orders = await getCustomerOrders(customer.phone);
        res.json({ customer, orders });
    } catch (error) {
        next(error);
    }
});

app.post("/api/orders", async (req, res, next) => {
    const customer = await getAuthenticatedCustomer(req);
    const items = req.body?.items;
    if (!customer) {
        return res.status(401).json({ error: "Sign in before placing an order." });
    }
    if (!Array.isArray(items) || items.length < 1 || items.length > 30 ||
        items.some((item) => !Number.isSafeInteger(Number(item?.productId)) ||
            Number(item.productId) < 1 || !Number.isSafeInteger(Number(item?.quantity)) ||
            Number(item.quantity) < 1 || Number(item.quantity) > 100)) {
        return res.status(400).json({ error: "Add at least one valid item to your cart." });
    }

    const quantities = new Map();
    for (const item of items) {
        const productId = Number(item.productId);
        quantities.set(productId, (quantities.get(productId) || 0) + Number(item.quantity));
    }
    const productIds = [...quantities.keys()];
    const connection = await pool.getConnection();
    let transactionStarted = false;

    try {
        await connection.beginTransaction();
        transactionStarted = true;
        const placeholders = productIds.map(() => "?").join(", ");
        const [products] = await connection.execute(
            `SELECT id, name, price, stock FROM products
             WHERE id IN (${placeholders}) FOR UPDATE`,
            productIds
        );
        if (products.length !== productIds.length) {
            await connection.rollback();
            transactionStarted = false;
            return res.status(400).json({ error: "One or more cart products are not available in the database." });
        }

        const productById = new Map(products.map((product) => [product.id, product]));
        const unavailableProduct = products.find((product) => product.stock < quantities.get(product.id));
        if (unavailableProduct) {
            await connection.rollback();
            transactionStarted = false;
            return res.status(409).json({
                error: `Not enough stock for ${unavailableProduct.name}. Please update your cart and try again.`
            });
        }

        const subtotal = products.reduce((sum, product) => sum + product.price * quantities.get(product.id), 0);
        if (!Number.isSafeInteger(subtotal) || subtotal < 1 || subtotal > 10000000) {
            await connection.rollback();
            transactionStarted = false;
            return res.status(400).json({ error: "The order total is invalid." });
        }

        const orderId = `SC-${Date.now()}-${randomBytes(3).toString("hex").toUpperCase()}`;
        const deliveryOtp = String(randomBytes(4).readUInt32BE(0) % 10000).padStart(4, "0");
        const handlingFee = 5;
        await connection.execute(
            `INSERT INTO orders
                (order_id, customer_phone, customer_name, customer_address,
                 subtotal, handling_fee, total_amount, delivery_otp)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
            [orderId, customer.phone, customer.name, customer.address,
                subtotal, handlingFee, subtotal + handlingFee, deliveryOtp]
        );

        for (const [productId, quantity] of quantities) {
            const product = productById.get(productId);
            await connection.execute(
                `INSERT INTO order_items (order_id, product_id, product_name, qty, price)
                 VALUES (?, ?, ?, ?, ?)`,
                [orderId, productId, product.name, quantity, product.price]
            );
            await connection.execute(
                "UPDATE products SET stock = stock - ? WHERE id = ?",
                [quantity, productId]
            );
        }

        await connection.commit();
        transactionStarted = false;
        res.status(201).json({
            orderId,
            totalAmount: subtotal + handlingFee
        });
    } catch (error) {
        if (transactionStarted) {
            await connection.rollback();
        }
        next(error);
    } finally {
        connection.release();
    }
});

app.post("/api/orders/:orderId/cancel", async (req, res, next) => {
    const customer = await getAuthenticatedCustomer(req);
    if (!customer) {
        return res.status(401).json({ error: "Sign in to cancel an order." });
    }

    const orderId = String(req.params.orderId || "").trim();
    if (!/^SC-[A-Za-z0-9-]{1,45}$/.test(orderId)) {
        return res.status(400).json({ error: "Enter a valid order number." });
    }

    const connection = await pool.getConnection();
    let transactionStarted = false;
    try {
        await connection.beginTransaction();
        transactionStarted = true;
        const [[order]] = await connection.execute(
            `SELECT order_id AS orderId, order_status AS status
             FROM orders
             WHERE order_id = ? AND customer_phone = ?
             FOR UPDATE`,
            [orderId, customer.phone]
        );
        if (!order) {
            await connection.rollback();
            transactionStarted = false;
            return res.status(404).json({ error: "Order not found for your account." });
        }
        if (String(order.status).toUpperCase() !== "PACKED") {
            await connection.rollback();
            transactionStarted = false;
            return res.status(409).json({
                error: "This order can no longer be cancelled. Orders can only be cancelled before dispatch."
            });
        }

        const [items] = await connection.execute(
            "SELECT product_id AS productId, qty FROM order_items WHERE order_id = ?",
            [orderId]
        );
        if (items.length === 0) {
            await connection.rollback();
            transactionStarted = false;
            return res.status(409).json({ error: "This order has no items to return to inventory." });
        }

        for (const item of items) {
            await connection.execute(
                "UPDATE products SET stock = stock + ? WHERE id = ?",
                [item.qty, item.productId]
            );
        }
        await connection.execute(
            "UPDATE orders SET order_status = 'CANCELLED' WHERE order_id = ?",
            [orderId]
        );
        await connection.commit();
        transactionStarted = false;
        res.json({ orderId, orderStatus: "CANCELLED" });
    } catch (error) {
        if (transactionStarted) {
            await connection.rollback();
        }
        next(error);
    } finally {
        connection.release();
    }
});

app.put("/api/me", async (req, res, next) => {
    try {
        const authenticatedCustomer = await getAuthenticatedCustomer(req);
        if (!authenticatedCustomer) {
            return res.status(401).json({ error: "Sign in to update your profile." });
        }
        const customer = validateCustomer(req.body, authenticatedCustomer.phone);
        if (!customer) {
            return res.status(400).json({ error: "Enter a valid name, email, and delivery address." });
        }

        const [result] = await pool.execute(
            `UPDATE customers SET full_name = ?, email = ?, address = ? WHERE phone = ?`,
            [customer.name, customer.email, customer.address, customer.phone]
        );
        if (result.affectedRows === 0) {
            return res.status(404).json({ error: "Customer account not found." });
        }
        res.json({ customer });
    } catch (error) {
        next(error);
    }
});

app.put("/api/me/password", async (req, res, next) => {
    try {
        const customer = await getAuthenticatedCustomer(req);
        const currentPassword = req.body?.currentPassword;
        const newPassword = req.body?.newPassword;
        if (!customer) {
            return res.status(401).json({ error: "Sign in to change your password." });
        }
        if (!validatePassword(newPassword)) {
            return res.status(400).json({ error: "Your new password must be between 8 and 128 characters." });
        }

        const [[account]] = await pool.execute(
            "SELECT password_hash FROM customers WHERE phone = ?",
            [customer.phone]
        );
        if (account.password_hash &&
            (typeof currentPassword !== "string" || !await verifyPassword(currentPassword, account.password_hash))) {
            return res.status(401).json({ error: "Your current password is incorrect." });
        }

        await pool.execute(
            "UPDATE customers SET password_hash = ? WHERE phone = ?",
            [await hashPassword(newPassword), customer.phone]
        );
        res.json({ message: "Password updated." });
    } catch (error) {
        next(error);
    }
});

app.get("/api/admin/dashboard", async (req, res, next) => {
    try {
        const [[metrics]] = await pool.query(`
            SELECT
                (SELECT COUNT(*) FROM orders
                 WHERE UPPER(order_status) IN ('PACKED', 'IN_TRANSIT', 'OUT_FOR_DELIVERY', 'READY_FOR_PICKUP')) AS activeOrders,
                (SELECT COALESCE(SUM(total_amount), 0) FROM orders
                 WHERE DATE(created_at) = CURDATE()) AS todayGmv,
                (SELECT COUNT(*) FROM orders
                 WHERE DATE(created_at) = CURDATE()) AS todayOrders,
                (SELECT COUNT(*) FROM products WHERE stock <= 15) AS criticalSkus,
                (SELECT COALESCE(ROUND(AVG(total_amount)), 0) FROM orders
                 WHERE DATE(created_at) = CURDATE()) AS averageOrderValue
        `);

        res.json(metrics);
    } catch (error) {
        next(error);
    }
});

app.get("/api/admin/hubs", async (req, res, next) => {
    try {
        const [rows] = await pool.query(`
            SELECT id, name, location, active_orders AS orders,
                   active_riders AS riders, load_factor AS \`load\`, status
            FROM dark_stores
            ORDER BY id
        `);

        res.json(rows.map((hub) => ({
            ...hub,
            ...(hubMapPositions[hub.id] || { x: 0.5, y: 0.5, radiusKm: 2 })
        })));
    } catch (error) {
        next(error);
    }
});

app.get("/api/admin/stockouts", async (req, res, next) => {
    try {
        const [rows] = await pool.query(`
            SELECT id, name, stock, aisle
            FROM products
            WHERE stock <= 15
            ORDER BY stock ASC, name ASC
        `);

        res.json(rows.map((product) => ({
            ...product,
            suggestedQuantity: Math.max(25, 100 - product.stock),
            estimatedMinutesLeft: Math.max(5, product.stock * 2)
        })));
    } catch (error) {
        next(error);
    }
});

app.get("/api/admin/orders", async (req, res, next) => {
    try {
        const [rows] = await pool.query(`
            SELECT o.order_id AS orderId, o.order_status AS status,
                   o.rider_name AS riderName, COUNT(oi.id) AS itemLines,
                   COALESCE(SUM(oi.qty), 0) AS itemCount
            FROM orders o
            LEFT JOIN order_items oi ON oi.order_id = o.order_id
            WHERE UPPER(o.order_status) IN ('PACKED', 'IN_TRANSIT', 'OUT_FOR_DELIVERY', 'READY_FOR_PICKUP')
            GROUP BY o.order_id, o.order_status, o.rider_name, o.created_at
            ORDER BY o.created_at DESC
            LIMIT 10
        `);

        res.json(rows);
    } catch (error) {
        next(error);
    }
});

app.post("/api/admin/purchase-orders", async (req, res, next) => {
    const productId = Number(req.body?.productId);
    const quantity = Number(req.body?.quantity);

    if (!Number.isSafeInteger(productId) || productId < 1 ||
        !Number.isSafeInteger(quantity) || quantity < 1 || quantity > 10000) {
        return res.status(400).json({
            error: "productId must be a positive integer and quantity must be between 1 and 10000."
        });
    }

    const connection = await pool.getConnection();
    try {
        const [products] = await connection.execute(
            "SELECT id FROM products WHERE id = ?",
            [productId]
        );
        if (products.length === 0) {
            return res.status(404).json({ error: "Product not found." });
        }

        const purchaseOrderNumber = `PO-${Date.now()}-${randomBytes(3).toString("hex").toUpperCase()}`;
        await connection.execute(
            `INSERT INTO purchase_orders (po_number, product_id, quantity, status)
             VALUES (?, ?, ?, 'PENDING')`,
            [purchaseOrderNumber, productId, quantity]
        );

        res.status(201).json({
            purchaseOrderNumber,
            productId,
            quantity,
            status: "PENDING"
        });
    } catch (error) {
        next(error);
    } finally {
        connection.release();
    }
});

app.get("/", (req, res) => {
    res.sendFile(path.join(__dirname, "index.html"));
});

app.get("/:page", (req, res, next) => {
    const page = publicPages.get(req.params.page);
    if (!page) {
        return next();
    }
    res.sendFile(path.join(__dirname, page));
});

app.use((error, req, res, next) => {
    console.error("API request failed:", error);
    if (res.headersSent) {
        return next(error);
    }
    res.status(500).json({ error: "The request could not be completed." });
});

async function startServer() {
    try {
        await pool.query("SELECT 1");
        app.listen(port, () => {
            console.log(`SwiftCart server running at http://localhost:${port}`);
        });
    } catch (error) {
        console.error("Could not connect to MySQL. Check the database and DB_* settings.", error);
        process.exitCode = 1;
        await pool.end();
    }
}

if (require.main === module) {
    startServer();
}

module.exports = { app, pool, startServer };
