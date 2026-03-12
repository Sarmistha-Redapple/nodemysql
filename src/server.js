const bcrypt = require("bcryptjs");
const cors = require("cors");
const dotenv = require("dotenv");
const express = require("express");
const net = require("net");

dotenv.config();

const { pool, query } = require("./db");

const app = express();

function parseCorsOrigins(value) {
  const raw = String(value ?? "").trim();
  if (!raw) return [];
  if (raw === "*") return ["*"];
  return raw
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
}

const corsOrigins = parseCorsOrigins(process.env.CORS_ORIGINS);
const corsOptions =
  corsOrigins.length === 0
    ? undefined
    : {
        origin(origin, cb) {
          // Allow non-browser tools (curl/postman) with no Origin header.
          if (!origin) return cb(null, true);
          if (corsOrigins.includes("*")) return cb(null, true);
          if (corsOrigins.includes(origin)) return cb(null, true);
          return cb(new Error(`CORS blocked for origin: ${origin}`));
        }
      };

app.use(cors(corsOptions));

app.use(express.urlencoded({ extended: false }));
app.use(express.json());

function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

app.get("/", (req, res) => {
  res.json({
    ok: true,
    message: "Node + MySQL API is running.",
    routes: {
      register: "POST /register",
      apiRegister: "POST /api/register",
      userById: "GET /users/:id",
      users: "GET /api/users"
    }
  });
});

async function handleRegister(req, res) {
  const name = String((req.body.name ?? req.body.username) ?? "").trim();
  const email = String(req.body.email ?? "").trim().toLowerCase();
  const phone = String(req.body.phone ?? "").trim() || null;
  const address = String(req.body.address ?? "").trim() || null;
  const password = String(req.body.password ?? "");

  if (!name) return res.status(400).send("Name is required.");
  if (!email || !isValidEmail(email)) return res.status(400).send("Valid email is required.");
  if (!password || password.length < 6) return res.status(400).send("Password must be at least 6 characters.");

  try {
    const passwordHash = await bcrypt.hash(password, 10);
    const [result] = await pool.execute(
      "INSERT INTO users (name, email, phone, address, password_hash) VALUES (?, ?, ?, ?, ?)",
      [name, email, phone, address, passwordHash]
    );

    res.status(201).json({
      ok: true,
      id: result.insertId,
      userUrl: `/users/${result.insertId}`
    });
  } catch (err) {
    // MySQL duplicate email
    if (err && err.code === "ER_DUP_ENTRY") {
      return res.status(409).send("This email is already registered.");
    }
    // eslint-disable-next-line no-console
    console.error(err);
    res.status(500).send("Server error.");
  }
}

app.post("/register", handleRegister);
app.post("/api/register", handleRegister);

app.get("/users/:id", async (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isInteger(id) || id <= 0) return res.status(400).send("Invalid id.");

  try {
    const rows = await query(
      "SELECT id, name, email, phone, address, created_at FROM users WHERE id = ?",
      [id]
    );
    const user = rows[0];
    if (!user) return res.status(404).send("User not found.");

    res.json({ ok: true, user });
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error(err);
    res.status(500).send("Server error.");
  }
});

// Optional: see saved users (JSON)
app.get("/api/users", async (req, res) => {
  try {
    const rows = await query(
      "SELECT id, name, email, phone, address, created_at FROM users ORDER BY id DESC LIMIT 100",
      []
    );
    res.json({ users: rows });
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error(err);
    res.status(500).json({ error: "Server error." });
  }
});

function isPortFree(port, host = "127.0.0.1") {
  return new Promise((resolve) => {
    const server = net.createServer();
    server.unref();
    server.on("error", () => resolve(false));
    server.listen({ port, host }, () => {
      server.close(() => resolve(true));
    });
  });
}

async function pickUniquePort() {
  const raw = process.env.PORT;
  if (raw != null && raw !== "") {
    const port = Number(raw);
    if (!Number.isInteger(port) || port <= 0 || port > 65535) {
      throw new Error("PORT must be an integer between 1 and 65535.");
    }
    const free = await isPortFree(port);
    if (!free) {
      throw new Error(`PORT ${port} is already in use. Change PORT in .env.`);
    }
    return port;
  }

  for (let port = 3000; port <= 3100; port += 1) {
    // eslint-disable-next-line no-await-in-loop
    const free = await isPortFree(port);
    if (free) return port;
  }

  throw new Error("No free port found between 3000 and 3100.");
}

async function ensureSchema() {
  try {
    await pool.execute(`
      CREATE TABLE IF NOT EXISTS users (
        id INT UNSIGNED NOT NULL AUTO_INCREMENT,
        name VARCHAR(100) NOT NULL,
        email VARCHAR(191) NOT NULL,
        phone VARCHAR(30) NULL,
        address VARCHAR(255) NULL,
        password_hash VARCHAR(255) NOT NULL,
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (id),
        UNIQUE KEY uniq_users_email (email)
      )
    `);
  } catch (err) {
    if (err && err.code === "ER_BAD_DB_ERROR") {
      throw new Error(
        `Database "${process.env.DB_NAME}" not found. Create it (run sql/init.sql) or start docker-compose.`
      );
    }
    throw err;
  }
}

async function main() {
  const port = await pickUniquePort();
  await ensureSchema();
  app.listen(port, () => {
    // eslint-disable-next-line no-console
    console.log(`Server running: http://localhost:${port}`);
  });
}

main().catch((err) => {
  // eslint-disable-next-line no-console
  console.error(err.message || err);
  process.exit(1);
});
