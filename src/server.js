const bcrypt = require("bcryptjs");
const cors = require("cors");
const dotenv = require("dotenv");
const express = require("express");
const rateLimit = require("express-rate-limit");
const net = require("net");
const crypto = require("crypto");

dotenv.config();

const { pool, query } = require("./db");

const app = express();

if (process.env.TRUST_PROXY === "1") {
  app.set("trust proxy", 1);
}

function parseCsv(value) {
  const raw = String(value ?? "").trim();
  if (!raw) return [];
  return raw
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
}

function parseCorsOrigins(value) {
  const list = parseCsv(value);
  if (list.length === 1 && list[0] === "*") return ["*"];
  return list;
}

const corsOrigins = parseCorsOrigins(process.env.CORS_ORIGINS);
const corsMethods = parseCsv(process.env.CORS_METHODS || "GET,POST,OPTIONS");
const corsAllowedHeaders = parseCsv(process.env.CORS_ALLOWED_HEADERS || "Content-Type");
const corsCredentials = String(process.env.CORS_CREDENTIALS ?? "0").trim() === "1";
const corsOptions =
  corsOrigins.length === 0
    ? undefined
    : {
        methods: corsMethods,
        allowedHeaders: corsAllowedHeaders,
        credentials: corsCredentials,
        optionsSuccessStatus: 204,
        origin(origin, cb) {
          // Allow non-browser tools (curl/postman) with no Origin header.
          if (!origin) return cb(null, true);
          if (corsOrigins.includes("*")) return cb(null, true);
          if (corsOrigins.includes(origin)) return cb(null, true);
          return cb(new Error(`CORS blocked for origin: ${origin}`));
        }
      };

// app.use(cors(corsOptions));
app.options("*", cors(corsOptions));
app.use(cors({ origin: true }));


app.use(express.urlencoded({ extended: false }));
app.use(express.json());

function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function getRequiredSecret(name, devFallback) {
  const raw = String(process.env[name] ?? "").trim();
  if (raw) return raw;
  if (process.env.NODE_ENV === "production") {
    throw new Error(`Missing ${name}. Set it in .env (required in production).`);
  }
  // eslint-disable-next-line no-console
  console.warn(`Warning: ${name} is not set. Using an insecure dev secret.`);
  return devFallback;
}

function base64UrlEncode(input) {
  return Buffer.from(input)
    .toString("base64")
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replaceAll("=", "");
}

function signJwtLike(payload, secret) {
  const header = { alg: "HS256", typ: "JWT" };
  const headerPart = base64UrlEncode(JSON.stringify(header));
  const payloadPart = base64UrlEncode(JSON.stringify(payload));
  const data = `${headerPart}.${payloadPart}`;
  const signature = crypto.createHmac("sha256", secret).update(data).digest("base64");
  const signaturePart = signature.replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
  return `${data}.${signaturePart}`;
}

function createAccessToken(user) {
  const nowSeconds = Math.floor(Date.now() / 1000);
  const ttlSeconds = Number(process.env.ACCESS_TOKEN_TTL_SECONDS || 60 * 15); // default 15m
  const payload = {
    typ: "access",
    sub: String(user.id),
    email: String(user.email),
    iat: nowSeconds,
    exp: nowSeconds + ttlSeconds
  };
  const secret = getRequiredSecret("ACCESS_TOKEN_SECRET", "dev-access-secret-change-me");
  return signJwtLike(payload, secret);
}

function getRefreshCookieName() {
  return String(process.env.REFRESH_COOKIE_NAME || "refresh_token");
}

function parseSameSite(value) {
  const raw = String(value ?? "").trim().toLowerCase();
  if (raw === "strict") return "strict";
  if (raw === "none") return "none";
  return "lax";
}

function refreshCookieOptions() {
  const ttlSeconds = Number(process.env.REFRESH_TOKEN_TTL_SECONDS || 60 * 60 * 24 * 30); // default 30d
  const secure =
    String(process.env.COOKIE_SECURE ?? "").trim() === "1" || String(process.env.NODE_ENV || "").trim() === "production";
  return {
    httpOnly: true,
    secure,
    sameSite: parseSameSite(process.env.COOKIE_SAMESITE),
    path: "/api",
    maxAge: ttlSeconds * 1000
  };
}

function clearRefreshCookie(res, name, options) {
  // Cookie deletion requires matching attributes (especially path/secure/sameSite).
  res.clearCookie(name, { ...options, maxAge: 0, expires: new Date(0) });
  // Also clear any old cookie that may have been set on the root path.
  res.clearCookie(name, { ...options, path: "/", maxAge: 0, expires: new Date(0) });
}

function generateRefreshToken() {
  return base64UrlEncode(crypto.randomBytes(32));
}

function getCookie(req, name) {
  const header = String(req.headers.cookie || "");
  if (!header) return null;
  const parts = header.split(";").map((p) => p.trim());
  for (const part of parts) {
    if (!part) continue;
    const idx = part.indexOf("=");
    if (idx === -1) continue;
    const key = part.slice(0, idx).trim();
    if (key !== name) continue;
    return decodeURIComponent(part.slice(idx + 1));
  }
  return null;
}

app.get("/", (req, res) => {
  res.json({
    status: true,
    message: "Node + MySQL API is running.",
    routes: {
      register: "POST /register",
      apiRegister: "POST /api/register",
      login: "POST /login",
      apiLogin: "POST /api/login",
      refresh: "POST /api/refresh",
      logout: "POST /api/logout",
      authLogin: "POST /api/auth/login",
      authRefresh: "POST /api/auth/refresh",
      authLogout: "POST /api/auth/logout",
      userById: "GET /users/:id",
      users: "GET /api/users"
    }
  });
});

async function handleLogin(req, res) {
  const email = String(req.body.email ?? "").trim().toLowerCase();
  const password = String(req.body.password ?? "");

  if (!email || !isValidEmail(email)) {
    return res.status(400).json({ status: false, error: "validation_error", message: "Valid email is required." });
  }
  if (!password) {
    return res.status(400).json({ status: false, error: "validation_error", message: "Password is required." });
  }

  try {
    const rows = await query(
      "SELECT id, name, email, phone, address, password_hash, created_at FROM users WHERE email = ? LIMIT 1",
      [email]
    );
    const user = rows[0];
    if (!user) {
      return res.status(401).json({ status: false, error: "invalid_credentials", message: "Invalid email or password." });
    }

    const ok = await bcrypt.compare(password, String(user.password_hash || ""));
    if (!ok) {
      return res.status(401).json({ status: false, error: "invalid_credentials", message: "Invalid email or password." });
    }

    // Never return password hash
    const { password_hash, ...safeUser } = user;

    const refreshToken = generateRefreshToken();
    const refreshTtlSeconds = Number(process.env.REFRESH_TOKEN_TTL_SECONDS || 60 * 60 * 24 * 30);
    const expiresAt = new Date(Date.now() + refreshTtlSeconds * 1000);

    await pool.execute(
      "INSERT INTO refresh_tokens (user_id, token_hash, expires_at) VALUES (?, ?, ?)",
      [safeUser.id, refreshToken, expiresAt]
    );

    res.cookie(getRefreshCookieName(), refreshToken, refreshCookieOptions());
    const accessToken = createAccessToken(safeUser);
    return res.json({ status: true, accessToken: accessToken, refreshToken, user: safeUser });
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error(err);
    return res.status(500).json({ status: false, error: "server_error", message: "Server error." });
  }
}

async function handleRefresh(req, res) {
  const cookieName = getRefreshCookieName();
  const raw = getCookie(req, cookieName);
  if (!raw) {
    return res.status(401).json({ status: false, error: "not_authenticated", message: "Missing refresh token." });
  }

  try {
    const rows = await query(
      `
        SELECT rt.id AS refresh_id, rt.user_id, u.id, u.name, u.email, u.phone, u.address, u.created_at
        FROM refresh_tokens rt
        JOIN users u ON u.id = rt.user_id
        WHERE rt.token_hash = ?
          AND rt.expires_at > NOW()
        LIMIT 1
      `,
      [raw]
    );
    const row = rows[0];
    if (!row) {
      return res.status(401).json({ status: false, error: "not_authenticated", message: "Invalid refresh token." });
    }

    // Rotate refresh token
    await pool.execute("DELETE FROM refresh_tokens WHERE id = ?", [row.refresh_id]);

    const newRefresh = generateRefreshToken();
    const refreshTtlSeconds = Number(process.env.REFRESH_TOKEN_TTL_SECONDS || 60 * 60 * 24 * 30);
    const expiresAt = new Date(Date.now() + refreshTtlSeconds * 1000);
    await pool.execute(
      "INSERT INTO refresh_tokens (user_id, token_hash, expires_at) VALUES (?, ?, ?)",
      [row.user_id, newRefresh, expiresAt]
    );

    res.cookie(cookieName, newRefresh, refreshCookieOptions());

    const safeUser = {
      id: row.id,
      name: row.name,
      email: row.email,
      phone: row.phone,
      address: row.address,
      created_at: row.created_at
    };
    const accessToken = createAccessToken(safeUser);
    return res.json({ status: true, accessToken: accessToken, refreshToken: newRefresh });
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error(err);
    return res.status(500).json({ status: false, error: "server_error", message: "Server error." });
  }
}

async function handleLogout(req, res) {
  const cookieName = getRefreshCookieName();
  const raw = getCookie(req, cookieName);
  if (raw) {
    try {
      await pool.execute("DELETE FROM refresh_tokens WHERE token_hash = ?", [raw]);
    } catch (err) {
      // eslint-disable-next-line no-console
      console.error(err);
    }
  }

  const opts = refreshCookieOptions();
  // Clear current cookie name + common legacy names (so clients don't stay "logged in").
  for (const name of new Set([cookieName, "ap_rt", "refresh_token"])) {
    clearRefreshCookie(res, name, opts);
  }
  return res.json({ status: true });
}

async function handleRegister(req, res) {
  const name = String((req.body.name ?? req.body.username) ?? "").trim();
  const email = String(req.body.email ?? "").trim().toLowerCase();
  const phone = String(req.body.phone ?? "").trim() || null;
  const address = String(req.body.address ?? "").trim() || null;
  const password = String(req.body.password ?? "");

  if (!name) {
    return res.status(400).json({ status: false, error: "validation_error", message: "Name is required." });
  }
  if (!email || !isValidEmail(email)) {
    return res.status(400).json({ status: false, error: "validation_error", message: "Valid email is required." });
  }
  if (!password || password.length < 6) {
    return res
      .status(400)
      .json({ status: false, error: "validation_error", message: "Password must be at least 6 characters." });
  }

  try {
    const passwordHash = await bcrypt.hash(password, 10);
    const [result] = await pool.execute(
      "INSERT INTO users (name, email, phone, address, password_hash) VALUES (?, ?, ?, ?, ?)",
      [name, email, phone, address, passwordHash]
    );

    res.status(201).json({
      status: true,
      id: result.insertId,
      userUrl: `/users/${result.insertId}`
    });
  } catch (err) {
    // MySQL duplicate email
    if (err && err.code === "ER_DUP_ENTRY") {
      return res
        .status(409)
        .json({ status: false, error: "duplicate", message: "This email is already registered." });
    }
    // eslint-disable-next-line no-console
    console.error(err);
    res.status(500).json({ status: false, error: "server_error", message: "Server error." });
  }
}

const registerLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 2,
  skipFailedRequests: true,
  standardHeaders: true,
  legacyHeaders: false,
  handler(req, res, next, options) {
    const limit = req.rateLimit?.limit ?? options.limit;
    const used = req.rateLimit?.used;
    const remaining = req.rateLimit?.remaining;
    const resetTime = req.rateLimit?.resetTime;
    const retryAfterSeconds = Math.max(
      1,
      Math.ceil(((resetTime?.getTime?.() ?? Date.now()) - Date.now()) / 1000)
    );
    res.status(options.statusCode).json({
      status: false,
      error: "rate_limit_exceeded",
      message: "Only 2 registration requests allowed per minute. Please try again later.",
      retryAfterSeconds,
      limit,
      used,
      remaining,
      resetTime: resetTime ? resetTime.toISOString() : undefined
    });
  }
});

const loginLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 10,
  skipFailedRequests: false,
  standardHeaders: true,
  legacyHeaders: false,
  handler(req, res, next, options) {
    const resetTime = req.rateLimit?.resetTime;
    const retryAfterSeconds = Math.max(
      1,
      Math.ceil(((resetTime?.getTime?.() ?? Date.now()) - Date.now()) / 1000)
    );
    res.status(options.statusCode).json({
      status: false,
      error: "rate_limit_exceeded",
      message: "Too many login attempts. Please try again later.",
      retryAfterSeconds
    });
  }
});

app.post("/login", loginLimiter, handleLogin);
app.post("/api/login", loginLimiter, handleLogin);
app.post("/api/auth/login", loginLimiter, handleLogin);
app.post("/api/refresh", handleRefresh);
app.post("/api/auth/refresh", handleRefresh);
app.post("/api/logout", handleLogout);
app.post("/api/auth/logout", handleLogout);

app.post("/register", registerLimiter, handleRegister);
app.post("/api/register", registerLimiter, handleRegister);

app.get("/users/:id", async (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isInteger(id) || id <= 0) {
    return res.status(400).json({ status: false, error: "validation_error", message: "Invalid id." });
  }

  try {
    const rows = await query(
      "SELECT id, name, email, phone, address, created_at FROM users WHERE id = ?",
      [id]
    );
    const user = rows[0];
    if (!user) return res.status(404).json({ status: false, error: "not_found", message: "User not found." });

    res.json({ status: true, user });
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error(err);
    res.status(500).json({ status: false, error: "server_error", message: "Server error." });
  }
});

// Optional: see saved users (JSON)
app.get("/api/users", async (req, res) => {
  try {
    const rows = await query(
      "SELECT id, name, email, phone, address, created_at FROM users ORDER BY id DESC",
      []
    );
    res.json({ status: true, users: rows });
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error(err);
    res.status(500).json({ status: false, error: "server_error", message: "Server error." });
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
    if (!Number.isInteger(port) || port < 0 || port > 65535) {
      throw new Error("PORT must be an integer between 0 and 65535.");
    }
    if (port === 0) return 0;
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

  // Fallback: let the OS pick any free port.
  return 0;
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

    await pool.execute(`
      CREATE TABLE IF NOT EXISTS refresh_tokens (
        id INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
        user_id INT UNSIGNED NOT NULL,
        token_hash VARCHAR(500) NOT NULL,
        expires_at DATETIME NOT NULL,
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
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
  const server = app.listen(port, () => {
    const addr = server.address();
    const actualPort = typeof addr === "object" && addr && "port" in addr ? addr.port : port;
    // eslint-disable-next-line no-console
    console.log(`Server running: http://localhost:${actualPort}`);
  });
}

main().catch((err) => {
  // eslint-disable-next-line no-console
  console.error(err.message || err);
  process.exit(1);
});
