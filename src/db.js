const mysql = require("mysql2/promise");

function requireEnv(name) {
  const value = process.env[name];
  if (!value && value !== "") {
    throw new Error(
      `Missing required env var: ${name}. Create a .env file (cp .env.example .env) and set DB_* values.`
    );
  }
  return value;
}

const pool = mysql.createPool({
  host: requireEnv("DB_HOST"),
  port: Number(requireEnv("DB_PORT")),
  user: requireEnv("DB_USER"),
  password: requireEnv("DB_PASSWORD"),
  database: requireEnv("DB_NAME"),
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

async function query(sql, params) {
  const [rows] = await pool.execute(sql, params);
  return rows;
}

module.exports = { pool, query };
