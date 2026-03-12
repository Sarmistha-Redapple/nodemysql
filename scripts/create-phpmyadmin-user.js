#!/usr/bin/env node
const mysql = require("mysql2/promise");
const dotenv = require("dotenv");

dotenv.config();

function getArg(name, fallback = null) {
  const idx = process.argv.indexOf(`--${name}`);
  if (idx === -1) return fallback;
  return process.argv[idx + 1] ?? fallback;
}

function requireValue(value, label) {
  if (!value) throw new Error(`Missing ${label}`);
  return value;
}

async function main() {
  const dbHost = getArg("db-host", process.env.DB_HOST || "127.0.0.1");
  const dbPort = Number(getArg("db-port", process.env.DB_PORT || 3306));
  const dbUser = requireValue(getArg("db-user", process.env.DB_USER), "DB_USER (set .env or pass --db-user)");
  const dbPassword = getArg("db-pass", process.env.DB_PASSWORD ?? "");
  const dbName = getArg("db-name", process.env.DB_NAME || "demo_app");

  const root = requireValue(getArg("pma-user", "root"), "--pma-user");
  const pmaPass = requireValue(getArg("pma-pass", null), "--pma-pass");
  const pmaHost = getArg("pma-host", "%");

  // eslint-disable-next-line no-console
  console.log("Connecting to MySQL:", { dbHost, dbPort, dbUser, dbName });

  const conn = await mysql.createConnection({
    host: dbHost,
    port: dbPort,
    user: dbUser,
    password: dbPassword,
    multipleStatements: false
  });

  try {
    await conn.execute(`CREATE USER IF NOT EXISTS \`${root}\`@\`${pmaHost}\` IDENTIFIED BY ?`, [
      pmaPass
    ]);
    await conn.execute(`GRANT ALL PRIVILEGES ON \`${dbName}\`.* TO \`${root}\`@\`${pmaHost}\``);
    await conn.execute("FLUSH PRIVILEGES");

    // eslint-disable-next-line no-console
    console.log("OK: phpMyAdmin user created/granted:", { root, pmaHost, dbName });
  } finally {
    await conn.end();
  }
}

main().catch((err) => {
  if (err && (err.code === "ER_ACCESS_DENIED_ERROR" || String(err.message || "").includes("Access denied"))) {
    // eslint-disable-next-line no-console
    console.error(
      "Access denied: check DB host/user/password. If MySQL is in Docker, run the SQL inside the MySQL container (docker exec) or connect using a MySQL admin user that is allowed from your current host."
    );
  }
  // eslint-disable-next-line no-console
  console.error(err.message || err);
  process.exit(1);
});
