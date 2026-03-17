const mysql = require("mysql2/promise");
const fs = require("fs");
const path = require("path");

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

const sqlCache = new Map();
let initSqlMap = null;

function parseInitSql(sqlText) {
  const map = new Map();
  const lines = String(sqlText).replaceAll("\r\n", "\n").split("\n");

  let currentName = null;
  let currentLines = [];

  function flush() {
    if (!currentName) return;
    const text = currentLines.join("\n").trim();
    if (text) map.set(currentName, text);
  }

  for (const line of lines) {
    const match = line.match(/^\s*--\s*name:\s*(.+?)\s*$/i);
    if (match) {
      flush();
      currentName = match[1].trim();
      currentLines = [];
      continue;
    }
    if (currentName) currentLines.push(line);
  }
  flush();
  return map;
}

function loadSql(name) {
  const key = String(name);
  const cached = sqlCache.get(key);
  if (cached) return cached;

  if (!initSqlMap) {
    const initPath = path.join(__dirname, "..", "sql", "init.sql");
    const initText = fs.readFileSync(initPath, "utf8");
    initSqlMap = parseInitSql(initText);
  }

  const text = initSqlMap.get(key);
  if (!text) {
    throw new Error(`SQL "${key}" not found in sql/init.sql. Add a block like: -- name: ${key}`);
  }

  sqlCache.set(key, text);
  return text;
}

async function executeSql(name, params) {
  const sql = loadSql(name);
  const [result] = await pool.execute(sql, params);
  return result;
}

async function querySql(name, params) {
  const sql = loadSql(name);
  const [rows] = await pool.execute(sql, params);
  return rows;
}

module.exports = { pool, query, loadSql, executeSql, querySql };
