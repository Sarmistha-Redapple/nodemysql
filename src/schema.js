const { executeSql } = require("./db");

async function ensureSchema() {
  try {
    await executeSql("schema/create_users_table", []);
    await executeSql("schema/create_refresh_tokens_table", []);

    // Optional hardening: dedupe rows so there is only one refresh token row per user.
    // This keeps behavior consistent even if older versions inserted multiple rows.
    try {
      await executeSql("schema/refresh_tokens_dedupe", []);
    } catch (err) {
      // eslint-disable-next-line no-console
      console.warn("Warning: refresh_tokens cleanup skipped:", err && err.code ? err.code : err);
    }

    // Enforce: only one row per user (for existing DBs).
    try {
      await executeSql("schema/refresh_tokens_add_unique_user_id", []);
    } catch (err) {
      if (err && err.code === "ER_DUP_KEYNAME") {
        // Index already exists.
      } else {
        // eslint-disable-next-line no-console
        console.warn("Warning: refresh_tokens unique index not added:", err && err.code ? err.code : err);
      }
    }
  } catch (err) {
    if (err && err.code === "ER_BAD_DB_ERROR") {
      throw new Error(
        `Database "${process.env.DB_NAME}" not found. Create it (run sql/init.sql) or start docker-compose.`
      );
    }
    throw err;
  }
}

module.exports = { ensureSchema };
