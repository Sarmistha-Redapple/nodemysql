function register(app, { querySql }) {
  app.get("/users/:id", async (req, res) => {
    const id = Number(req.params.id);
    if (!Number.isInteger(id) || id <= 0) {
      return res.status(400).json({ status: false, error: "validation_error", message: "Invalid id." });
    }

    try {
      const rows = await querySql("queries/users/select_by_id", [id]);
      const user = rows[0];
      if (!user) return res.status(404).json({ status: false, error: "not_found", message: "User not found." });

      return res.json({ status: true, user });
    } catch (err) {
      // eslint-disable-next-line no-console
      console.error(err);
      return res.status(500).json({ status: false, error: "server_error", message: "Server error." });
    }
  });

  // Optional: see saved users (JSON)
  app.get("/api/users", async (req, res) => {
    try {
      const rows = await querySql("queries/users/select_all_desc", []);
      return res.json({ status: true, users: rows });
    } catch (err) {
      // eslint-disable-next-line no-console
      console.error(err);
      return res.status(500).json({ status: false, error: "server_error", message: "Server error." });
    }
  });
}

module.exports = { register };
