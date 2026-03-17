function register(app) {
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
}

module.exports = { register };

