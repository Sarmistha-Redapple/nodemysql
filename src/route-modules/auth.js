const rateLimit = require("express-rate-limit");

function register(app, { handleLogin, handleRefresh, handleLogout, handleRegister }) {
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
      const retryAfterSeconds = Math.max(1, Math.ceil(((resetTime?.getTime?.() ?? Date.now()) - Date.now()) / 1000));
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
      const retryAfterSeconds = Math.max(1, Math.ceil(((resetTime?.getTime?.() ?? Date.now()) - Date.now()) / 1000));
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
}

module.exports = { register };

