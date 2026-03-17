const fs = require("fs");
const path = require("path");

function registerRoutes(app, deps) {
  const routesDir = path.join(__dirname, "route-modules");
  const files = fs
    .readdirSync(routesDir, { withFileTypes: true })
    .filter((d) => d.isFile())
    .map((d) => d.name)
    .filter((name) => name.endsWith(".js"))
    .sort();

  for (const name of files) {
    // eslint-disable-next-line global-require, import/no-dynamic-require
    const mod = require(path.join(routesDir, name));
    if (!mod || typeof mod.register !== "function") {
      throw new Error(`Route module "${name}" must export { register(app, deps) }`);
    }
    mod.register(app, deps);
  }
}

module.exports = { registerRoutes };
