import { loadConfig } from "./config.js";
import { buildApp } from "./app.js";

const path = process.env.GATEWAY_CONFIG ?? new URL("../../config.json", import.meta.url).pathname;
const cfg = loadConfig(path);
const { app } = buildApp(cfg);
app.listen(cfg.port, cfg.host, () => console.log(`mcp-gateway on ${cfg.host}:${cfg.port}, public ${cfg.publicUrl}, upstreams: ${Object.keys(cfg.upstreams).join(", ")}`));
