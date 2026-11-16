import express from "express";
import { appendFileSync } from "node:fs";
import { join } from "node:path";
import { mcpAuthRouter } from "@modelcontextprotocol/sdk/server/auth/router.js";
import type { Config } from "./config.js";
import { Store } from "./store.js";
import { GatewayProvider } from "./provider.js";
import { upstreamRouter } from "./proxy.js";

export function buildApp(cfg: Config, opts: { fetchImpl?: typeof fetch } = {}) {
  const store = new Store(cfg.dataDir);
  const auditPath = join(cfg.dataDir, "audit.log");
  const audit = (e: Record<string, unknown>) => { try { appendFileSync(auditPath, JSON.stringify({ ts: new Date().toISOString(), ...e }) + "\n", { mode: 0o600 }); } catch { /* never block a request on logging */ } };
  const provider = new GatewayProvider(cfg, store, audit);
  const app = express();
  app.disable("x-powered-by");
  app.set("trust proxy", 1);
  app.get("/healthz", (_req, res) => { res.json({ ok: true }); });
  const issuer = new URL(cfg.publicUrl);
  app.use(mcpAuthRouter({ provider, issuerUrl: issuer, baseUrl: issuer, scopesSupported: ["mcp"], resourceName: "MCP gateway" }));
  app.get("/google/callback", provider.handleGoogleCallback);
  for (const [name, upstream] of Object.entries(cfg.upstreams)) {
    app.use(upstreamRouter({ name, upstream, resource: provider.resourceUrl(name), metadataUrl: `${cfg.publicUrl}/.well-known/oauth-protected-resource/${name}/mcp`, publicAuthServer: cfg.publicUrl, verifier: provider, audit, fetchImpl: opts.fetchImpl }));
  }
  app.use((_req, res) => { res.status(404).json({ error: "not_found" }); });
  const sweeper = setInterval(() => store.sweep(), 60_000); sweeper.unref();
  return { app, store, provider, audit };
}
