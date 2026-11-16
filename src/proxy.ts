import express, { type Request, type Response, type Router } from "express";
import { Readable } from "node:stream";
import { requireBearerAuth } from "@modelcontextprotocol/sdk/server/auth/middleware/bearerAuth.js";
import type { OAuthTokenVerifier } from "@modelcontextprotocol/sdk/server/auth/provider.js";
import { toolAllowed, type UpstreamConfig } from "./config.js";

type Msg = { jsonrpc?: string; id?: unknown; method?: string; params?: { name?: string }; result?: { tools?: { name: string }[] } };
const FORWARD_REQ = ["accept", "content-type", "mcp-session-id", "mcp-protocol-version", "last-event-id"];
const FORWARD_RES = ["content-type", "mcp-session-id", "cache-control"];

export interface ProxyDeps {
  name: string; upstream: UpstreamConfig; resource: string; metadataUrl: string; publicAuthServer: string;
  verifier: OAuthTokenVerifier; getCredentials: (credId: string | undefined) => string | undefined; audit: (e: Record<string, unknown>) => void; fetchImpl?: typeof fetch;
}

/** Remove tools the policy hides from a tools/list result, in a JSON body or an SSE stream. */
export function filterToolList(body: string, contentType: string, ids: Set<unknown>, allowed: (t: string) => boolean): string {
  const filt = (m: Msg) => { if (m.result?.tools && ids.has(m.id)) m.result.tools = m.result.tools.filter((t) => allowed(t.name)); return m; };
  if (contentType.includes("text/event-stream")) {
    return body.split("\n").map((line) => {
      if (!line.startsWith("data:")) return line;
      try { const m = JSON.parse(line.slice(5)); return "data: " + JSON.stringify(Array.isArray(m) ? m.map(filt) : filt(m)); } catch { return line; }
    }).join("\n");
  }
  try { const m = JSON.parse(body); return JSON.stringify(Array.isArray(m) ? m.map(filt) : filt(m)); } catch { return body; }
}

export function upstreamRouter(d: ProxyDeps): Router {
  const r = express.Router();
  const doFetch = d.fetchImpl ?? fetch;
  const allowed = (t: string) => toolAllowed(d.upstream.tools, t);
  const windowHits = new Map<string, number[]>();
  const limited = (who: string) => { const t = Date.now(), hits = (windowHits.get(who) ?? []).filter((x) => t - x < 60_000); hits.push(t); windowHits.set(who, hits); return hits.length > 240; };

  r.get(`/.well-known/oauth-protected-resource/${d.name}/mcp`, (_req, res) => {
    res.json({ resource: d.resource, authorization_servers: [d.publicAuthServer], scopes_supported: ["mcp"], bearer_methods_supported: ["header"], resource_name: d.upstream.title ?? d.name });
  });

  r.all(`/${d.name}/mcp`,
    requireBearerAuth({ verifier: d.verifier, resourceMetadataUrl: d.metadataUrl, expectedResource: new URL(d.resource) }),
    express.raw({ type: () => true, limit: "4mb" }),
    async (req: Request, res: Response) => {
      const email = String(req.auth?.extra?.email ?? "?");
      if (limited(email)) { res.status(429).json({ error: "rate_limited" }); return; }
      const raw = Buffer.isBuffer(req.body) ? req.body : Buffer.alloc(0);
      let msgs: Msg[] = [];
      if (req.method === "POST" && raw.length) {
        try { const p = JSON.parse(raw.toString("utf8")); msgs = Array.isArray(p) ? p : [p]; }
        catch { res.status(400).json({ jsonrpc: "2.0", id: null, error: { code: -32700, message: "Parse error" } }); return; }
      }
      const calls = msgs.filter((m) => m.method === "tools/call").map((m) => m.params?.name ?? "");
      const denied = msgs.find((m) => m.method === "tools/call" && !allowed(m.params?.name ?? ""));
      d.audit({ event: "mcp", upstream: d.name, email, http: req.method, methods: msgs.map((m) => m.method), tools: calls, denied: denied?.params?.name });
      if (denied) { res.status(200).json({ jsonrpc: "2.0", id: denied.id ?? null, error: { code: -32601, message: `Tool '${denied.params?.name}' is not available through the gateway` } }); return; }
      const listIds = new Set(msgs.filter((m) => m.method === "tools/list").map((m) => m.id));

      const headers: Record<string, string> = { ...(d.upstream.headers ?? {}) };
      if (d.upstream.credentials) {
        const creds = d.getCredentials(req.auth?.extra?.credId as string | undefined);
        if (!creds) { res.status(401).set("www-authenticate", `Bearer error="invalid_token", resource_metadata="${d.metadataUrl}"`).json({ error: "invalid_token", error_description: "credentials missing; reconnect the connector" }); return; }
        headers["x-upstream-credentials"] = Buffer.from(creds).toString("base64url");
      }
      for (const h of FORWARD_REQ) { const v = req.header(h); if (v) headers[h] = v; }
      const ac = new AbortController();
      res.on("close", () => ac.abort());
      let up: Response | globalThis.Response;
      try { up = await doFetch(d.upstream.url, { method: req.method, headers, body: req.method === "POST" ? new Uint8Array(raw) : undefined, signal: ac.signal }) as globalThis.Response; }
      catch { if (!res.headersSent) res.status(502).json({ error: "upstream_unreachable" }); return; }
      const u = up as globalThis.Response;
      res.status(u.status);
      for (const h of FORWARD_RES) { const v = u.headers.get(h); if (v) res.setHeader(h, v); }
      if (!u.body) { res.end(); return; }
      if (listIds.size) {
        const body = filterToolList(await u.text(), u.headers.get("content-type") ?? "", listIds, allowed);
        res.send(body); return;
      }
      Readable.fromWeb(u.body as never).on("error", () => res.end()).pipe(res);
    });
  return r;
}
