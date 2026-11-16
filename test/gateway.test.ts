import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import net from "node:net";
import { createHash, randomBytes } from "node:crypto";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { parseConfig, toolAllowed } from "../src/config.js";
import { buildApp } from "../src/app.js";

const CB = "https://claude.ai/api/mcp/auth_callback";
const freePort = () => new Promise<number>((r) => { const s = net.createServer().listen(0, "127.0.0.1", () => { const p = (s.address() as net.AddressInfo).port; s.close(() => r(p)); }); });
const listen = (srv: http.Server, port: number) => new Promise<void>((r) => srv.listen(port, "127.0.0.1", r));

let gw: http.Server, google: http.Server, upstream: http.Server, base: string, dir: string;
let googleEmail = "kyle@example.test";
const nonces = new Map<string, string>();
const seen: { url: string; headers: http.IncomingHttpHeaders; body: string }[] = [];
const TOOLS = [{ name: "search" }, { name: "add_candidate" }, { name: "confirm_event" }, { name: "accept_proposal" }];

before(async () => {
  const [gp, goP, upP] = await Promise.all([freePort(), freePort(), freePort()]);
  base = `http://127.0.0.1:${gp}`;
  dir = mkdtempSync(join(tmpdir(), "gw-"));
  google = http.createServer((req, res) => {
    const u = new URL(req.url!, "http://x");
    if (u.pathname === "/auth") { // fake Google: sign in immediately and bounce back
      const code = randomBytes(8).toString("hex"); nonces.set(code, u.searchParams.get("nonce")!);
      res.writeHead(302, { location: `${u.searchParams.get("redirect_uri")}?code=${code}&state=${u.searchParams.get("state")}` }).end();
    } else if (u.pathname === "/token") {
      let b = ""; req.on("data", (c) => (b += c)); req.on("end", () => {
        const code = new URLSearchParams(b).get("code")!;
        const payload = { iss: "https://accounts.google.com", aud: "gid", email: googleEmail, email_verified: true, nonce: nonces.get(code), exp: Math.floor(Date.now() / 1000) + 300 };
        res.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify({ id_token: `x.${Buffer.from(JSON.stringify(payload)).toString("base64url")}.y` }));
      });
    } else res.writeHead(404).end();
  });
  upstream = http.createServer((req, res) => {
    let b = ""; req.on("data", (c) => (b += c)); req.on("end", () => {
      seen.push({ url: req.url!, headers: req.headers, body: b });
      const m = b ? JSON.parse(b) : {};
      const result = m.method === "tools/list" ? { tools: TOOLS } : m.method === "tools/call" ? { content: [{ type: "text", text: "ran " + m.params.name }] } : {};
      const json = JSON.stringify({ jsonrpc: "2.0", id: m.id, result });
      if (req.url!.startsWith("/sse")) res.writeHead(200, { "content-type": "text/event-stream" }).end(`event: message\ndata: ${json}\n\n`);
      else res.writeHead(200, { "content-type": "application/json", "mcp-session-id": "s1" }).end(json);
    });
  });
  await Promise.all([listen(google, goP), listen(upstream, upP)]);
  const cfg = parseConfig({
    publicUrl: base, port: gp, dataDir: dir, allowedEmails: ["Kyle@example.test"],
    google: { clientId: "gid", clientSecret: "gsecret", authUrl: `http://127.0.0.1:${goP}/auth`, tokenUrl: `http://127.0.0.1:${goP}/token` },
    upstreams: {
      timeline: { url: `http://127.0.0.1:${upP}/mcp?agent=claude-cloud`, headers: { "x-upstream-key": "k1" }, tools: { deny: ["confirm_*", "accept_*"] } },
      other: { url: `http://127.0.0.1:${upP}/sse`, tools: { allow: ["search"] } },
    },
  });
  gw = buildApp(cfg).app.listen(gp, "127.0.0.1") as http.Server;
  await new Promise((r) => gw.once("listening", r));
});
after(() => { gw.close(); google.close(); upstream.close(); });

const b64 = (b: Buffer) => b.toString("base64url");
async function signIn(resource: string) {
  const reg = await fetch(`${base}/register`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ client_name: "Claude", redirect_uris: [CB], token_endpoint_auth_method: "none", grant_types: ["authorization_code", "refresh_token"], response_types: ["code"] }) });
  assert.equal(reg.status, 201);
  const client = (await reg.json()) as { client_id: string };
  const verifier = b64(randomBytes(32)), challenge = b64(createHash("sha256").update(verifier).digest());
  const a = new URL(`${base}/authorize`);
  a.search = new URLSearchParams({ response_type: "code", client_id: client.client_id, redirect_uri: CB, code_challenge: challenge, code_challenge_method: "S256", state: "st1", resource, scope: "mcp" }).toString();
  const r1 = await fetch(a, { redirect: "manual" });
  assert.equal(r1.status, 302);
  const r2 = await fetch(r1.headers.get("location")!, { redirect: "manual" }); // fake Google bounces to the gateway callback
  const r3 = await fetch(r2.headers.get("location")!, { redirect: "manual" });
  return { client, verifier, r3 };
}
const exchange = async (client_id: string, code: string, verifier: string, resource: string) =>
  fetch(`${base}/token`, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ grant_type: "authorization_code", client_id, code, code_verifier: verifier, redirect_uri: CB, resource }) });
async function token(name: string) {
  const resource = `${base}/${name}/mcp`;
  const { client, verifier, r3 } = await signIn(resource);
  const cb = new URL(r3.headers.get("location")!);
  assert.equal(cb.origin + cb.pathname, CB); assert.equal(cb.searchParams.get("state"), "st1");
  const t = await exchange(client.client_id, cb.searchParams.get("code")!, verifier, resource);
  assert.equal(t.status, 200);
  return { ...(await t.json()) as { access_token: string; refresh_token: string }, client };
}
const rpc = (name: string, tok: string | null, body: unknown, extra: Record<string, string> = {}) =>
  fetch(`${base}/${name}/mcp`, { method: "POST", headers: { "content-type": "application/json", accept: "application/json, text/event-stream", ...(tok ? { authorization: `Bearer ${tok}` } : {}), ...extra }, body: JSON.stringify(body) });

test("policy matching", () => {
  assert.equal(toolAllowed({ deny: ["confirm_*"] }, "confirm_event"), false);
  assert.equal(toolAllowed({ deny: ["confirm_*"] }, "search"), true);
  assert.equal(toolAllowed({ allow: ["search"] }, "add_candidate"), false);
  assert.equal(toolAllowed({ allow: ["a*"], deny: ["ab"] }, "ab"), false);
});

test("config refuses public upstreams and unnamed config", () => {
  const ok = { publicUrl: "https://x.test", dataDir: "/tmp/x", allowedEmails: ["a@b.c"], google: { clientId: "i", clientSecret: "s" } };
  assert.throws(() => parseConfig({ ...ok, upstreams: { a: { url: "https://evil.example.com/mcp" } } }), /loopback or tailnet/);
  assert.throws(() => parseConfig({ ...ok, upstreams: { "Bad Name": { url: "http://127.0.0.1:1/mcp" } } }), /lowercase/);
  assert.throws(() => parseConfig({ ...ok, allowedEmails: [], upstreams: { a: { url: "http://127.0.0.1:1/mcp" } } }), /allowedEmails/);
});

test("unauthenticated request gets 401 with resource_metadata, and discovery documents are served", async () => {
  const r = await rpc("timeline", null, { jsonrpc: "2.0", id: 1, method: "tools/list" });
  assert.equal(r.status, 401);
  assert.match(r.headers.get("www-authenticate")!, new RegExp(`resource_metadata="${base}/.well-known/oauth-protected-resource/timeline/mcp"`));
  const prm = (await (await fetch(`${base}/.well-known/oauth-protected-resource/timeline/mcp`)).json()) as { resource: string; authorization_servers: string[] };
  assert.equal(prm.resource, `${base}/timeline/mcp`); assert.equal(prm.authorization_servers[0], base);
  const as = (await (await fetch(`${base}/.well-known/oauth-authorization-server`)).json()) as Record<string, unknown>;
  assert.deepEqual(as.code_challenge_methods_supported, ["S256"]); assert.ok(as.registration_endpoint);
});

test("registration only accepts Claude's callback", async () => {
  const r = await fetch(`${base}/register`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ redirect_uris: ["https://evil.example.com/cb"], token_endpoint_auth_method: "none" }) });
  assert.equal(r.status, 400);
});

test("full flow: sign in, filtered tools/list, denied call blocked, allowed call passes, no credentials leak upstream", async () => {
  const t = await token("timeline");
  const list = (await (await rpc("timeline", t.access_token, { jsonrpc: "2.0", id: 1, method: "tools/list" })).json()) as { result: { tools: { name: string }[] } };
  assert.deepEqual(list.result.tools.map((x) => x.name), ["search", "add_candidate"]);
  const denied = (await (await rpc("timeline", t.access_token, { jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: "confirm_event", arguments: {} } })).json()) as { error: { message: string } };
  assert.match(denied.error.message, /not available/);
  assert.ok(!seen.some((s) => s.body.includes("confirm_event")), "denied call must never reach the upstream");
  const ok = (await (await rpc("timeline", t.access_token, { jsonrpc: "2.0", id: 3, method: "tools/call", params: { name: "search", arguments: {} } })).json()) as { result: { content: { text: string }[] } };
  assert.equal(ok.result.content[0].text, "ran search");
  const last = seen[seen.length - 1];
  assert.equal(last.headers.authorization, undefined); assert.equal(last.headers["x-upstream-key"], "k1"); assert.match(last.url, /agent=claude-cloud/);
});

test("a batch containing a denied call is refused whole", async () => {
  const t = await token("timeline"); const before = seen.length;
  const r = await rpc("timeline", t.access_token, [{ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "search" } }, { jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: "accept_proposal" } }]);
  assert.match(JSON.stringify(await r.json()), /not available/); assert.equal(seen.length, before);
});

test("SSE upstream: tools/list is filtered inside the event stream", async () => {
  const t = await token("other");
  const r = await rpc("other", t.access_token, { jsonrpc: "2.0", id: 1, method: "tools/list" });
  assert.match(r.headers.get("content-type")!, /event-stream/);
  assert.deepEqual((JSON.parse((await r.text()).split("\n").find((l) => l.startsWith("data:"))!.slice(5)) as { result: { tools: { name: string }[] } }).result.tools.map((x) => x.name), ["search"]);
});

test("a token is bound to one upstream", async () => {
  const t = await token("timeline");
  assert.equal((await rpc("other", t.access_token, { jsonrpc: "2.0", id: 1, method: "tools/list" })).status, 401);
});

test("authorize refuses an unknown resource", async () => {
  const reg = (await (await fetch(`${base}/register`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ redirect_uris: [CB], token_endpoint_auth_method: "none" }) })).json()) as { client_id: string };
  const a = new URL(`${base}/authorize`);
  a.search = new URLSearchParams({ response_type: "code", client_id: reg.client_id, redirect_uri: CB, code_challenge: "x".repeat(43), code_challenge_method: "S256", resource: "https://other.example.com/mcp" }).toString();
  const r = await fetch(a, { redirect: "manual" });
  const loc = r.headers.get("location") ?? "";
  assert.ok(r.status >= 300 && loc.startsWith(CB) && new URL(loc).searchParams.get("error") === "invalid_target", `expected invalid_target redirect, got ${r.status} ${loc}`);
});

test("wrong PKCE verifier is rejected, and a code works once", async () => {
  const resource = `${base}/timeline/mcp`;
  const { client, r3 } = await signIn(resource);
  const code = new URL(r3.headers.get("location")!).searchParams.get("code")!;
  assert.notEqual((await exchange(client.client_id, code, b64(randomBytes(32)), resource)).status, 200);
  assert.notEqual((await exchange(client.client_id, code, b64(randomBytes(32)), resource)).status, 200);
});

test("refresh rotates: the old refresh token stops working", async () => {
  const t = await token("timeline");
  const refresh = (rt: string) => fetch(`${base}/token`, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ grant_type: "refresh_token", client_id: t.client.client_id, refresh_token: rt }) });
  const r1 = await refresh(t.refresh_token); assert.equal(r1.status, 200);
  const n = (await r1.json()) as { refresh_token: string; access_token: string };
  assert.notEqual(n.refresh_token, t.refresh_token);
  assert.notEqual((await refresh(t.refresh_token)).status, 200);
  assert.equal((await rpc("timeline", n.access_token, { jsonrpc: "2.0", id: 1, method: "tools/list" })).status, 200);
});

test("a Google account that is not on the allowlist is refused and logged", async () => {
  googleEmail = "intruder@example.test";
  try {
    const { r3 } = await signIn(`${base}/timeline/mcp`);
    assert.equal(r3.status, 403);
  } finally { googleEmail = "kyle@example.test"; }
  const log = readFileSync(join(dir, "audit.log"), "utf8");
  assert.match(log, /"event":"login_refused"/);
  assert.ok(!/"arguments"/.test(log), "audit log must not record tool arguments");
});
