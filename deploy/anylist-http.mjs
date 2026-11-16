// Single-purpose HTTP front for the AnyList MCP server, for use behind mcp-gateway.
// Listens on loopback only. Credentials arrive per request from the gateway in x-upstream-credentials
// (base64url JSON {username, password}); nothing is read from the environment or written to disk.
//
//   ANYLIST_MCP_DIR  path to a checkout of the anylist-mcp project (default ~/workspace/anylist-mcp)
//   PORT             default 8093
import http from "node:http";
import { createHash } from "node:crypto";
import { pathToFileURL } from "node:url";
import { join } from "node:path";
import { homedir } from "node:os";

const dir = process.env.ANYLIST_MCP_DIR ?? join(homedir(), "workspace/anylist-mcp");
const load = (rel) => import(pathToFileURL(join(dir, rel)).href);
const sdk = (rel) => import(pathToFileURL(join(dir, "node_modules/@modelcontextprotocol/sdk/dist/esm", rel)).href);
const { McpServer } = await sdk("server/mcp.js");
const { StreamableHTTPServerTransport } = await sdk("server/streamableHttp.js");
const { default: AnyListClient } = await load("src/anylist-client.js");
const { registerAllTools } = await load("src/tools/index.js");

// AnyList logins are slow, so keep one client per credential set for a while. Memory only.
const clients = new Map();
const IDLE_MS = 30 * 60_000;
function clientFor(creds) {
  const key = createHash("sha256").update(JSON.stringify(creds)).digest("hex");
  let e = clients.get(key);
  if (!e) { e = { client: new AnyListClient({ username: creds.username, password: creds.password }), last: 0 }; clients.set(key, e); }
  e.last = Date.now();
  return e.client;
}
setInterval(() => { for (const [k, e] of clients) if (Date.now() - e.last > IDLE_MS) clients.delete(k); }, 60_000).unref();

const server = http.createServer(async (req, res) => {
  if (!req.url?.startsWith("/mcp")) { res.writeHead(404).end(); return; }
  let creds;
  try { creds = JSON.parse(Buffer.from(String(req.headers["x-upstream-credentials"] ?? ""), "base64url").toString()); } catch { /* handled below */ }
  if (!creds?.username || !creds?.password) { res.writeHead(401, { "content-type": "application/json" }).end(JSON.stringify({ error: "credentials required" })); return; }
  const chunks = []; for await (const c of req) chunks.push(c);
  let body; try { body = chunks.length ? JSON.parse(Buffer.concat(chunks).toString()) : undefined; } catch { res.writeHead(400).end(); return; }
  const mcp = new McpServer({ name: "anylist-mcp-server", version: "gateway" });
  registerAllTools(mcp, () => clientFor(creds));
  const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined, enableJsonResponse: true }); // stateless
  res.on("close", () => { transport.close(); mcp.close(); });
  await mcp.connect(transport);
  await transport.handleRequest(req, res, body);
});
server.listen(Number(process.env.PORT ?? 8093), "127.0.0.1", () => console.error(`anylist-http on 127.0.0.1:${server.address().port}`));
