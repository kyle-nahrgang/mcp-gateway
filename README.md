# mcp-gateway

An OAuth gateway that lets claude.ai (web, phone, desktop) use selected MCP servers running on node1, without opening node1 to the internet in general.

```
claude.ai ──https──▶ Tailscale Funnel ──▶ mcp-gateway :8092 ──▶ 127.0.0.1:<port>/mcp  (one entry per upstream)
```

Only the gateway is published. Each upstream is named in `config.json`, gets its own connector URL (`https://HOST/<name>/mcp`) and its own tool policy. Nothing else on node1 is reachable, and the upstream's own HTTP API (for the life timeline: the viewer and the confirm/accept endpoints) is never exposed.

## What it does

- **OAuth authorization server** for Claude's connector flow (MCP authorization spec, 2025-11): protected-resource and authorization-server metadata, dynamic client registration, authorization code with S256 PKCE, refresh tokens that rotate. Built on the MCP TypeScript SDK's auth handlers.
- **Login with Google**, restricted to `allowedEmails`. No other account gets a token.
- **Registration is locked** to Claude's callback, `https://claude.ai/api/mcp/auth_callback` (override with `allowedRedirectUris`).
- **Tokens are bound to one upstream** (RFC 8707 `resource`): a token for `/anylist/mcp` is useless on `/life-timeline/mcp`. Tokens and codes are stored hashed in SQLite.
- **Tool policy per upstream** (`allow` / `deny`, trailing `*` matches a prefix): hidden tools are removed from `tools/list` (JSON or SSE replies) and refused on `tools/call`, including inside batches. A refused call never reaches the upstream.
- **Credentials never cross over**: Claude's bearer token is not forwarded; the gateway can add its own headers per upstream (`headers`).
- **Audit log** (`audit.log` in `dataDir`): one JSON line per call with the upstream, account and tool names. Never arguments or results.
- **Config refuses** upstreams that aren't loopback or tailnet addresses, so it can't be turned into an open proxy. Rate limit: 240 calls a minute per account, plus the SDK's limits on the OAuth endpoints.

## Credentials entered at connect time

An upstream can ask for its own credentials (see `anylist` in `config.example.json`). After Google sign-in the gateway shows a form; the values never go through claude.ai or Anthropic. They are stored AES-256-GCM encrypted (key in `secret.key` in the data directory, mode 600), tied to that connector's tokens, sent to the upstream only on loopback in `x-upstream-credentials`, never logged, and deleted when the connector is disconnected (token revocation) or if the tokens expire. `deploy/anylist-http.mjs` is an example upstream that builds a per-user AnyList client from that header (`ANYLIST_MCP_DIR` points at a checkout of the AnyList MCP project). For a single user, it can instead read the login from a local file (`ANYLIST_CREDENTIALS_FILE`, mode 600); then leave `credentials` off that upstream.

## Set up

1. Google Cloud console → APIs & Services → Credentials → Create OAuth client ID, type **Web application**. Authorized redirect URI: `https://HOST/google/callback`. Consent screen: external, in "testing" mode with your own account as the only test user. Scopes: `openid`, `email`.
2. `cp config.example.json ~/.config/mcp-gateway/config.json`, fill in the client ID and secret and `allowedEmails`, then `chmod 600` it. It holds the Google secret and stays out of git.
3. `npm ci && npm run build && npm test`
4. `mkdir -p ~/.local/share/mcp-gateway && cp deploy/mcp-gateway.service ~/.config/systemd/user/ && systemctl --user enable --now mcp-gateway`
5. Publish **only after the tests pass and the config is in place**: `sudo tailscale funnel --bg --https=443 http://127.0.0.1:8092`. Check with `tailscale funnel status`. Turn off with `sudo tailscale funnel --https=443 off`.
6. claude.ai → Settings → Connectors → Add custom connector → `https://HOST/life-timeline/mcp`. Sign in with Google once.

Add another MCP: add an entry under `upstreams`, restart the service, add its URL as a new connector. Never put a shell or filesystem MCP behind it.

## Tests

`npm test` runs the whole flow against a fake Google and a fake upstream: discovery, locked registration, PKCE, single-use codes, rotation, audience binding, allowlist refusal, tool filtering (JSON and SSE), batch refusal, and that no Claude credential or tool argument leaks upstream or into the log.

Requires Node 22.13+ (`node:sqlite`).
