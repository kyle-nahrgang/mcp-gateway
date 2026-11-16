import type { Request, Response } from "express";
import type { OAuthServerProvider, AuthorizationParams } from "@modelcontextprotocol/sdk/server/auth/provider.js";
import type { OAuthRegisteredClientsStore } from "@modelcontextprotocol/sdk/server/auth/clients.js";
import type { OAuthClientInformationFull, OAuthTokens } from "@modelcontextprotocol/sdk/shared/auth.js";
import type { AuthInfo } from "@modelcontextprotocol/sdk/server/auth/types.js";
import { InvalidClientMetadataError, InvalidGrantError, InvalidTargetError, InvalidTokenError } from "@modelcontextprotocol/sdk/server/auth/errors.js";
import type { Config } from "./config.js";
import { Store, randomToken, type Pending } from "./store.js";

const nowSec = () => Math.floor(Date.now() / 1000);
const GOOGLE_AUTH = "https://accounts.google.com/o/oauth2/v2/auth";
const GOOGLE_TOKEN = "https://oauth2.googleapis.com/token";

export class GatewayProvider implements OAuthServerProvider {
  constructor(private cfg: Config, public store: Store, private audit: (e: Record<string, unknown>) => void) {}

  /** Resource URL for an upstream: this is also the connector URL entered in claude.ai. */
  resourceUrl(name: string) { return `${this.cfg.publicUrl}/${name}/mcp`; }
  private knownResources() { return new Set(Object.keys(this.cfg.upstreams).map((n) => this.resourceUrl(n))); }

  get clientsStore(): OAuthRegisteredClientsStore {
    return {
      getClient: (id) => this.store.getClient(id),
      registerClient: (c) => {
        const client = c as OAuthClientInformationFull; // the SDK handler assigns client_id before calling
        const uris = (client.redirect_uris ?? []).map(String);
        if (!uris.length || !uris.every((u) => this.cfg.allowedRedirectUris.includes(u))) {
          this.audit({ event: "register_refused", redirect_uris: uris });
          throw new InvalidClientMetadataError("redirect_uris must be Claude's callback URL");
        }
        this.store.putClient(client.client_id, client);
        this.audit({ event: "register", client_id: client.client_id, name: client.client_name });
        return client;
      },
    };
  }

  /** Step 1: Claude sent the user here. Send them to Google; the rest happens in handleGoogleCallback. */
  async authorize(client: OAuthClientInformationFull, params: AuthorizationParams, res: Response): Promise<void> {
    const resource = params.resource?.href;
    if (!resource || !this.knownResources().has(resource)) throw new InvalidTargetError("resource must be one of this gateway's MCP endpoints");
    const id = randomToken(24), nonce = randomToken(16);
    this.store.putPending({ id, clientId: client.client_id, redirectUri: params.redirectUri, codeChallenge: params.codeChallenge, state: params.state, scopes: params.scopes ?? [], resource, nonce, expiresAt: nowSec() + 600 });
    const u = new URL(this.cfg.google.authUrl ?? GOOGLE_AUTH);
    u.search = new URLSearchParams({ client_id: this.cfg.google.clientId, redirect_uri: `${this.cfg.publicUrl}/google/callback`, response_type: "code", scope: "openid email", state: id, nonce, prompt: "select_account" }).toString();
    res.redirect(u.href);
  }

  /** Step 2: Google sent the user back. Check who they are, then hand Claude an authorization code. */
  handleGoogleCallback = async (req: Request, res: Response) => {
    const fail = (status: number, msg: string, why: Record<string, unknown> = {}) => { this.audit({ event: "login_refused", reason: msg, ...why }); res.status(status).type("text/plain").send(msg); };
    const { code, state, error } = req.query as Record<string, string | undefined>;
    if (!state) return fail(400, "Missing state");
    const pending = this.store.takePending(state);
    if (!pending) return fail(400, "Sign-in expired. Start again from Claude.");
    const back = (params: Record<string, string>) => { const u = new URL(pending.redirectUri); for (const [k, v] of Object.entries(params)) u.searchParams.set(k, v); if (pending.state) u.searchParams.set("state", pending.state); res.redirect(u.href); };
    if (error || !code) return back({ error: "access_denied" });
    let idToken: Record<string, unknown>;
    try {
      const r = await fetch(this.cfg.google.tokenUrl ?? GOOGLE_TOKEN, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ code, client_id: this.cfg.google.clientId, client_secret: this.cfg.google.clientSecret, redirect_uri: `${this.cfg.publicUrl}/google/callback`, grant_type: "authorization_code" }) });
      const j = (await r.json()) as { id_token?: string };
      if (!r.ok || !j.id_token) throw new Error("no id_token");
      // The id_token came straight from Google's token endpoint over TLS, so its signature need not be re-checked (OIDC Core 3.1.3.7).
      idToken = JSON.parse(Buffer.from(j.id_token.split(".")[1], "base64url").toString());
    } catch { return fail(502, "Could not verify the Google sign-in"); }
    const email = String(idToken.email ?? "").toLowerCase();
    const okIss = idToken.iss === "https://accounts.google.com" || idToken.iss === "accounts.google.com";
    if (!okIss || idToken.aud !== this.cfg.google.clientId || idToken.nonce !== pending.nonce || Number(idToken.exp) < nowSec() || idToken.email_verified !== true) return fail(403, "Sign-in could not be verified", { email });
    if (!this.cfg.allowedEmails.includes(email)) return fail(403, "This account is not allowed", { email });
    const up = this.upstreamFor(pending.resource);
    if (up?.credentials) { // second step: ask for the upstream's own credentials
      const id = randomToken(24);
      this.store.putPending({ ...pending, id, email, expiresAt: nowSec() + 600 });
      return void this.page(res, formHtml(id, up.title ?? "this service", up.credentials));
    }
    this.finish(res, pending, email);
  };

  private upstreamFor(resource: string) {
    for (const [n, u] of Object.entries(this.cfg.upstreams)) if (this.resourceUrl(n) === resource) return u;
  }
  private page(res: Response, html: string, status = 200) {
    res.status(status).set({ "cache-control": "no-store", "content-security-policy": "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'", "referrer-policy": "no-referrer", "x-content-type-options": "nosniff" }).type("html").send(html);
  }
  private finish(res: Response, pending: Pending, email: string, credId?: string) {
    const authCode = randomToken(32);
    this.store.putCode(authCode, { clientId: pending.clientId, redirectUri: pending.redirectUri, codeChallenge: pending.codeChallenge, scopes: pending.scopes, resource: pending.resource, email, expiresAt: nowSec() + 300, credId });
    this.audit({ event: "login", email, client_id: pending.clientId, resource: pending.resource, credentials: Boolean(credId) });
    const u = new URL(pending.redirectUri); u.searchParams.set("code", authCode); if (pending.state) u.searchParams.set("state", pending.state);
    res.redirect(u.href);
  }

  /** POST from the credentials form. The id is a one-time secret handed out only after the Google check. */
  handleCredentials = (req: Request, res: Response) => {
    const body = (req.body ?? {}) as Record<string, string>;
    const pending = this.store.takePending(String(body.id ?? ""));
    const up = pending && this.upstreamFor(pending.resource);
    if (!pending || !pending.email || !up?.credentials) { this.audit({ event: "credentials_refused" }); return this.page(res, msgHtml("This sign-in expired. Start again from Claude."), 400); }
    const values: Record<string, string> = {};
    for (const f of up.credentials.fields) { const v = String(body[f.name] ?? "").trim(); if (!v || v.length > 512) { this.store.putPending({ ...pending, expiresAt: nowSec() + 600 }); return this.page(res, formHtml(pending.id, up.title ?? "this service", up.credentials, `Please fill in ${f.label}.`), 400); } values[f.name] = v; }
    const credId = randomToken(16);
    this.store.putSecret(credId, JSON.stringify(values));
    this.finish(res, pending, pending.email, credId);
  };

  async challengeForAuthorizationCode(_client: OAuthClientInformationFull, code: string): Promise<string> {
    const c = this.store.peekCode(code);
    if (!c) throw new InvalidGrantError("invalid or expired code");
    return c.codeChallenge;
  }

  private issue(clientId: string, scopes: string[], resource: string, email: string, credId?: string): OAuthTokens {
    const access = randomToken(32), refresh = randomToken(32);
    this.store.putToken(access, { kind: "access", clientId, scopes, resource, email, credId, expiresAt: nowSec() + this.cfg.accessTokenTtlSec });
    this.store.putToken(refresh, { kind: "refresh", clientId, scopes, resource, email, credId, expiresAt: nowSec() + this.cfg.refreshTokenTtlSec });
    return { access_token: access, token_type: "Bearer", expires_in: this.cfg.accessTokenTtlSec, refresh_token: refresh, scope: scopes.join(" ") };
  }

  async exchangeAuthorizationCode(client: OAuthClientInformationFull, code: string, _verifier?: string, redirectUri?: string, resource?: URL): Promise<OAuthTokens> {
    const c = this.store.takeCode(code);
    if (!c || c.clientId !== client.client_id) throw new InvalidGrantError("invalid or expired code");
    if (redirectUri && redirectUri !== c.redirectUri) throw new InvalidGrantError("redirect_uri mismatch");
    if (resource && resource.href !== c.resource) throw new InvalidTargetError("resource mismatch");
    return this.issue(client.client_id, c.scopes, c.resource, c.email, c.credId);
  }

  async exchangeRefreshToken(client: OAuthClientInformationFull, refreshToken: string, scopes?: string[], resource?: URL): Promise<OAuthTokens> {
    const t = this.store.getToken(refreshToken, "refresh");
    if (!t || t.clientId !== client.client_id) throw new InvalidGrantError("invalid or expired refresh token");
    if (resource && resource.href !== t.resource) throw new InvalidTargetError("resource mismatch");
    this.store.deleteToken(refreshToken); // rotate: the old refresh token dies here
    return this.issue(client.client_id, scopes?.length ? scopes.filter((s) => t.scopes.includes(s)) : t.scopes, t.resource, t.email, t.credId);
  }

  async verifyAccessToken(token: string): Promise<AuthInfo> {
    const t = this.store.getToken(token, "access");
    if (!t) throw new InvalidTokenError("invalid or expired token");
    return { token, clientId: t.clientId, scopes: t.scopes, expiresAt: t.expiresAt, resource: new URL(t.resource), extra: { email: t.email, credId: t.credId } };
  }

  async revokeToken(_client: OAuthClientInformationFull, req: { token: string }): Promise<void> {
    const t = this.store.findToken(req.token);
    if (t?.credId) this.store.revokeCred(t.credId); else this.store.deleteToken(req.token);
    this.audit({ event: "revoke", credentials: Boolean(t?.credId) });
  }

  credentialsFor(credId: string | undefined): string | undefined { return credId ? this.store.getSecret(credId) : undefined; }
}

const esc = (x: string) => x.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]!);
const STYLE = "body{font:16px system-ui,sans-serif;max-width:26rem;margin:2rem auto;padding:0 1rem}label{display:block;margin:1rem 0 .25rem}input{width:100%;box-sizing:border-box;font:inherit;padding:.6rem}button{margin-top:1.5rem;font:inherit;padding:.7rem 1.2rem}.e{color:#b00020}small{color:#555}";
function msgHtml(m: string) { return `<!doctype html><meta name=viewport content="width=device-width,initial-scale=1"><style>${STYLE}</style><p>${esc(m)}</p>`; }
function formHtml(id: string, service: string, c: NonNullable<import("./config.js").UpstreamConfig["credentials"]>, error?: string) {
  const fields = c.fields.map((f) => `<label for="${esc(f.name)}">${esc(f.label)}</label><input id="${esc(f.name)}" name="${esc(f.name)}" type="${f.secret ? "password" : "text"}" autocomplete="${f.secret ? "current-password" : "username"}" required>`).join("");
  return `<!doctype html><meta name=viewport content="width=device-width,initial-scale=1"><title>${esc(c.title)}</title><style>${STYLE}</style><h1>${esc(c.title)}</h1>${error ? `<p class=e>${esc(error)}</p>` : ""}<p><small>${esc(c.help ?? `Used only to connect ${service} for this connector. Stored encrypted on your own server and deleted when you disconnect.`)}</small></p><form method="post" action="/credentials"><input type="hidden" name="id" value="${esc(id)}">${fields}<button type="submit">Connect</button></form>`;
}
