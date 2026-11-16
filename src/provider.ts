import type { Request, Response } from "express";
import type { OAuthServerProvider, AuthorizationParams } from "@modelcontextprotocol/sdk/server/auth/provider.js";
import type { OAuthRegisteredClientsStore } from "@modelcontextprotocol/sdk/server/auth/clients.js";
import type { OAuthClientInformationFull, OAuthTokens } from "@modelcontextprotocol/sdk/shared/auth.js";
import type { AuthInfo } from "@modelcontextprotocol/sdk/server/auth/types.js";
import { InvalidClientMetadataError, InvalidGrantError, InvalidTargetError, InvalidTokenError } from "@modelcontextprotocol/sdk/server/auth/errors.js";
import type { Config } from "./config.js";
import { Store, randomToken } from "./store.js";

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
    const authCode = randomToken(32);
    this.store.putCode(authCode, { clientId: pending.clientId, redirectUri: pending.redirectUri, codeChallenge: pending.codeChallenge, scopes: pending.scopes, resource: pending.resource, email, expiresAt: nowSec() + 300 });
    this.audit({ event: "login", email, client_id: pending.clientId, resource: pending.resource });
    back({ code: authCode });
  };

  async challengeForAuthorizationCode(_client: OAuthClientInformationFull, code: string): Promise<string> {
    const c = this.store.peekCode(code);
    if (!c) throw new InvalidGrantError("invalid or expired code");
    return c.codeChallenge;
  }

  private issue(clientId: string, scopes: string[], resource: string, email: string): OAuthTokens {
    const access = randomToken(32), refresh = randomToken(32);
    this.store.putToken(access, { kind: "access", clientId, scopes, resource, email, expiresAt: nowSec() + this.cfg.accessTokenTtlSec });
    this.store.putToken(refresh, { kind: "refresh", clientId, scopes, resource, email, expiresAt: nowSec() + this.cfg.refreshTokenTtlSec });
    return { access_token: access, token_type: "Bearer", expires_in: this.cfg.accessTokenTtlSec, refresh_token: refresh, scope: scopes.join(" ") };
  }

  async exchangeAuthorizationCode(client: OAuthClientInformationFull, code: string, _verifier?: string, redirectUri?: string, resource?: URL): Promise<OAuthTokens> {
    const c = this.store.takeCode(code);
    if (!c || c.clientId !== client.client_id) throw new InvalidGrantError("invalid or expired code");
    if (redirectUri && redirectUri !== c.redirectUri) throw new InvalidGrantError("redirect_uri mismatch");
    if (resource && resource.href !== c.resource) throw new InvalidTargetError("resource mismatch");
    return this.issue(client.client_id, c.scopes, c.resource, c.email);
  }

  async exchangeRefreshToken(client: OAuthClientInformationFull, refreshToken: string, scopes?: string[], resource?: URL): Promise<OAuthTokens> {
    const t = this.store.getToken(refreshToken, "refresh");
    if (!t || t.clientId !== client.client_id) throw new InvalidGrantError("invalid or expired refresh token");
    if (resource && resource.href !== t.resource) throw new InvalidTargetError("resource mismatch");
    this.store.deleteToken(refreshToken); // rotate: the old refresh token dies here
    return this.issue(client.client_id, scopes?.length ? scopes.filter((s) => t.scopes.includes(s)) : t.scopes, t.resource, t.email);
  }

  async verifyAccessToken(token: string): Promise<AuthInfo> {
    const t = this.store.getToken(token, "access");
    if (!t) throw new InvalidTokenError("invalid or expired token");
    return { token, clientId: t.clientId, scopes: t.scopes, expiresAt: t.expiresAt, resource: new URL(t.resource), extra: { email: t.email } };
  }

  async revokeToken(_client: OAuthClientInformationFull, req: { token: string }): Promise<void> { this.store.deleteToken(req.token); }
}
