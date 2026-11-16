import { DatabaseSync } from "node:sqlite";
import { createHash, randomBytes } from "node:crypto";
import { mkdirSync } from "node:fs";
import { join } from "node:path";

export const sha256 = (s: string) => createHash("sha256").update(s).digest("hex");
export const randomToken = (bytes = 32) => randomBytes(bytes).toString("base64url");
const now = () => Math.floor(Date.now() / 1000);

export interface Pending { id: string; clientId: string; redirectUri: string; codeChallenge: string; state?: string; scopes: string[]; resource: string; nonce: string; expiresAt: number }
export interface Code { clientId: string; redirectUri: string; codeChallenge: string; scopes: string[]; resource: string; email: string; expiresAt: number }
export interface TokenRow { kind: "access" | "refresh"; clientId: string; scopes: string[]; resource: string; email: string; expiresAt: number }

export class Store {
  db: DatabaseSync;
  constructor(dir: string) {
    mkdirSync(dir, { recursive: true, mode: 0o700 });
    this.db = new DatabaseSync(join(dir, "gateway.db"));
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS clients (id TEXT PRIMARY KEY, json TEXT NOT NULL, created INTEGER NOT NULL);
      CREATE TABLE IF NOT EXISTS pending (id TEXT PRIMARY KEY, json TEXT NOT NULL, expires INTEGER NOT NULL);
      CREATE TABLE IF NOT EXISTS codes (hash TEXT PRIMARY KEY, json TEXT NOT NULL, expires INTEGER NOT NULL);
      CREATE TABLE IF NOT EXISTS tokens (hash TEXT PRIMARY KEY, kind TEXT NOT NULL, client_id TEXT NOT NULL, json TEXT NOT NULL, expires INTEGER NOT NULL);
    `);
  }
  sweep() {
    const t = now();
    for (const tbl of ["pending", "codes", "tokens"]) this.db.prepare(`DELETE FROM ${tbl} WHERE expires < ?`).run(t);
  }
  getClient(id: string) { const r = this.db.prepare("SELECT json FROM clients WHERE id=?").get(id) as { json: string } | undefined; return r ? JSON.parse(r.json) : undefined; }
  putClient(id: string, c: unknown) { this.db.prepare("INSERT OR REPLACE INTO clients VALUES (?,?,?)").run(id, JSON.stringify(c), now()); }
  putPending(p: Pending) { this.db.prepare("INSERT INTO pending VALUES (?,?,?)").run(p.id, JSON.stringify(p), p.expiresAt); }
  takePending(id: string): Pending | undefined {
    const r = this.db.prepare("SELECT json FROM pending WHERE id=? AND expires>=?").get(id, now()) as { json: string } | undefined;
    this.db.prepare("DELETE FROM pending WHERE id=?").run(id);
    return r ? JSON.parse(r.json) : undefined;
  }
  putCode(code: string, c: Code) { this.db.prepare("INSERT INTO codes VALUES (?,?,?)").run(sha256(code), JSON.stringify(c), c.expiresAt); }
  peekCode(code: string): Code | undefined {
    const r = this.db.prepare("SELECT json FROM codes WHERE hash=? AND expires>=?").get(sha256(code), now()) as { json: string } | undefined;
    return r ? JSON.parse(r.json) : undefined;
  }
  takeCode(code: string): Code | undefined { const c = this.peekCode(code); this.db.prepare("DELETE FROM codes WHERE hash=?").run(sha256(code)); return c; }
  putToken(token: string, t: TokenRow) { this.db.prepare("INSERT INTO tokens VALUES (?,?,?,?,?)").run(sha256(token), t.kind, t.clientId, JSON.stringify(t), t.expiresAt); }
  getToken(token: string, kind: TokenRow["kind"]): TokenRow | undefined {
    const r = this.db.prepare("SELECT json FROM tokens WHERE hash=? AND kind=? AND expires>=?").get(sha256(token), kind, now()) as { json: string } | undefined;
    return r ? JSON.parse(r.json) : undefined;
  }
  deleteToken(token: string) { this.db.prepare("DELETE FROM tokens WHERE hash=?").run(sha256(token)); }
  revokeClient(clientId: string) { this.db.prepare("DELETE FROM tokens WHERE client_id=?").run(clientId); }
}
