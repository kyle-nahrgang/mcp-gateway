import { DatabaseSync } from "node:sqlite";
import { createHash, randomBytes, createCipheriv, createDecipheriv } from "node:crypto";
import { mkdirSync, existsSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

export const sha256 = (s: string) => createHash("sha256").update(s).digest("hex");
export const randomToken = (bytes = 32) => randomBytes(bytes).toString("base64url");
const now = () => Math.floor(Date.now() / 1000);

export interface Pending { id: string; clientId: string; redirectUri: string; codeChallenge: string; state?: string; scopes: string[]; resource: string; nonce: string; expiresAt: number; email?: string }
export interface Code { clientId: string; redirectUri: string; codeChallenge: string; scopes: string[]; resource: string; email: string; expiresAt: number; credId?: string }
export interface TokenRow { kind: "access" | "refresh"; clientId: string; scopes: string[]; resource: string; email: string; expiresAt: number; credId?: string }

export class Store {
  db: DatabaseSync;
  private key: Buffer;
  constructor(dir: string) {
    mkdirSync(dir, { recursive: true, mode: 0o700 });
    this.db = new DatabaseSync(join(dir, "gateway.db"));
    const keyPath = join(dir, "secret.key");
    if (!existsSync(keyPath)) writeFileSync(keyPath, randomBytes(32), { mode: 0o600 });
    this.key = readFileSync(keyPath);
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS clients (id TEXT PRIMARY KEY, json TEXT NOT NULL, created INTEGER NOT NULL);
      CREATE TABLE IF NOT EXISTS pending (id TEXT PRIMARY KEY, json TEXT NOT NULL, expires INTEGER NOT NULL);
      CREATE TABLE IF NOT EXISTS codes (hash TEXT PRIMARY KEY, json TEXT NOT NULL, expires INTEGER NOT NULL);
      CREATE TABLE IF NOT EXISTS secrets (id TEXT PRIMARY KEY, blob TEXT NOT NULL, created INTEGER NOT NULL);
      CREATE TABLE IF NOT EXISTS tokens (hash TEXT PRIMARY KEY, kind TEXT NOT NULL, client_id TEXT NOT NULL, json TEXT NOT NULL, expires INTEGER NOT NULL);
    `);
  }
  sweep() {
    const t = now();
    for (const tbl of ["pending", "codes", "tokens"]) this.db.prepare(`DELETE FROM ${tbl} WHERE expires < ?`).run(t);
    // credentials nobody's tokens refer to any more (grace period covers the gap between the form and the token exchange)
    this.db.prepare("DELETE FROM secrets WHERE created < ? AND NOT EXISTS (SELECT 1 FROM tokens WHERE json_extract(tokens.json,'$.credId') = secrets.id) AND NOT EXISTS (SELECT 1 FROM codes WHERE json_extract(codes.json,'$.credId') = secrets.id)").run(t - 900);
  }
  /** AES-256-GCM with the key file in the data directory. */
  seal(plain: string): string {
    const iv = randomBytes(12), c = createCipheriv("aes-256-gcm", this.key, iv);
    const enc = Buffer.concat([c.update(plain, "utf8"), c.final()]);
    return Buffer.concat([iv, c.getAuthTag(), enc]).toString("base64");
  }
  open(blob: string): string {
    const b = Buffer.from(blob, "base64"), d = createDecipheriv("aes-256-gcm", this.key, b.subarray(0, 12));
    d.setAuthTag(b.subarray(12, 28));
    return Buffer.concat([d.update(b.subarray(28)), d.final()]).toString("utf8");
  }
  putSecret(id: string, plain: string) { this.db.prepare("INSERT INTO secrets VALUES (?,?,?)").run(id, this.seal(plain), now()); }
  getSecret(id: string): string | undefined {
    const r = this.db.prepare("SELECT blob FROM secrets WHERE id=?").get(id) as { blob: string } | undefined;
    try { return r ? this.open(r.blob) : undefined; } catch { return undefined; }
  }
  /** Disconnect: remove the credentials and every token that could use them. */
  revokeCred(credId: string) {
    this.db.prepare("DELETE FROM tokens WHERE json_extract(json,'$.credId') = ?").run(credId);
    this.db.prepare("DELETE FROM secrets WHERE id=?").run(credId);
  }
  findToken(token: string): TokenRow | undefined {
    const r = this.db.prepare("SELECT json FROM tokens WHERE hash=?").get(sha256(token)) as { json: string } | undefined;
    return r ? JSON.parse(r.json) : undefined;
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
