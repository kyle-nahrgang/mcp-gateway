import { readFileSync } from "node:fs";

export interface ToolPolicy {
  /** If set, only these tools are visible and callable. A trailing * matches a prefix. */
  allow?: string[];
  /** These tools are hidden and blocked. A trailing * matches a prefix. Deny wins over allow. */
  deny?: string[];
}

export interface UpstreamConfig {
  /** Local MCP endpoint, e.g. http://127.0.0.1:8091/mcp?agent=claude-cloud. Must be loopback or tailnet. */
  url: string;
  tools?: ToolPolicy;
  /** Extra headers sent to the upstream (for example its own bearer token). Never sent to Claude. */
  headers?: Record<string, string>;
  title?: string;
}

export interface Config {
  /** Public origin, no trailing slash, e.g. https://your-host.your-tailnet.ts.net */
  publicUrl: string;
  port: number;
  host: string;
  dataDir: string;
  google: { clientId: string; clientSecret: string; authUrl?: string; tokenUrl?: string };
  /** Only these Google accounts can sign in. Lowercase. Kept in config.json, never in git. */
  allowedEmails: string[];
  allowedRedirectUris: string[];
  accessTokenTtlSec: number;
  refreshTokenTtlSec: number;
  upstreams: Record<string, UpstreamConfig>;
}

export const DEFAULT_REDIRECTS = ["https://claude.ai/api/mcp/auth_callback"];

const NAME = /^[a-z0-9][a-z0-9-]{0,30}$/;

export function parseConfig(raw: unknown): Config {
  const c = raw as Partial<Config>;
  const fail = (m: string): never => { throw new Error(`config: ${m}`); };
  if (!c.publicUrl || !/^https?:\/\//.test(c.publicUrl) || c.publicUrl.endsWith("/")) fail("publicUrl must be an origin without trailing slash");
  if (!c.google?.clientId || !c.google?.clientSecret) fail("google.clientId and google.clientSecret are required");
  if (!c.allowedEmails?.length) fail("allowedEmails must list at least one account");
  if (!c.dataDir) fail("dataDir is required");
  const upstreams = c.upstreams ?? {};
  if (!Object.keys(upstreams).length) fail("at least one upstream is required");
  for (const [name, u] of Object.entries(upstreams)) {
    if (!NAME.test(name)) fail(`upstream name '${name}' must be lowercase letters, digits and dashes`);
    const url = new URL(u.url);
    if (!isLocalHost(url.hostname)) fail(`upstream '${name}' must be a loopback or tailnet address, not ${url.hostname}`);
  }
  return {
    publicUrl: c.publicUrl!,
    port: c.port ?? 8092,
    host: c.host ?? "127.0.0.1",
    dataDir: c.dataDir!,
    google: c.google as Config["google"],
    allowedEmails: c.allowedEmails!.map((e) => e.toLowerCase()),
    allowedRedirectUris: c.allowedRedirectUris ?? DEFAULT_REDIRECTS,
    accessTokenTtlSec: c.accessTokenTtlSec ?? 3600,
    refreshTokenTtlSec: c.refreshTokenTtlSec ?? 60 * 60 * 24 * 30,
    upstreams,
  };
}

export function isLocalHost(h: string): boolean {
  return h === "localhost" || h === "::1" || h === "[::1]" || /^127\./.test(h) || /^100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\./.test(h) || h.endsWith(".ts.net");
}

export function loadConfig(path: string): Config {
  return parseConfig(JSON.parse(readFileSync(path, "utf8")));
}

export function toolAllowed(policy: ToolPolicy | undefined, tool: string): boolean {
  const match = (list: string[]) => list.some((p) => (p.endsWith("*") ? tool.startsWith(p.slice(0, -1)) : p === tool));
  if (policy?.deny && match(policy.deny)) return false;
  if (policy?.allow && !match(policy.allow)) return false;
  return true;
}
