import { randomBytes, createHash } from 'node:crypto';

export type ErrorCode = 'invalid_options' | 'connection_failed' | 'registration_rejected' | 'protocol_violation' | 'canceled';
/** Static messages only: transport/relay errors and AbortSignal reasons are never exposed. */
export class TunnelError extends Error {
  constructor(readonly code: ErrorCode) {
    super(`tunn: ${code.replaceAll('_', ' ')}`);
    this.name = 'TunnelError';
  }
}
export interface Credentials {
  authToken?: string;
  tunnelKey?: string;
  /** Existing endpoint token; only SHA-256 is sent to the relay. */
  endpointToken?: string;
}
export interface ReconnectPolicy {
  /** Five retries by default. An explicit zero disables retries. */
  maxAttempts: number;
  initialDelayMs?: number;
  maxDelayMs?: number;
}
export interface Options {
  origin: string;
  name?: string;
  serverAddr?: string;
  credentials?: Credentials;
  public?: boolean;
  allowedEmails?: readonly string[];
  /** Lifetime cancellation, including connection, requests and retry waits. */
  signal?: AbortSignal;
  /** PEM certificate authorities, separate for relay and HTTPS origin. Verification is always enabled. */
  relayCA?: string | Buffer;
  originCA?: string | Buffer;
  connectTimeoutMs?: number;
  httpTimeoutMs?: number;
  reconnect?: ReconnectPolicy;
  requireUpstreamAuth?: boolean;
  maxConnections?: number;
  /** Limit for legacy buffered HTTP requests/responses; default 8 MiB, maximum 100 MiB. */
  maxBufferedBytes?: number;
}
export type HandlerOptions = Omit<Options, 'origin'> & { origin?: never };

export interface Config {
  origin: URL;
  name: string;
  serverAddr: string;
  authToken: string;
  tunnelKey: string;
  endpointToken: string;
  endpointDigest: Buffer;
  public: boolean;
  allowedEmails: string[];
  requireSharing: boolean;
  signal?: AbortSignal;
  relayCA?: string | Buffer;
  originCA?: string | Buffer;
  connectTimeoutMs: number;
  httpTimeoutMs: number;
  reconnect: Required<ReconnectPolicy>;
  requireUpstreamAuth: boolean;
  maxConnections: number;
  maxBufferedBytes: number;
}
const invalid = (): never => { throw new TunnelError('invalid_options'); };
function integer(value: unknown, fallback: number, min: number, max = 2_147_483_647): number {
  if (value === undefined) return fallback;
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < min || value > max) return invalid();
  return value;
}
function string(value: unknown): string {
  if (value === undefined) return '';
  if (typeof value !== 'string') return invalid();
  return value;
}
function ca(value: unknown): string | Buffer | undefined {
  if (value === undefined || typeof value === 'string') return value;
  if (Buffer.isBuffer(value)) return Buffer.from(value);
  return invalid();
}
export function configure(options: Options): Config {
  if (!options || typeof options !== 'object') return invalid();
  let origin: URL;
  try { origin = new URL(options.origin); } catch { return invalid(); }
  if (!/^https?:\/\/[^/?#]+\/?$/.test(options.origin) || !origin.hostname || origin.username || origin.password) return invalid();
  const serverAddr = options.serverAddr ?? 'tunn.to:443';
  if (typeof serverAddr !== 'string') return invalid();
  const match = /^(\[[0-9a-fA-F:]+\]|[^:/@?#\s]+):([0-9]+)$/.exec(serverAddr);
  if (!match || Number(match[2]) < 1 || Number(match[2]) > 65535) return invalid();
  const name = options.name ?? randomBytes(6).toString('hex');
  if (typeof name !== 'string' || name.length > 63 || !/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(name)) return invalid();
  const credentials = options.credentials ?? {};
  if (!credentials || typeof credentials !== 'object') return invalid();
  const authToken = string(credentials.authToken), tunnelKey = string(credentials.tunnelKey), endpointToken = string(credentials.endpointToken);
  if (endpointToken && !endpointToken.startsWith('tunn_ep_')) return invalid();
  if (options.public !== undefined && typeof options.public !== 'boolean') return invalid();
  if (options.requireUpstreamAuth !== undefined && typeof options.requireUpstreamAuth !== 'boolean') return invalid();
  if (options.allowedEmails !== undefined && (!Array.isArray(options.allowedEmails) || options.allowedEmails.some(e => typeof e !== 'string' || !e.trim()))) return invalid();
  const allowedEmails = [...(options.allowedEmails ?? [])];
  if (options.public && (allowedEmails.length || endpointToken)) return invalid();
  if (options.signal !== undefined && !(options.signal instanceof AbortSignal)) return invalid();
  if (options.signal?.aborted) throw new TunnelError('canceled');
  const retry = options.reconnect;
  if (retry !== undefined && (!retry || typeof retry !== 'object')) return invalid();
  const reconnect = {
    maxAttempts: integer(retry?.maxAttempts, 5, 0),
    initialDelayMs: integer(retry?.initialDelayMs, 1000, 1),
    maxDelayMs: integer(retry?.maxDelayMs, 30_000, 1),
  };
  if (reconnect.initialDelayMs > reconnect.maxDelayMs) return invalid();
  return {
    origin, name, serverAddr, authToken, tunnelKey, endpointToken,
    endpointDigest: endpointToken ? createHash('sha256').update(endpointToken).digest() : Buffer.alloc(0),
    public: options.public ?? false, allowedEmails,
    requireSharing: !!options.public || (!allowedEmails.length && !endpointToken),
    signal: options.signal, relayCA: ca(options.relayCA), originCA: ca(options.originCA),
    connectTimeoutMs: integer(options.connectTimeoutMs, 10_000, 1),
    httpTimeoutMs: integer(options.httpTimeoutMs, 30_000, 1), reconnect,
    requireUpstreamAuth: options.requireUpstreamAuth ?? false,
    maxConnections: integer(options.maxConnections, 100, 1, 100),
    maxBufferedBytes: integer(options.maxBufferedBytes, 8 * 1024 * 1024, 1, 100 * 1024 * 1024),
  };
}
