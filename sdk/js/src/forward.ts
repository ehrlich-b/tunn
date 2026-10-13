import * as http from 'node:http';
import * as https from 'node:https';
import { Config } from './options.js';
import { Message } from './protocol.js';

const chunkSize = 32 * 1024;
const inputQueueLimit = 16 * chunkSize;
interface Field { name: string; value: string }
interface Connection {
  id: string;
  buffered: boolean;
  request: http.ClientRequest;
  response?: http.IncomingMessage;
  timer: NodeJS.Timeout;
  length: number;
  received: number;
  inputEnded: boolean;
  accepted: boolean;
  terminal: boolean;
  completion: Promise<void>;
  inputDone: Promise<void>;
  resolveInput: () => void;
}
const token = /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/;
const forbiddenTrailer = new Set(('authorization cache-control connection content-encoding content-length content-range content-type expect host keep-alive max-forwards pragma proxy-authenticate proxy-authorization proxy-connection range realm te trailer transfer-encoding www-authenticate').split(' '));
function fields(raw: string[]): Field[] {
  const result: Field[] = [];
  for (let i = 0; i < raw.length; i += 2) result.push({ name: raw[i], value: raw[i + 1] });
  return result;
}
function encode(raw: string[]): { headers: Record<string, string>; headerFields: Field[] } {
  const headerFields = fields(raw), headers: Record<string, string> = Object.create(null);
  for (const { name, value } of headerFields) {
    const key = name.toLowerCase();
    headers[key] = headers[key] === undefined ? value : headers[key] + ', ' + value;
  }
  return { headers, headerFields };
}
function validateTrailers(names: string[], trailers: Field[]): void {
  if (names.length > 64 || trailers.length > 64) throw new Error('invalid trailers');
  const declared = new Set<string>();
  let bytes = 0;
  for (const name of names) {
    const key = name.toLowerCase();
    if (!token.test(name) || key.startsWith('if-') || forbiddenTrailer.has(key) || declared.has(key)) throw new Error('invalid trailers');
    declared.add(key); bytes += Buffer.byteLength(name);
  }
  for (const field of trailers) {
    if (!declared.has(field.name.toLowerCase()) || /[\x00-\x08\x0a-\x1f\x7f]/.test(field.value)) throw new Error('invalid trailers');
    bytes += Buffer.byteLength(field.name) + Buffer.byteLength(field.value);
  }
  if (bytes > 16 * 1024) throw new Error('invalid trailers');
}

/** Each session owns its workers; a replaced session cannot send into a new one. */
export class Forwarder {
  #active = new Map<string, Connection>();
  #jobs = new Set<Promise<void>>();
  #closed = false;
  constructor(private config: Config, private trailers: boolean, private send: (message: Message) => Promise<void>) {}

  message(message: Message): void {
    switch (message.message) {
      case 'httpRequest': this.open(message.httpRequest.connectionId, message.httpRequest, true); break;
      case 'connectionOpen': {
        const open = message.connectionOpen;
        if (open.protocol !== 'http' || !open.httpRequest) { this.reject(open.connectionId); break; }
        this.open(open.connectionId, open.httpRequest, false); break;
      }
      case 'connectionData': {
        const { connectionId, data } = message.connectionData;
        const c = this.#active.get(connectionId);
        if (!c) break;
        if (c.inputEnded || data.length > chunkSize || c.request.writableLength + data.length > inputQueueLimit || (c.length >= 0 && c.received + data.length > c.length)) {
          this.fail(c); break;
        }
        c.received += data.length;
        c.request.write(data); break;
      }
      case 'connectionHalfClose': {
        const c = this.#active.get(message.connectionHalfClose.connectionId);
        if (!c) break;
        if (c.inputEnded || message.connectionHalfClose.trailers?.length || (c.length >= 0 && c.received !== c.length)) { this.fail(c); break; }
        c.inputEnded = true; c.request.end(); c.resolveInput(); break;
      }
      case 'connectionClose':
      case 'streamClosed': {
        const close = message.connectionClose ?? message.streamClosed;
        const c = this.#active.get(close.connectionId);
        if (c) this.fail(c, false);
      }
    }
  }
  async close(): Promise<void> {
    this.#closed = true;
    for (const c of this.#active.values()) this.fail(c, false);
    await Promise.allSettled([...this.#jobs]);
  }
  private dispatch(message: Message): void { void this.send(message).catch(() => {}); }
  private reject(id: string): void {
    this.dispatch({ connectionAccept: { connectionId: id, success: false, errorMessage: 'local request rejected' } });
  }
  private fail(c: Connection, notify = true): void {
    if (c.terminal) return;
    c.terminal = true;
    c.resolveInput();
    if (notify && !this.#closed) {
      if (c.buffered) this.dispatch({ httpResponse: { connectionId: c.id, statusCode: 502, body: Buffer.from('Local request failed') } });
      else if (c.accepted) this.dispatch({ connectionClose: { connectionId: c.id, errorMessage: 'local request failed' } });
      else this.reject(c.id);
    }
    clearTimeout(c.timer);
    c.response?.destroy();
    c.request.destroy(new Error('local request failed'));
  }
  private open(id: string, head: Message, buffered: boolean): void {
    if (this.#closed) return;
    if (typeof id !== 'string' || !id || this.#active.has(id) || this.#active.size >= this.config.maxConnections) {
      if (buffered) this.dispatch({ httpResponse: { connectionId: id, statusCode: 503 } }); else this.reject(id);
      return;
    }
    const headers: Record<string, string> = Object.create(null);
    for (const [key, value] of Object.entries(head.headers ?? {})) headers[key.toLowerCase()] = String(value);
    // Publisher credentials are never added to application requests.
    delete headers['tunn-authorization'];
    if (this.config.requireUpstreamAuth && !headers.authorization?.trim()) {
      const metadata = { statusCode: 401, headers: { 'www-authenticate': 'Bearer realm="upstream"' } };
      if (buffered) this.dispatch({ httpResponse: { connectionId: id, ...metadata } });
      else {
        this.dispatch({ connectionAccept: { connectionId: id, success: true, httpResponse: metadata } });
        this.dispatch({ connectionHalfClose: { connectionId: id } });
      }
      return;
    }
    const length = buffered ? (head.body?.length ?? 0) : head.contentLength;
    if (typeof head.path !== 'string' || !head.path.startsWith('/') || /[\x00-\x20\x7f#]/.test(head.path) || !token.test(head.method ?? '') || !Number.isSafeInteger(length) || length < -1 || (buffered && length > this.config.maxBufferedBytes)) {
      if (buffered) this.dispatch({ httpResponse: { connectionId: id, statusCode: 502 } }); else this.reject(id);
      return;
    }
    delete headers['transfer-encoding']; delete headers['content-length']; delete headers.connection; delete headers.upgrade;
    if (length >= 0) headers['content-length'] = String(length);
    let request: http.ClientRequest;
    try {
      request = (this.config.origin.protocol === 'https:' ? https : http).request({
        protocol: this.config.origin.protocol, hostname: this.config.origin.hostname.replace(/^\[|\]$/g, ''),
        port: this.config.origin.port || undefined, path: head.path, method: head.method, headers,
        agent: false, ca: this.config.originCA, rejectUnauthorized: true,
      });
    } catch {
      if (buffered) this.dispatch({ httpResponse: { connectionId: id, statusCode: 502 } }); else this.reject(id);
      return;
    }
    let resolveInput!: () => void;
    const inputDone = new Promise<void>(resolve => { resolveInput = resolve; });
    const c: Connection = {
      id, request, buffered, length, received: 0, inputEnded: buffered,
      timer: setTimeout(() => this.fail(c), this.config.httpTimeoutMs),
      terminal: false, accepted: false, completion: Promise.resolve(),
      inputDone, resolveInput,
    };
    this.#active.set(id, c);
    const response = new Promise<http.IncomingMessage>((resolve, reject) => {
      request.once('response', resolve);
      request.on('error', () => { reject(new Error('local request failed')); if (c.response) this.fail(c); });
      // Upgrade tunnels use a separate adapter; ordinary HTTP cannot enter it.
      request.once('upgrade', (_response, socket) => { socket.destroy(); reject(new Error('unsupported upgrade')); });
    });
    c.completion = this.respond(c, head.method, response).catch(() => this.fail(c)).finally(() => {
      clearTimeout(c.timer);
      c.response?.destroy(); request.destroy();
      if (this.#active.get(id) === c) this.#active.delete(id);
      this.#jobs.delete(c.completion);
    });
    this.#jobs.add(c.completion);
    request.flushHeaders();
    if (buffered) { request.end(head.body); resolveInput(); } // Streaming input ends only on a half-close, even for length zero.
  }
  private async respond(c: Connection, method: string, promise: Promise<http.IncomingMessage>): Promise<void> {
    const response = await promise;
    c.response = response;
    if (c.terminal) return;
    if (!c.buffered) clearTimeout(c.timer); // SSE body lifetime belongs to the publisher, not the header timeout.
    const statusCode = response.statusCode ?? 502;
    const hasBody = method !== 'HEAD' && statusCode !== 204 && statusCode !== 304;
    const trailerNames = hasBody && response.headers.trailer ? response.headers.trailer.split(',').map(s => s.trim()) : [];
    validateTrailers(trailerNames, []);
    if (trailerNames.length && !this.trailers) throw new Error('unsupported trailers');
    const metadata = { statusCode, ...encode(response.rawHeaders), trailerNames };
    const chunks: Buffer[] = [];
    let count = 0;
    if (!c.buffered) {
      c.accepted = true;
      await this.send({ connectionAccept: { connectionId: c.id, success: true, httpResponse: metadata } });
    }
    if (hasBody) {
      for await (const chunk of response) {
        if (c.terminal) return;
        const data = Buffer.from(chunk);
        count += data.length;
        if (c.buffered) {
          if (count > this.config.maxBufferedBytes) throw new Error('response limit');
          chunks.push(data);
        } else {
          for (let offset = 0; offset < data.length; offset += chunkSize) {
            if (c.terminal) return;
            await this.send({ connectionData: { connectionId: c.id, data: data.subarray(offset, offset + chunkSize) } });
          }
        }
      }
      if (!response.complete) throw new Error('response interrupted');
      const declaredLength = response.headers['content-length'];
      if (declaredLength !== undefined && Number(declaredLength) !== count) throw new Error('response length mismatch');
    }
    if (c.terminal) return;
    const trailers = hasBody ? fields(response.rawTrailers) : [];
    validateTrailers(trailerNames, trailers);
    if (trailers.length && !this.trailers) throw new Error('unsupported trailers');
    // An early response may finish before its upload. Keep the request worker
    // alive until EOF so upload errors cannot be reported as a clean response.
    await c.inputDone;
    if (c.terminal) return;
    // Mark completion before awaiting the terminal write: a late upload close must not send a second terminal.
    c.terminal = true;
    if (c.buffered) await this.send({ httpResponse: { connectionId: c.id, ...metadata, body: Buffer.concat(chunks), trailers } });
    else await this.send({ connectionHalfClose: { connectionId: c.id, trailers } });
  }
}
