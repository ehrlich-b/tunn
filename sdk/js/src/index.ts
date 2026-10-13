import * as grpc from '@grpc/grpc-js';
import * as http from 'node:http';
import type { Socket } from 'node:net';
import { setTimeout as delay } from 'node:timers/promises';
import { Config, Options, HandlerOptions, TunnelError, configure } from './options.js';
import { Event, Events } from './events.js';
import { TunnelService, Stream, Message, capabilities, write } from './protocol.js';
import { Forwarder } from './forward.js';

export { TunnelError } from './options.js';
export type { Options, HandlerOptions, Credentials, ReconnectPolicy, ErrorCode } from './options.js';
export type { Event, State } from './events.js';

/** Starts asynchronously after synchronous local validation. */
export function publish(options: Options): Tunnel { return new RunningTunnel(configure(options)); }

/** Serves a Node request listener on an SDK-owned ephemeral IPv4 loopback port. */
export function publishHandler(handler: http.RequestListener, options: HandlerOptions = {}): Tunnel {
  if (typeof handler !== 'function' || !options || options.origin !== undefined) throw new TunnelError('invalid_options');
  return new RunningTunnel(configure({ ...options, origin: 'http://127.0.0.1' }), handler);
}

export interface Tunnel {
  readonly name: string;
  readonly url: string | undefined;
  readonly status: Event;
  readonly events: AsyncIterable<Event>;
  readonly done: Promise<void>;
  waitReady(signal?: AbortSignal): Promise<string>;
  wait(): Promise<void>;
  close(): Promise<void>;
}

class RunningTunnel implements Tunnel {
  #config: Config;
  #controller = new AbortController();
  #events = new Events();
  #status: Event = Object.freeze({ state: 'connecting' });
  #url?: string;
  #firstURL?: string;
  #ready: Promise<string | TunnelError>;
  #resolveReady!: (result: string | TunnelError) => void;
  #done: Promise<void>;
  #resolveDone!: () => void;
  #error?: TunnelError;
  #stop?: 'close' | 'cancel';
  #finished = false;
  #server?: http.Server;
  #sockets = new Set<Socket>();
  #abortListener: () => void;

  /** Use publish/publishHandler. Configuration is internal and retains credentials privately. */
  constructor(config: Config, handler?: http.RequestListener) {
    this.#config = config;
    this.#ready = new Promise(resolve => { this.#resolveReady = resolve; });
    this.#done = new Promise(resolve => { this.#resolveDone = resolve; });
    this.#abortListener = () => this.stop('cancel');
    config.signal?.addEventListener('abort', this.#abortListener, { once: true });
    if (config.signal?.aborted) this.stop('cancel');
    queueMicrotask(() => { void this.run(handler); });
  }
  get name(): string { return this.#config.name; }
  /** Last confirmed URL; check status for current connectivity. */
  get url(): string | undefined { return this.#url; }
  get status(): Event { return this.#status; }
  get events(): AsyncIterable<Event> { return this.#events; }
  /** Resolves after all SDK-owned resources close; use wait() for the terminal result. */
  get done(): Promise<void> { return this.#done; }

  /** The signal limits only this wait. The first registration result is retained. */
  async waitReady(signal?: AbortSignal): Promise<string> {
    if (signal?.aborted) throw new TunnelError('canceled');
    let abort!: () => void;
    const canceled = new Promise<TunnelError>(resolve => { abort = () => resolve(new TunnelError('canceled')); });
    signal?.addEventListener('abort', abort, { once: true });
    try {
      const result = await (signal ? Promise.race([this.#ready, canceled]) : this.#ready);
      if (result instanceof TunnelError) throw result;
      return result;
    } finally { signal?.removeEventListener('abort', abort); }
  }
  async wait(): Promise<void> { await this.#done; if (this.#error) throw this.#error; }
  /** Idempotent join. Intentional shutdown succeeds; a prior failure remains observable. */
  async close(): Promise<void> { this.stop('close'); return this.wait(); }
  private stop(reason: 'close' | 'cancel'): void {
    if (this.#finished || this.#stop) return;
    this.#stop = reason;
    this.#controller.abort();
  }
  private emit(event: Event): void {
    this.#status = Object.freeze(event);
    if (event.state === 'ready') {
      this.#url = event.url;
      if (!this.#firstURL) { this.#firstURL = event.url; this.#resolveReady(event.url!); }
    }
    this.#events.push(this.#status);
  }
  private async serve(handler: http.RequestListener): Promise<void> {
    if (this.#controller.signal.aborted) return;
    const server = http.createServer({ requestTimeout: 0, headersTimeout: 30_000 }, handler);
    this.#server = server;
    server.on('connection', socket => {
      this.#sockets.add(socket);
      socket.once('close', () => this.#sockets.delete(socket));
    });
    await new Promise<void>((resolve, reject) => {
      server.once('error', () => reject(new TunnelError('connection_failed')));
      server.listen({ port: 0, host: '127.0.0.1', signal: this.#controller.signal }, resolve);
      this.#controller.signal.addEventListener('abort', () => reject(new TunnelError('canceled')), { once: true });
    });
    const address = server.address();
    if (!address || typeof address === 'string') throw new TunnelError('connection_failed');
    this.#config.origin = new URL(`http://127.0.0.1:${address.port}`);
  }
  private async run(handler?: http.RequestListener): Promise<void> {
    let error: TunnelError | undefined;
    try {
      if (handler) await this.serve(handler);
      let retries = 0;
      while (!this.#controller.signal.aborted) {
        this.emit({ state: 'connecting' });
        const { error: result, stable } = await this.session();
        if (result?.code === 'registration_rejected' || result?.code === 'protocol_violation') { error = result; break; }
        if (this.#controller.signal.aborted) break;
        if (stable) retries = 0;
        if (retries >= this.#config.reconnect.maxAttempts) { error = result ?? new TunnelError('connection_failed'); break; }
        const cap = Math.min(this.#config.reconnect.maxDelayMs, this.#config.reconnect.initialDelayMs * 2 ** Math.min(retries, 31));
        const retryDelayMs = Math.max(1, Math.floor(cap * (0.5 + Math.random() / 2)));
        retries++;
        this.emit({ state: 'reconnecting', error: result ?? new TunnelError('connection_failed'), retryDelayMs });
        try { await delay(retryDelayMs, undefined, { signal: this.#controller.signal }); } catch { break; }
      }
    } catch (caught) {
      if (!this.#controller.signal.aborted) error = caught instanceof TunnelError ? caught : new TunnelError('connection_failed');
    } finally {
      // Freeze failure before cleanup so a later close does not erase it.
      this.#error = error ?? (this.#stop === 'cancel' ? new TunnelError('canceled') : undefined);
      this.#config.signal?.removeEventListener('abort', this.#abortListener);
      this.#controller.abort();
      for (const socket of this.#sockets) socket.destroy();
      if (this.#server) await new Promise<void>(resolve => this.#server!.close(() => resolve()));
      this.#finished = true;
      if (this.#error && this.#error.code !== 'canceled') this.emit({ state: 'failed', error: this.#error });
      this.emit({ state: 'closed', error: this.#error });
      if (!this.#firstURL) this.#resolveReady(this.#error ?? new TunnelError('canceled'));
      this.#resolveDone();
    }
  }
  private validURL(value: string): boolean {
    try {
      const url = new URL(value);
      if (!/^https?:\/\/[^/?#]+\/?$/.test(value) || url.username || url.password || !url.hostname.startsWith(this.name + '.')) return false;
      if (this.#url && this.#url !== value) return false;
      const forms = [value, decodeURIComponent(value)];
      return ![this.#config.authToken, this.#config.tunnelKey, this.#config.endpointToken].some(secret => secret && forms.some(form => form.includes(secret)));
    } catch { return false; }
  }
  private async session(): Promise<{ error?: TunnelError; stable: boolean }> {
    const config = this.#config;
    const credentials = grpc.credentials.createSsl(config.relayCA ? Buffer.from(config.relayCA) : undefined);
    const client = new TunnelService(config.serverAddr, credentials, {
      'grpc.max_receive_message_length': 128 * 1024 * 1024,
      'grpc.max_send_message_length': 128 * 1024 * 1024,
      'grpc.enable_retries': 0,
      'grpc.enable_http_proxy': 0,
    });
    const stream = (client as unknown as { establishTunnel(): Stream }).establishTunnel();
    const session = new AbortController();
    let forwarder: Forwarder | undefined;
    let registered = false;
    let readyAt: number | undefined;
    let finishedAt = 0;
    let resolve!: (result: TunnelError | undefined) => void;
    const ended = new Promise<TunnelError | undefined>(done => { resolve = done; });
    let finished = false;
    const finish = (error?: TunnelError) => {
      if (finished) return;
      finished = true; finishedAt = Date.now(); resolve(error);
      session.abort(); stream.cancel();
    };
    const abort = () => finish();
    this.#controller.signal.addEventListener('abort', abort, { once: true });
    const timer = setTimeout(() => finish(new TunnelError('connection_failed')), config.connectTimeoutMs);
    const send = (message: Message) => write(stream, message, session.signal);
    stream.on('error', () => finish(new TunnelError('connection_failed')));
    stream.on('end', () => finish(new TunnelError('connection_failed')));
    stream.on('data', (message: Message) => {
      if (finished) return;
      try {
        if (!registered) {
          if (message.message !== 'registerResponse') return finish(new TunnelError('protocol_violation'));
          const response = message.registerResponse;
          if (!response.success) return finish(new TunnelError('registration_rejected'));
          if (!this.validURL(response.publicUrl) || (config.requireSharing && !response.capabilities.includes('web-sharing-v1')) || (config.requireUpstreamAuth && !response.capabilities.includes('websocket-v1'))) return finish(new TunnelError('protocol_violation'));
          registered = true; readyAt = Date.now(); clearTimeout(timer);
          forwarder = new Forwarder(config, response.capabilities.includes('http-response-trailers-v1'), send);
          this.emit({ state: 'ready', url: response.publicUrl });
        } else if (message.message === 'registerResponse') finish(new TunnelError('protocol_violation'));
        else if (message.message === 'healthCheck') void send({ healthCheckResponse: { timestamp: message.healthCheck.timestamp, responseTimestamp: Date.now() } }).catch(() => finish(new TunnelError('connection_failed')));
        else forwarder?.message(message);
      } catch { finish(new TunnelError('protocol_violation')); }
    });
    if (this.#controller.signal.aborted) finish();
    else void send({ registerClient: {
      tunnelId: config.name, targetUrl: 'http', authToken: config.authToken,
      allowedEmails: config.allowedEmails, tunnelKey: config.tunnelKey,
      accessTokenSha256: config.endpointDigest, capabilities,
      endpointProtocol: 'http', exposureVersion: config.requireSharing ? 1 : 0,
      exposureMode: config.requireSharing ? (config.public ? 'public' : 'private') : '',
    } }).catch(() => finish(new TunnelError('connection_failed')));
    const result = await ended;
    clearTimeout(timer);
    this.#controller.signal.removeEventListener('abort', abort);
    client.close();
    await forwarder?.close();
    return { error: result, stable: readyAt !== undefined && finishedAt - readyAt >= 30_000 };
  }
}
