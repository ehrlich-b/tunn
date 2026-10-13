import * as grpc from '@grpc/grpc-js';
import { loadSync } from '@grpc/proto-loader';
import { fileURLToPath } from 'node:url';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFileSync } from 'node:child_process';
import { once } from 'node:events';
import { setTimeout as delay } from 'node:timers/promises';
import assert from 'node:assert/strict';

export const schema = fileURLToPath(new URL('../proto/tunnel.proto', import.meta.url));
export const service = grpc.loadPackageDefinition(loadSync(schema, { longs: Number, defaults: true, oneofs: true })).tunn.v1.TunnelService;
const root = mkdtempSync(join(tmpdir(), 'tunn-js-cert-'));
let tls;
try {
  execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1', '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost,IP:127.0.0.1', '-keyout', join(root, 'fixture.key'), '-out', join(root, 'fixture.crt')], { stdio: 'ignore' });
  tls = { key: readFileSync(join(root, 'fixture.key')), cert: readFileSync(join(root, 'fixture.crt')) };
} finally { rmSync(root, { recursive: true, force: true }); }
export { tls };
export const caps = ['http-stream-v1', 'connection-stream-v1', 'http-response-trailers-v1', 'websocket-v1', 'web-sharing-v1'];

export function inbox(emitter) {
  const values = [], waiting = [];
  emitter.on('data', value => {
    if (waiting.length) waiting.shift()(value); else values.push(value);
  });
  return async function next(kind) {
    const timeout = AbortSignal.timeout(2500);
    while (true) {
      let resolve;
      const promise = values.length ? Promise.resolve(values.shift()) : new Promise(r => { resolve = r; waiting.push(r); });
      const aborted = new Promise((_, reject) => {
        const listener = () => reject(new Error(`fixture timeout waiting for ${kind}`));
        timeout.addEventListener('abort', listener, { once: true });
        promise.finally(() => timeout.removeEventListener('abort', listener));
      });
      let value;
      try { value = await Promise.race([promise, aborted]); }
      finally { if (resolve) { const i = waiting.indexOf(resolve); if (i !== -1) waiting.splice(i, 1); } }
      if (!kind || value.message === kind) return kind ? value[kind] : value;
    }
  };
}

export async function relay(t, handle) {
  const server = new grpc.Server();
  const sessions = [];
  server.addService(service.service, { establishTunnel(call) {
    call.on('error', () => {});
    const next = inbox(call);
    const session = { call, next };
    sessions.push(session);
    Promise.resolve(handle(session, sessions.length)).catch(error => { call.destroy(error); });
  } });
  const address = await new Promise((resolve, reject) => server.bindAsync('127.0.0.1:0', grpc.ServerCredentials.createSsl(null, [{ private_key: tls.key, cert_chain: tls.cert }]), (error, port) => error ? reject(error) : resolve(`127.0.0.1:${port}`)));
  t.after(() => server.forceShutdown());
  return { address, sessions, options: { serverAddr: address, relayCA: tls.cert, connectTimeoutMs: 600, reconnect: { maxAttempts: 0 } } };
}
export function ready(session, register, capabilities = caps, url = `https://${register.tunnelId}.sdk.test`) {
  session.call.write({ registerResponse: { success: true, publicUrl: url, capabilities } });
}
export async function until(predicate) {
  for (let i = 0; i < 250; i++) { if (predicate()) return; await delay(10); }
  assert.fail('fixture condition timed out');
}
export async function listen(t, server) {
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  t.after(() => { server.closeAllConnections?.(); server.close(); });
  return `http://127.0.0.1:${server.address().port}`;
}
