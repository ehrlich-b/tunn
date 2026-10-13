import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as http from 'node:http';
import * as https from 'node:https';
import { createHash } from 'node:crypto';
import { inspect } from 'node:util';
import { readFileSync } from 'node:fs';
import { publish, publishHandler, TunnelError } from '../dist/index.js';
import { Events } from '../dist/events.js';
import { relay, ready, until, caps, listen, tls } from './fixture.mjs';

const fails = code => error => error instanceof TunnelError && error.code === code;
const origin = 'http://127.0.0.1:1';
async function collect(iterable) { const values = []; for await (const value of iterable) values.push(value); return values; }

test('packaged schema matches the repository protocol', () => {
  assert.equal(readFileSync(new URL('../proto/tunnel.proto', import.meta.url), 'utf8'), readFileSync(new URL('../../../proto/tunnel.proto', import.meta.url), 'utf8'));
});

test('invalid options fail synchronously before starting resources', () => {
  for (const patch of [
    { origin: 'file:///tmp/app' }, { origin: 'http://user:secret@host' }, { origin: 'http://host/api' },
    { origin: 'http://host/?q=1' }, { origin: 'http://host/#fragment' }, { origin: 'http://host/../' },
    { name: 'UPPER' }, { name: '-name' }, { name: 'name-' }, { name: 'x'.repeat(64) },
    { serverAddr: 'localhost' }, { serverAddr: 'localhost:0' }, { serverAddr: 'https://host:443' },
    { connectTimeoutMs: -1 }, { httpTimeoutMs: NaN }, { maxConnections: 0 }, { public: 'yes' },
    { credentials: { endpointToken: 'bad-format' } }, { public: true, allowedEmails: ['alice@example.invalid'] },
    { public: true, credentials: { endpointToken: 'tunn_ep_fixture' } }, { allowedEmails: [42] },
    { reconnect: { maxAttempts: -1 } }, { reconnect: { maxAttempts: 2, initialDelayMs: 20, maxDelayMs: 10 } },
  ]) assert.throws(() => publish({ origin, ...patch }), fails('invalid_options'));
  assert.throws(() => publishHandler(null), fails('invalid_options'));
  assert.throws(() => publishHandler(() => {}, { origin }), fails('invalid_options'));
  const aborted = new AbortController(); aborted.abort('private cancellation reason');
  assert.throws(() => publish({ origin, signal: aborted.signal }), fails('canceled'));
});

test('private default, credential digest, copied options and retained lifecycle', async t => {
  let registration;
  const r = await relay(t, async s => { registration = await s.next('registerClient'); ready(s, registration); });
  const allowedEmails = ['alice@example.invalid'];
  const credentials = { authToken: 'fixture-auth', tunnelKey: 'fixture-key', endpointToken: 'tunn_ep_fixture-endpoint' };
  const tunnel = publish({ origin, name: 'identity', ...r.options, credentials, allowedEmails });
  allowedEmails.push('bob@example.invalid'); credentials.authToken = 'changed';
  assert.equal(await tunnel.waitReady(), 'https://identity.sdk.test');
  assert.equal(registration.targetUrl, 'http');
  assert.equal(registration.authToken, 'fixture-auth');
  assert.deepEqual(registration.allowedEmails, ['alice@example.invalid']);
  assert.deepEqual(registration.accessTokenSha256, createHash('sha256').update('tunn_ep_fixture-endpoint').digest());
  assert.equal(registration.exposureVersion, 0); // Same explicitly private legacy compatibility as Go.
  assert.ok(!inspect(tunnel).includes('fixture-auth'));
  assert.ok(!inspect(tunnel).includes(origin));
  await Promise.all([tunnel.close(), tunnel.close(), tunnel.wait()]);
  assert.equal(await tunnel.waitReady(), 'https://identity.sdk.test');
  const events = await collect(tunnel.events);
  assert.deepEqual(events.map(e => e.state), ['connecting', 'ready', 'closed']);
  assert.equal(tunnel.status.state, 'closed');
  assert.equal(tunnel.url, 'https://identity.sdk.test');
});

for (const exposure of ['private', 'public', 'allow-list', 'endpoint']) {
  test(`registration exposure: ${exposure}`, async t => {
    let register;
    const r = await relay(t, async s => { register = await s.next('registerClient'); ready(s, register); });
    const exposureOptions = exposure === 'public' ? { public: true } : exposure === 'allow-list' ? { allowedEmails: ['@example.invalid'] } : exposure === 'endpoint' ? { credentials: { endpointToken: 'tunn_ep_fixture' } } : {};
    const tunnel = publish({ origin, ...r.options, ...exposureOptions }); t.after(() => tunnel.close());
    await tunnel.waitReady();
    assert.equal(register.exposureVersion, ['private', 'public'].includes(exposure) ? 1 : 0);
    assert.equal(register.exposureMode, exposure === 'private' ? 'private' : exposure === 'public' ? 'public' : '');
    assert.equal(register.creatorEmail, '');
  });
}

test('legacy relay rejects default/private and public before ready; explicit ACL remains compatible', async t => {
  const r = await relay(t, async s => { const register = await s.next('registerClient'); ready(s, register, []); });
  for (const options of [{}, { public: true }]) {
    const tunnel = publish({ origin, ...r.options, ...options });
    await assert.rejects(tunnel.waitReady(), fails('protocol_violation'));
    await assert.rejects(tunnel.wait(), fails('protocol_violation'));
  }
  const compatible = publish({ origin, ...r.options, allowedEmails: ['alice@example.invalid'] });
  await compatible.waitReady(); await compatible.close();
});

test('registration failures and remote errors never expose credentials', async t => {
  const secret = 'fixture-private-credential';
  const r = await relay(t, async s => {
    await s.next('registerClient');
    s.call.write({ registerResponse: { success: false, errorMessage: `relay echoed ${secret}` } });
  });
  const tunnel = publish({ origin, ...r.options, credentials: { authToken: secret } });
  await assert.rejects(tunnel.waitReady(), fails('registration_rejected'));
  await assert.rejects(tunnel.close(), fails('registration_rejected'));
  const events = await collect(tunnel.events);
  assert.deepEqual(events.map(e => e.state), ['connecting', 'failed', 'closed']);
  assert.ok(!inspect(events).includes(secret));
  assert.equal(r.sessions.length, 1);
});

for (const violation of ['wrong-first-message', 'duplicate', 'identity', 'credentials', 'path', 'changed-on-reconnect']) {
  test(`protocol violation: ${violation}`, async t => {
    const r = await relay(t, async (s, attempt) => {
      const register = await s.next('registerClient');
      if (violation === 'wrong-first-message') return s.call.write({ healthCheck: { timestamp: 1 } });
      let url = `https://${register.tunnelId}.sdk.test`;
      if (violation === 'identity') url = 'https://other.sdk.test';
      if (violation === 'credentials') url = `https://${register.tunnelId}.fixture-secret.test`;
      if (violation === 'path') url += '/path';
      if (violation === 'changed-on-reconnect' && attempt === 2) url += ':8443';
      ready(s, register, caps, url);
      if (violation === 'duplicate') ready(s, register);
      if (violation === 'changed-on-reconnect' && attempt === 1) s.call.end();
    });
    const tunnel = publish({ origin, ...r.options, credentials: { authToken: 'fixture-secret' }, reconnect: { maxAttempts: 2, initialDelayMs: 2, maxDelayMs: 5 } });
    await assert.rejects(tunnel.wait(), fails('protocol_violation'));
  });
}

test('bounded retry attempts retain identity; no retry timers after close', async t => {
  const names = [];
  const r = await relay(t, async s => { const register = await s.next('registerClient'); names.push(register.tunnelId); ready(s, register); s.call.end(); });
  const tunnel = publish({ origin, ...r.options, reconnect: { maxAttempts: 2, initialDelayMs: 5, maxDelayMs: 20 } });
  await assert.rejects(tunnel.wait(), fails('connection_failed'));
  assert.equal(names.length, 3); assert.equal(new Set(names).size, 1);
  const events = await collect(tunnel.events);
  assert.equal(events.filter(e => e.state === 'ready').length, 3);
  assert.ok(events.filter(e => e.state === 'reconnecting').every(e => e.retryDelayMs >= 2 && e.retryDelayMs <= 20));
  assert.equal(events.at(-1).state, 'closed');
});

test('TLS trust is verified; registration deadline cannot expire a ready stream', async t => {
  const r = await relay(t, async s => { ready(s, await s.next('registerClient')); });
  const untrusted = publish({ origin, ...r.options, relayCA: undefined });
  await assert.rejects(untrusted.waitReady(), fails('connection_failed'));
  const verified = publish({ origin, ...r.options, connectTimeoutMs: 150 });
  await verified.waitReady();
  await new Promise(resolve => setTimeout(resolve, 180));
  assert.equal(verified.status.state, 'ready'); await verified.close();
});

for (const stage of ['registration', 'ready', 'backoff', 'handler-initialization']) {
  test(`lifetime cancellation at ${stage} returns a static result and joins`, async t => {
    const controller = new AbortController();
    const r = await relay(t, async s => { const register = await s.next('registerClient'); if (stage !== 'registration') ready(s, register); if (stage === 'backoff') s.call.end(); });
    const options = { origin, ...r.options, signal: controller.signal, reconnect: { maxAttempts: 5, initialDelayMs: 200, maxDelayMs: 200 } };
    const tunnel = stage === 'handler-initialization' ? publishHandler(() => {}, { ...options, origin: undefined }) : publish(options);
    if (stage === 'registration') await until(() => r.sessions.length === 1);
    if (stage === 'ready') await tunnel.waitReady();
    if (stage === 'backoff') await until(() => tunnel.status.state === 'reconnecting');
    controller.abort('fixture-private-cancel-reason');
    await assert.rejects(tunnel.wait(), fails('canceled')); await tunnel.done;
    assert.equal(tunnel.status.state, 'closed');
    assert.ok(!inspect(tunnel.status).includes('fixture-private-cancel-reason'));
  });
}

test('waitReady cancellation does not cancel the publisher', async t => {
  const r = await relay(t, async s => { const register = await s.next('registerClient'); await new Promise(resolve => setTimeout(resolve, 60)); ready(s, register); });
  const tunnel = publish({ origin, ...r.options }); t.after(() => tunnel.close());
  await assert.rejects(tunnel.waitReady(AbortSignal.timeout(20)), fails('canceled'));
  assert.ok(await tunnel.waitReady());
});

test('registration timeout, explicit close while connecting and health checks', async t => {
  const r = await relay(t, async s => { await s.next('registerClient'); });
  const timeout = publish({ origin, ...r.options, connectTimeoutMs: 50 });
  await assert.rejects(timeout.waitReady(), fails('connection_failed'));
  const close = publish({ origin, ...r.options }); await close.close();
  await assert.rejects(close.waitReady(), fails('canceled'));
  const ping = await relay(t, async s => { ready(s, await s.next('registerClient')); s.call.write({ healthCheck: { timestamp: 123 } }); });
  const tunnel = publish({ origin, ...ping.options }); t.after(() => tunnel.close());
  await tunnel.waitReady(); const pong = await ping.sessions[0].next('healthCheckResponse');
  assert.equal(pong.timestamp, 123); assert.ok(pong.responseTimestamp > 123);
});

test('event buffer retains 16 ordered entries and the terminal event', async () => {
  const events = new Events();
  for (let i = 0; i < 25; i++) events.push({ state: 'connecting', retryDelayMs: i });
  events.push({ state: 'closed' });
  const retained = await collect(events);
  assert.equal(retained.length, 16); assert.equal(retained[0].retryDelayMs, 10); assert.equal(retained.at(-1).state, 'closed');
});

async function request(s, id, path, buffered = false, method = 'GET', headers = {}, body = Buffer.alloc(0)) {
  if (buffered) s.call.write({ httpRequest: { connectionId: id, method, path, headers, body } });
  else {
    s.call.write({ connectionOpen: { connectionId: id, protocol: 'http', httpRequest: { method, path, headers, contentLength: body.length } } });
    if (body.length) s.call.write({ connectionData: { connectionId: id, data: body } });
    s.call.write({ connectionHalfClose: { connectionId: id } });
  }
  if (buffered) return s.next('httpResponse');
  const accepted = await s.next('connectionAccept');
  assert.equal(accepted.success, true);
  const chunks = [];
  while (true) {
    const message = await s.next();
    if (message.message === 'connectionData') chunks.push(message.connectionData.data);
    else if (message.message === 'connectionHalfClose') return { ...accepted.httpResponse, body: Buffer.concat(chunks), trailers: message.connectionHalfClose.trailers };
    else assert.fail(`unexpected response terminal ${message.message}`);
  }
}

for (const mode of ['handler', 'origin']) for (const buffered of [false, true]) {
  test(`${mode} ${buffered ? 'buffered' : 'streaming'} HTTP forwards path, application auth, repeated cookies and trailers`, async t => {
    const handler = async (req, res) => {
      const parts = []; for await (const part of req) parts.push(part);
      res.setHeader('Set-Cookie', ['one=a,b=c', 'two=d']); res.setHeader('X-Repeat', ['one', 'two']);
      res.setHeader('Trailer', 'X-Final');
      res.write(JSON.stringify({ url: req.url, method: req.method, auth: req.headers.authorization, tunnAuth: req.headers['tunn-authorization'] ?? '', host: req.headers.host, body: Buffer.concat(parts).toString() }));
      res.addTrailers({ 'X-Final': ['first', 'second'] }); res.end();
    };
    const r = await relay(t, async s => ready(s, await s.next('registerClient')));
    const app = mode === 'origin' ? http.createServer(handler) : undefined;
    const appOrigin = app ? await listen(t, app) : undefined;
    const tunnel = mode === 'handler' ? publishHandler(handler, r.options) : publish({ origin: appOrigin, ...r.options });
    t.after(() => tunnel.close()); await tunnel.waitReady();
    const response = await request(r.sessions[0], 'test', '/mcp?q=%2F', buffered, 'POST', { Authorization: 'Bearer application', Host: 'public.sdk.test', 'Tunn-Authorization': 'Bearer private' }, Buffer.from('input'));
    assert.equal(response.statusCode, 200);
    assert.deepEqual(JSON.parse(response.body), { url: '/mcp?q=%2F', method: 'POST', auth: 'Bearer application', tunnAuth: '', host: 'public.sdk.test', body: 'input' });
    assert.deepEqual(response.headerFields.filter(f => f.name.toLowerCase() === 'set-cookie').map(f => f.value), ['one=a,b=c', 'two=d']);
    assert.deepEqual(response.trailers.map(f => f.value), ['first', 'second']);
    await tunnel.close();
    if (appOrigin) { const res = await fetch(appOrigin); assert.equal(res.status, 200); await res.text(); }
  });
}

test('SSE prefix reaches relay before completion and body outlives header deadline', async t => {
  let finish;
  const completed = new Promise(resolve => { finish = resolve; });
  const r = await relay(t, async s => ready(s, await s.next('registerClient')));
  const tunnel = publishHandler(async (_req, res) => {
    res.writeHead(200, { 'Content-Type': 'text/event-stream' }); res.write('data: prefix\n\n');
    await completed; res.end('data: final\n\n');
  }, { ...r.options, httpTimeoutMs: 60 });
  t.after(() => tunnel.close()); await tunnel.waitReady(); const s = r.sessions[0];
  s.call.write({ connectionOpen: { connectionId: 'sse', protocol: 'http', httpRequest: { method: 'GET', path: '/', contentLength: 0 } } });
  s.call.write({ connectionHalfClose: { connectionId: 'sse' } });
  assert.equal((await s.next('connectionAccept')).httpResponse.statusCode, 200);
  assert.equal((await s.next('connectionData')).data.toString(), 'data: prefix\n\n');
  await new Promise(resolve => setTimeout(resolve, 90)); assert.equal(tunnel.status.state, 'ready');
  finish(); assert.equal((await s.next('connectionData')).data.toString(), 'data: final\n\n');
  await s.next('connectionHalfClose');
});

test('HTTPS origin verifies trust independently from relay CA', async t => {
  const server = https.createServer(tls, (_req, res) => res.end('secure'));
  const url = (await listen(t, server)).replace('http:', 'https:');
  const r = await relay(t, async s => ready(s, await s.next('registerClient')));
  const denied = publish({ origin: url, ...r.options }); await denied.waitReady();
  assert.equal((await request(r.sessions[0], 'untrusted', '/', true)).statusCode, 502); await denied.close();
  const trusted = publish({ origin: url, ...r.options, originCA: tls.cert }); t.after(() => trusted.close()); await trusted.waitReady();
  assert.equal((await request(r.sessions[1], 'trusted', '/', true)).body.toString(), 'secure');
});

for (const buffered of [false, true]) {
  test(`upstream authorization gate (${buffered ? 'buffered' : 'streaming'})`, async t => {
    let calls = 0;
    const r = await relay(t, async s => ready(s, await s.next('registerClient')));
    const tunnel = publishHandler((_req, res) => { calls++; res.end('allowed'); }, { ...r.options, requireUpstreamAuth: true });
    t.after(() => tunnel.close()); await tunnel.waitReady();
    assert.equal((await request(r.sessions[0], 'absent', '/', buffered)).statusCode, 401);
    assert.equal(calls, 0);
    assert.equal((await request(r.sessions[0], 'present', '/', buffered, 'GET', { Authorization: 'Bearer app' })).body.toString(), 'allowed');
    assert.equal(calls, 1);
  });
}

test('upstream gate rejects relays without credential separation capability', async t => {
  const r = await relay(t, async s => ready(s, await s.next('registerClient'), caps.filter(c => c !== 'websocket-v1')));
  const tunnel = publish({ origin, ...r.options, requireUpstreamAuth: true });
  await assert.rejects(tunnel.waitReady(), fails('protocol_violation')); await tunnel.done;
});

for (const buffered of [false, true]) for (const method of ['HEAD', '204', '304']) {
  test(`bodyless ${method} (${buffered ? 'buffered' : 'streaming'})`, async t => {
    const r = await relay(t, async s => ready(s, await s.next('registerClient')));
    const tunnel = publishHandler((_req, res) => {
      if (method === 'HEAD') res.setHeader('Content-Length', '100'); else res.statusCode = Number(method);
      res.end();
    }, r.options);
    t.after(() => tunnel.close()); await tunnel.waitReady();
    const response = await request(r.sessions[0], 'bodyless', '/', buffered, method === 'HEAD' ? method : 'GET');
    assert.equal(response.statusCode, method === 'HEAD' ? 200 : Number(method));
    assert.equal(response.body.length, 0);
  });
}

test('small buffered body limits reject oversize request and response', async t => {
  const r = await relay(t, async s => ready(s, await s.next('registerClient')));
  const tunnel = publishHandler((_req, res) => res.end('123456789'), { ...r.options, maxBufferedBytes: 8 });
  t.after(() => tunnel.close()); await tunnel.waitReady();
  assert.equal((await request(r.sessions[0], 'large-input', '/', true, 'POST', {}, Buffer.from('123456789'))).statusCode, 502);
  assert.equal((await request(r.sessions[0], 'large-output', '/', true)).statusCode, 502);
});

for (const buffered of [false, true]) {
  test(`response header timeout and unreachable origin (${buffered ? 'buffered' : 'streaming'})`, async t => {
    const r = await relay(t, async s => ready(s, await s.next('registerClient')));
    const timeout = publishHandler(() => {}, { ...r.options, httpTimeoutMs: 30 });
    await timeout.waitReady();
    if (buffered) assert.equal((await request(r.sessions[0], 'timeout', '/', true)).statusCode, 502);
    else {
      r.sessions[0].call.write({ connectionOpen: { connectionId: 'timeout', protocol: 'http', httpRequest: { method: 'GET', path: '/', contentLength: 0 } } });
      assert.equal((await r.sessions[0].next('connectionAccept')).success, false);
    }
    await timeout.close();
    const denied = publish({ origin, ...r.options }); await denied.waitReady();
    assert.equal((await request(r.sessions[1], 'no-origin', '/', true)).statusCode, 502); await denied.close();
  });
}

for (const invalid of ['path', 'method', 'length', 'request-trailers', 'data-after-eof', 'short-upload', 'unsupported-protocol']) {
  test(`invalid streaming request is rejected: ${invalid}`, async t => {
    const r = await relay(t, async s => ready(s, await s.next('registerClient')));
    const tunnel = publishHandler((_req, _res) => {}, r.options);
    t.after(() => tunnel.close()); await tunnel.waitReady(); const s = r.sessions[0];
    s.call.write({ connectionOpen: { connectionId: 'invalid', protocol: invalid === 'unsupported-protocol' ? 'tcp' : 'http', httpRequest: { method: invalid === 'method' ? 'bad method' : 'POST', path: invalid === 'path' ? 'http://external.invalid' : '/', contentLength: invalid === 'length' ? -2 : 2 } } });
    if (invalid === 'request-trailers') s.call.write({ connectionHalfClose: { connectionId: 'invalid', trailers: [{ name: 'X-Input', value: 'value' }] } });
    if (invalid === 'data-after-eof') {
      s.call.write({ connectionData: { connectionId: 'invalid', data: Buffer.from('ok') } });
      s.call.write({ connectionHalfClose: { connectionId: 'invalid' } });
      s.call.write({ connectionData: { connectionId: 'invalid', data: Buffer.from('x') } });
    }
    if (invalid === 'short-upload') s.call.write({ connectionHalfClose: { connectionId: 'invalid' } });
    assert.equal((await s.next('connectionAccept')).success, false);
    assert.equal(tunnel.status.state, 'ready');
  });
}

test('early response remains open until valid upload EOF; short upload closes with error', async t => {
  const r = await relay(t, async s => ready(s, await s.next('registerClient')));
  const tunnel = publishHandler((req, res) => { req.resume(); res.end('prefix'); }, r.options);
  t.after(() => tunnel.close()); await tunnel.waitReady(); const s = r.sessions[0];
  s.call.write({ connectionOpen: { connectionId: 'early', protocol: 'http', httpRequest: { method: 'POST', path: '/', contentLength: 2 } } });
  await s.next('connectionAccept'); assert.equal((await s.next('connectionData')).data.toString(), 'prefix');
  s.call.write({ connectionHalfClose: { connectionId: 'early' } });
  assert.equal((await s.next()).message, 'connectionClose');
  assert.equal(tunnel.status.state, 'ready');
});

for (const negotiated of [false, true]) {
  test(`response trailers require capability and valid declarations (${negotiated})`, async t => {
    const r = await relay(t, async s => ready(s, await s.next('registerClient'), negotiated ? caps : caps.filter(c => c !== 'http-response-trailers-v1')));
    const tunnel = publishHandler((_req, res) => { res.setHeader('Trailer', negotiated ? 'Authorization' : 'X-Final'); res.write('body'); res.addTrailers({ [negotiated ? 'Authorization' : 'X-Final']: 'value' }); res.end(); }, r.options);
    t.after(() => tunnel.close()); await tunnel.waitReady();
    assert.equal((await request(r.sessions[0], 'trailers', '/', true)).statusCode, 502);
  });
}

test('connection limit, remote cancel, and tunnel close destroy pending origins', async t => {
  let closed = 0;
  const r = await relay(t, async s => ready(s, await s.next('registerClient')));
  const tunnel = publishHandler((req, _res) => { req.socket.once('close', () => closed++); }, { ...r.options, maxConnections: 1 });
  await tunnel.waitReady(); const s = r.sessions[0];
  const open = id => s.call.write({ connectionOpen: { connectionId: id, protocol: 'http', httpRequest: { method: 'GET', path: '/', contentLength: 0 } } });
  open('first'); await new Promise(resolve => setTimeout(resolve, 25)); open('second');
  assert.equal((await s.next('connectionAccept')).success, false);
  s.call.write({ connectionClose: { connectionId: 'first' } }); await until(() => closed === 1);
  open('third'); await new Promise(resolve => setTimeout(resolve, 25)); await tunnel.close(); await until(() => closed === 2);
});

test('runnable MCP example initializes, lists/calls a tool, and rejects wrong Host/Origin', async t => {
  const { mcpHandler } = await import('../examples/mcp-server.mjs');
  const r = await relay(t, async s => ready(s, await s.next('registerClient')));
  const tunnel = publishHandler(mcpHandler('https://mcp.sdk.test'), { ...r.options, name: 'mcp' });
  t.after(() => tunnel.close()); await tunnel.waitReady(); const s = r.sessions[0];
  const headers = { Host: 'mcp.sdk.test', Accept: 'application/json, text/event-stream', 'Content-Type': 'application/json' };
  const rpc = async (id, method, params) => {
    const response = await request(s, String(id), '/mcp', false, 'POST', headers, Buffer.from(JSON.stringify({ jsonrpc: '2.0', id, method, params })));
    assert.equal(response.statusCode, 200);
    return JSON.parse(response.body).result;
  };
  const init = await rpc(1, 'initialize', { protocolVersion: '2025-11-25', capabilities: {}, clientInfo: { name: 'fixture', version: '1.0.0' } });
  assert.equal(init.serverInfo.name, 'tunn-node-example');
  assert.equal((await rpc(2, 'tools/list', {})).tools[0].name, 'hello');
  assert.equal((await rpc(3, 'tools/call', { name: 'hello', arguments: {} })).content[0].text, 'Hello from Node through tunn');
  assert.equal((await request(s, 'wrong-host', '/mcp', true, 'POST', { ...headers, Host: 'evil.invalid' })).statusCode, 403);
  assert.equal((await request(s, 'wrong-origin', '/mcp', true, 'POST', { ...headers, Origin: 'https://evil.invalid' })).statusCode, 403);
});

for (const stable of [false, true]) {
  test(`retry budget resets only after a ready session: ${stable}`, async t => {
    let now = Date.now();
    t.mock.method(Date, 'now', () => now);
    const controller = new AbortController();
    let tunnel;
    const r = await relay(t, async (s, attempt) => {
      const register = await s.next('registerClient');
      if (stable && attempt === 2) {
        ready(s, register); await until(() => tunnel.status.state === 'ready');
        now += 31_000;
      } else if (!stable) now += 31_000;
      // Bound the old buggy implementation without long timers or load.
      if (attempt >= 4) controller.abort();
      s.call.end();
    });
    tunnel = publish({ origin, ...r.options, signal: controller.signal, reconnect: { maxAttempts: 1, initialDelayMs: 2, maxDelayMs: 2 } });
    t.after(() => tunnel.close().catch(() => {}));
    await assert.rejects(tunnel.wait(), fails('connection_failed'));
    assert.equal(r.sessions.length, stable ? 3 : 2);
  });
}

for (const status of [400, 413, 500]) {
  test(`completed early ${status} abandons upload and releases the worker`, async t => {
    const r = await relay(t, async s => ready(s, await s.next('registerClient')));
    const tunnel = publishHandler((req, res) => { if (req.url === '/reject') { res.writeHead(status).end('rejected'); } else { req.resume(); res.end('accepted'); } }, { ...r.options, maxConnections: 1, httpTimeoutMs: 60 });
    t.after(() => tunnel.close()); await tunnel.waitReady(); const s = r.sessions[0];
    s.call.write({ connectionOpen: { connectionId: 'reject', protocol: 'http', httpRequest: { method: 'POST', path: '/reject', contentLength: 20 } } });
    // No upload data or EOF: a rejected caller is allowed to stop immediately.
    assert.equal((await s.next('connectionAccept')).httpResponse.statusCode, status);
    assert.equal((await s.next('connectionData')).data.toString(), 'rejected');
    await s.next('connectionHalfClose');
    await new Promise(resolve => setTimeout(resolve, 10));
    s.call.write({ connectionData: { connectionId: 'reject', data: Buffer.from('late') } });
    assert.equal((await request(s, 'next', '/ok')).body.toString(), 'accepted');
    assert.equal(tunnel.status.state, 'ready');
  });
}

test('streamed upload progresses while an early response prefix is open', async t => {
  const r = await relay(t, async s => ready(s, await s.next('registerClient')));
  const tunnel = publishHandler(async (req, res) => {
    res.write('prefix:'); const chunks = []; for await (const part of req) chunks.push(part);
    res.end(Buffer.concat(chunks));
  }, r.options);
  t.after(() => tunnel.close()); await tunnel.waitReady(); const s = r.sessions[0];
  s.call.write({ connectionOpen: { connectionId: 'duplex', protocol: 'http', httpRequest: { method: 'POST', path: '/', contentLength: -1 } } });
  await s.next('connectionAccept'); assert.equal((await s.next('connectionData')).data.toString(), 'prefix:');
  for (const part of ['one', 'two']) s.call.write({ connectionData: { connectionId: 'duplex', data: Buffer.from(part) } });
  s.call.write({ connectionHalfClose: { connectionId: 'duplex' } });
  assert.equal((await s.next('connectionData')).data.toString(), 'onetwo'); await s.next('connectionHalfClose');
});

test('truncated upstream response sends error terminal after delivered prefix', async t => {
  const r = await relay(t, async s => ready(s, await s.next('registerClient')));
  let truncate;
  const app = http.createServer((_req, res) => { res.writeHead(200, { 'Content-Length': '8' }); res.write('prefix'); truncate = () => res.destroy(); });
  const appOrigin = await listen(t, app);
  const tunnel = publish({ origin: appOrigin, ...r.options }); t.after(() => tunnel.close()); await tunnel.waitReady(); const s = r.sessions[0];
  s.call.write({ connectionOpen: { connectionId: 'truncated', protocol: 'http', httpRequest: { method: 'GET', path: '/', contentLength: 0 } } });
  s.call.write({ connectionHalfClose: { connectionId: 'truncated' } });
  await s.next('connectionAccept'); assert.equal((await s.next('connectionData')).data.toString(), 'prefix');
  truncate(); assert.equal((await s.next()).message, 'connectionClose');
});

test('session reconnect destroys old pending HTTP workers', async t => {
  let closed = 0;
  const r = await relay(t, async s => ready(s, await s.next('registerClient')));
  const tunnel = publishHandler((req, _res) => { req.socket.once('close', () => closed++); }, { ...r.options, reconnect: { maxAttempts: 1, initialDelayMs: 2, maxDelayMs: 2 } });
  t.after(() => tunnel.close()); await tunnel.waitReady();
  r.sessions[0].call.write({ connectionOpen: { connectionId: 'old', protocol: 'http', httpRequest: { method: 'GET', path: '/', contentLength: 0 } } });
  await new Promise(resolve => setTimeout(resolve, 25)); r.sessions[0].call.end();
  await until(() => closed === 1 && r.sessions.length === 2 && tunnel.status.state === 'ready');
  await tunnel.close(); assert.equal(closed, 1);
});
