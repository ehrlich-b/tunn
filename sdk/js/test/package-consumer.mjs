import { execFileSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import assert from 'node:assert/strict';

const packageRoot = dirname(dirname(fileURLToPath(import.meta.url)));
const scratch = mkdtempSync(join(tmpdir(), 'tunn-js-consumer-'));
try {
  const packed = JSON.parse(execFileSync('npm', ['pack', '--json', '--pack-destination', scratch], { cwd: packageRoot, encoding: 'utf8', stdio: ['ignore', 'pipe', 'inherit'] }))[0];
  const files = packed.files.map(f => f.path);
  assert.ok(files.includes('dist/index.js') && files.includes('dist/index.d.ts') && files.includes('proto/tunnel.proto') && files.includes('README.md'));
  assert.ok(files.every(f => !f.startsWith('test/') && !f.startsWith('src/') && !f.includes('node_modules') && !f.endsWith('.key')));
  const consumer = join(scratch, 'app'); mkdirSync(consumer);
  const lock = JSON.parse(readFileSync(join(packageRoot, 'package-lock.json')));
  const overrides = Object.fromEntries(Object.entries(lock.packages).filter(([path, pkg]) => path.startsWith('node_modules/') && !pkg.dev).map(([path, pkg]) => [path.slice('node_modules/'.length), pkg.version]));
  writeFileSync(join(consumer, 'package.json'), JSON.stringify({ private: true, type: 'module', dependencies: { '@tunn/sdk': 'file:' + join(scratch, packed.filename) }, overrides }));
  execFileSync('npm', ['install', '--offline', '--ignore-scripts', '--no-audit', '--no-fund'], { cwd: consumer, stdio: 'inherit' });
  writeFileSync(join(consumer, 'consumer.ts'), `
import { publish, publishHandler, TunnelError, type Options, type Tunnel, type Event } from '@tunn/sdk';
const options: Options = { origin: 'http://127.0.0.1:3000', credentials: { authToken: 'fixture', tunnelKey: 'fixture' }, allowedEmails: ['alice@example.invalid'], reconnect: { maxAttempts: 0 }, signal: new AbortController().signal };
const tunnel: Tunnel = publish(options);
const event: Event = tunnel.status;
void event; void tunnel.waitReady(); void tunnel.done; void tunnel.close();
const handler = publishHandler((_req, res) => res.end('hello'), { public: true });
void handler.close();
const error: TunnelError = new TunnelError('canceled'); void error.code;
// @ts-expect-error Origins belong only to publish.
publishHandler((_req, res) => res.end(), { origin: 'http://localhost' });
// @ts-expect-error Public exposure requires a boolean.
publish({ origin: 'http://localhost', public: 'yes' });
`);
  execFileSync(process.execPath, [join(packageRoot, 'node_modules/typescript/bin/tsc'), '--noEmit', '--strict', '--skipLibCheck', '--module', 'NodeNext', '--moduleResolution', 'NodeNext', '--target', 'ES2022', '--typeRoots', join(packageRoot, 'node_modules/@types'), join(consumer, 'consumer.ts')], { cwd: consumer, stdio: 'inherit' });
  writeFileSync(join(consumer, 'consumer.mjs'), `
import assert from 'node:assert/strict';
import { publish, publishHandler, TunnelError } from '@tunn/sdk';
const canceled = new AbortController(); canceled.abort();
assert.throws(() => publish({ origin: 'http://localhost:3000', signal: canceled.signal }), e => e instanceof TunnelError && e.code === 'canceled');
const tunnel = publishHandler((_req,res) => res.end('hello'), { serverAddr: '127.0.0.1:1', reconnect: { maxAttempts: 0 } });
await tunnel.close(); await tunnel.done;
assert.equal(tunnel.status.state, 'closed');
`);
  execFileSync(process.execPath, [join(consumer, 'consumer.mjs')], { cwd: consumer, stdio: 'inherit' });
  const installed = JSON.parse(readFileSync(join(consumer, 'node_modules/@tunn/sdk/package.json')));
  assert.equal(installed.name, '@tunn/sdk');
  console.log('PASS: tarball inventory, isolated ESM import, declaration consumer, negative types, shutdown');
} finally { rmSync(scratch, { recursive: true, force: true }); }
