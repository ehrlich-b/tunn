import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';
const context = vm.createContext({});
vm.runInContext(readFileSync(new URL('../site/walkthrough.js', import.meta.url), 'utf8'), context);
for (const recipe of ['mcp', 'browser']) {
  const f = context.AccessFixture.create(recipe);
  assert.equal(f.request().state, 'success');
  assert.equal(f.upstreamOperations, 1);
  assert.equal(f.request('other').state, 'denied');
  assert.equal(f.request(f.caller, 'write_secret').state, 'denied');
  assert.equal(f.upstreamOperations, 1);
  assert.equal(f.revoke().state, 'revoked');
  assert.equal(f.request().state, 'revoked');
  assert.equal(f.upstreamOperations, 1);
  const offline = context.AccessFixture.create(recipe);
  assert.equal(offline.setOffline().state, 'offline');
  assert.equal(offline.upstreamOperations, 0);
  assert.equal(offline.request('other').state, 'denied');
  assert.equal(offline.revoke().state, 'revoked');
}
assert.throws(() => context.AccessFixture.create('unknown'));
console.log('PASS: two synthetic recipes; allowed/denied/revoked/offline; zero denied fixture operations.');
