// Serverless Chrome tests over CDP pipes. No HTTP server, provider or dependency.
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve, sep } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { once } from 'node:events';
import vm from 'node:vm';
import { homedir } from 'node:os';

const repo = resolve(dirname(fileURLToPath(import.meta.url)), '../../..');
const preview = resolve(repo, '.scratch/agent-access-preview');
const scratch = join(repo, '.scratch');
const pages = ['index.html', 'team.html', 'results.html'];
const widths = [1280, 390];
mkdirSync(join(scratch, 'tmp'), { recursive: true });
mkdirSync(join(scratch, 'agent-access-screenshots'), { recursive: true });
for (const name of pages) {
  assert.ok(existsSync(join(preview, name)), 'Run build.py before site-smoke.mjs');
  const html = readFileSync(join(preview, name), 'utf8');
  assert.ok(!/<(?:form|iframe|object|embed)\b/i.test(html));
  assert.ok(!/\b(?:src|href|action)\s*=\s*["'](?:https?:|\/\/|mailto:|javascript:)/i.test(html));
  assert.ok(html.includes("connect-src 'none'"));
  assert.ok(!html.includes('@@RESULTS@@'));
}
const fixtureContext = vm.createContext({});
vm.runInContext(readFileSync(join(preview, 'walkthrough.js'), 'utf8'), fixtureContext);
assert.equal(fixtureContext.AccessFixture.create('mcp').request().state, 'success');

const browserCache = join(homedir(), 'Library/Caches/ms-playwright');
const cachedShells = existsSync(browserCache) ? readdirSync(browserCache)
  .filter(name => name.startsWith('chromium_headless_shell-'))
  .sort((a, b) => Number(b.split('-').at(-1)) - Number(a.split('-').at(-1)))
  .map(name => join(browserCache, name, 'chrome-headless-shell-mac-arm64/chrome-headless-shell')) : [];
const candidates = [process.env.CHROMIUM_PATH, ...cachedShells,
  '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
  '/Applications/Chromium.app/Contents/MacOS/Chromium',
  '/usr/bin/chromium', '/usr/bin/chromium-browser', '/usr/bin/google-chrome'].filter(Boolean);
const executable = candidates.find(path => existsSync(path));
if (!executable) {
  console.error('REQUIRED-UNRUN: browser DOM/visual/network gates; Chromium unavailable. Static checks passed.');
  process.exit(2);
}
const profile = mkdtempSync(join(scratch, 'agent-access-chrome-'));
const chrome = spawn(executable, [
  '--headless=new', '--remote-debugging-pipe', `--user-data-dir=${profile}`,
  `--crash-dumps-dir=${join(profile, 'crash-dumps')}`,
  '--no-first-run', '--no-default-browser-check', '--disable-background-networking',
  '--disable-component-update', '--disable-sync', '--disable-extensions', '--disable-default-apps',
  '--disable-domain-reliability', '--disable-client-side-phishing-detection', '--disable-breakpad',
  '--metrics-recording-only', '--safebrowsing-disable-auto-update', '--no-pings', '--disable-gpu',
  '--disable-features=MediaRouter,OptimizationHints,AutofillServerCommunication,CertificateTransparencyComponentUpdater',
  '--host-resolver-rules=MAP * ~NOTFOUND', '--proxy-server=http://127.0.0.1:9', 'about:blank',
], { stdio: ['ignore', 'ignore', 'pipe', 'pipe', 'pipe'], env: { ...process.env, TMPDIR: join(scratch, 'tmp') } });

let stderr = '';
chrome.stderr.on('data', chunk => { stderr = (stderr + chunk.toString()).slice(-12000); });
const pending = new Map();
const listeners = new Set();
let buffer = Buffer.alloc(0);
let sequence = 0;
let closing = false;
let chromeClosed = false;
let browserReady = false;
let networkCount = 0;
let unexpected = [];
const runtimeErrors = [];

function command(method, params = {}, sessionId) {
  return new Promise((resolvePromise, reject) => {
    if (chromeClosed || chrome.stdio[3].destroyed || chrome.stdio[3].writableEnded) {
      reject(new Error(`Chrome pipe closed: ${stderr}`)); return;
    }
    const id = ++sequence;
    const timeout = setTimeout(() => { pending.delete(id); reject(new Error(`CDP timeout: ${method}`)); }, 20000);
    pending.set(id, { resolve: resolvePromise, reject, timeout });
    chrome.stdio[3].write(JSON.stringify({ id, method, params, ...(sessionId ? { sessionId } : {}) }) + '\0');
  });
}
function allowed(url) {
  if (url === 'about:blank') return true;
  try {
    const path = fileURLToPath(url);
    return path.startsWith(preview + sep);
  } catch { return false; }
}
chrome.stdio[4].on('data', chunk => {
  buffer = Buffer.concat([buffer, chunk]);
  let end;
  while ((end = buffer.indexOf(0)) >= 0) {
    const message = JSON.parse(buffer.subarray(0, end).toString());
    buffer = buffer.subarray(end + 1);
    if (message.id) {
      const request = pending.get(message.id);
      if (request) {
        clearTimeout(request.timeout); pending.delete(message.id);
        if (message.error) request.reject(new Error(JSON.stringify(message.error)));
        else request.resolve(message.result);
      }
    } else {
      if (message.method === 'Network.requestWillBeSent') {
        networkCount += 1;
        if (!allowed(message.params.request.url)) unexpected.push(message.params.request.url);
      }
      if (message.method === 'Fetch.requestPaused') {
        const { requestId, request } = message.params;
        const ok = allowed(request.url);
        if (!ok) unexpected.push(request.url);
        command(ok ? 'Fetch.continueRequest' : 'Fetch.failRequest',
          ok ? { requestId } : { requestId, errorReason: 'BlockedByClient' }, message.sessionId)
          .catch(error => { if (!closing) runtimeErrors.push(error.message); });
      }
      if (message.method === 'Runtime.exceptionThrown') runtimeErrors.push(JSON.stringify(message.params.exceptionDetails));
      if (message.method === 'Log.entryAdded' && message.params.entry.level === 'error') runtimeErrors.push(message.params.entry.text);
      for (const listener of listeners) listener(message);
    }
  }
});
chrome.on('error', error => {
  for (const request of pending.values()) { clearTimeout(request.timeout); request.reject(error); }
  pending.clear();
});
chrome.stdio[3].on('error', error => {
  for (const request of pending.values()) { clearTimeout(request.timeout); request.reject(error); }
  pending.clear();
});
chrome.on('exit', () => {
  chromeClosed = true;
  for (const request of pending.values()) { clearTimeout(request.timeout); request.reject(new Error(`Chrome exited: ${stderr}`)); }
  pending.clear();
});

function event(method, sessionId) {
  return new Promise((resolvePromise, reject) => {
    const listener = message => {
      if (message.method === method && message.sessionId === sessionId) {
        clearTimeout(timeout); listeners.delete(listener); resolvePromise(message.params);
      }
    };
    const timeout = setTimeout(() => { listeners.delete(listener); reject(new Error(`Missing browser event: ${method}`)); }, 20000);
    listeners.add(listener);
  });
}
async function evaluate(expression, sessionId) {
  const response = await command('Runtime.evaluate', { expression, returnByValue: true, awaitPromise: true }, sessionId);
  if (response.exceptionDetails) throw new Error(JSON.stringify(response.exceptionDetails));
  return response.result.value;
}

let checks = 0;
try {
  const version = await command('Browser.getVersion');
  browserReady = true;
  const { targetId } = await command('Target.createTarget', { url: 'about:blank' });
  const { sessionId } = await command('Target.attachToTarget', { targetId, flatten: true });
  for (const domain of ['Page', 'Network', 'Runtime', 'Log']) await command(`${domain}.enable`, {}, sessionId);
  await command('Fetch.enable', { patterns: [{ urlPattern: '*', requestStage: 'Request' }] }, sessionId);
  for (const width of widths) {
    await command('Emulation.setDeviceMetricsOverride', { width, height: 900, deviceScaleFactor: 1, mobile: width < 500 }, sessionId);
    for (const name of pages) {
      const loaded = event('Page.loadEventFired', sessionId);
      await command('Page.navigate', { url: pathToFileURL(join(preview, name)).href }, sessionId);
      await loaded;
      const state = await evaluate(`({
        title: document.title, text: document.body.innerText,
        forms: document.querySelectorAll('form,iframe,object,embed').length,
        actions: [...document.querySelectorAll('button')].filter(b => /signup|payment|invite|send email/i.test(b.textContent) && !b.disabled).length,
        overflow: document.documentElement.scrollWidth > innerWidth + 1,
        stylesheet: document.styleSheets.length,
        links: [...document.querySelectorAll('a')].map(a => a.getAttribute('href')),
      })`, sessionId);
      assert.ok(state.title.startsWith('tunn'));
      assert.equal(state.forms, 0);
      assert.equal(state.actions, 0);
      assert.equal(state.overflow, false, `${name} overflows at ${width}px`);
      assert.equal(state.stylesheet, 1);
      assert.ok(state.links.every(href => href.startsWith('#') || pages.includes(href)));
      if (name === 'results.html') {
        assert.ok(state.text.includes('0 asserted actual rows'));
        assert.ok(state.text.includes('16 simulated rows'));
        assert.ok(state.text.includes('NO_ACTUAL_EVIDENCE'));
        assert.ok(state.text.includes('undefined (null)'));
        assert.ok(state.text.includes('Collected payment'));
      } else {
        assert.ok(state.text.includes('LOCAL PROTOTYPE'));
        const click = action => evaluate(`document.querySelector('[data-action="${action}"]').click(); document.getElementById('fixture-result').dataset.state`, sessionId);
        assert.equal(await click('success'), 'success');
        assert.equal(await click('denied'), 'denied');
        assert.equal(await click('ungranted'), 'denied');
        assert.equal(await click('revoked'), 'revoked');
        assert.equal(await click('success'), 'revoked');
        assert.ok((await evaluate("document.getElementById('fixture-audit').textContent", sessionId)).includes('operations: 1'));
        await click('reset');
        assert.equal(await click('offline'), 'offline');
        await click('reset');
        await click('timer-start');
        assert.ok((await evaluate("document.getElementById('elapsed').textContent", sessionId)).includes('Ineligible for demand evidence'));
        await click('timer-stop');
        await click('reset');
        // Exercise the actual internal anchor and verify keyboard-visible controls.
        await evaluate("document.querySelector('a[href=\"#walkthrough\"]').click()", sessionId);
        const focusable = await evaluate("document.querySelector('[data-action=success]').focus(); document.activeElement.dataset.action", sessionId);
        assert.equal(focusable, 'success');
      }
      assert.deepEqual(unexpected, [], 'Unexpected request fails the gate');
      assert.deepEqual(runtimeErrors, [], 'Browser console/runtime errors fail the gate');
      const screenshot = await command('Page.captureScreenshot', { format: 'png', captureBeyondViewport: true }, sessionId);
      writeFileSync(join(scratch, 'agent-access-screenshots', `${name.replace('.html', '')}-${width}.png`), Buffer.from(screenshot.data, 'base64'));
      checks += 1;
    }
  }
  // Verify the network guard with a classifier assertion; no external request is issued.
  assert.equal(allowed('https://unexpected.invalid/pixel'), false);
  assert.equal(allowed('file:///etc/passwd'), false);
  assert.ok(networkCount > 0, 'Network observer must see the local page/asset requests');
  console.log(`PASS: ${checks} page/viewport browser checks; 2 recipe state/timer flows; ${networkCount} local file requests; 0 external requests; ${version.product}.`);
  writeFileSync(join(scratch, 'agent-access-browser-receipt.json'), JSON.stringify({
    pages: pages.length, viewports: widths, pageViewportChecks: checks,
    localRequests: networkCount, unexpectedRequests: unexpected,
    browser: version.product, screenshots: '.scratch/agent-access-screenshots/',
  }, null, 2) + '\n');
} catch (error) {
  const unavailable = checks === 0 && /Operation not permitted|sandbox initialization failed|ENOENT/.test(stderr + error.message);
  if (unavailable) {
    console.error(`REQUIRED-UNRUN: browser DOM/visual/network gates; Chromium startup blocked by this environment.\n${stderr}`);
    writeFileSync(join(scratch, 'agent-access-browser-receipt.json'), JSON.stringify({
      status: 'REQUIRED-UNRUN', reason: 'Chromium startup blocked by environment',
      pageViewportChecks: 0, visualVerified: false, externalRequestsVerified: false, stderr,
    }, null, 2) + '\n');
    process.exitCode = 2;
  } else {
    console.error(`FAIL: ${error.stack}\n${stderr}`);
    process.exitCode = 1;
  }
} finally {
  closing = true;
  if (!chromeClosed) {
    try { await command('Browser.close'); } catch { /* Closing drops pending CDP responses. */ }
    if (!chromeClosed) await once(chrome, 'exit');
  }
}
