const assert = require('node:assert/strict');
const fs = require('node:fs');
const http = require('node:http');
const path = require('node:path');
const {chromium} = require(process.env.TUNN_ACCOUNT_TUNNELS_PLAYWRIGHT_MODULE);
const snapshots = JSON.parse(fs.readFileSync(process.argv[2]));
const assets = process.argv[3], evidence = path.resolve(process.argv[4]);

(async () => {
  const browser = await chromium.launch({headless:true});
  let current = snapshots.empty;
  const server = http.createServer((req, res) => {
    if (req.url === '/account') {
      res.setHeader('Content-Type', 'text/html'); return res.end(current.html);
    }
    if (req.url === '/api/account/tunnels') {
      res.setHeader('Content-Type', 'application/json'); return res.end(JSON.stringify(current.listing));
    }
    if (req.url.startsWith('/assets/')) {
      return http.get(assets + req.url, upstream => {
        res.writeHead(upstream.statusCode, upstream.headers); upstream.pipe(res);
      }).on('error', error => res.destroy(error));
    }
    res.writeHead(404); res.end();
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const origin = `http://127.0.0.1:${server.address().port}`;
  const records = [];
  try {
    for (const name of ['empty', 'running', 'over-limit', 'busy', 'plan-limit']) {
      for (const theme of ['light', 'dark']) for (const width of [390, 1440]) {
        current = snapshots[name];
        const record = name === 'empty' && theme === 'light' && width === 390;
        const context = await browser.newContext({
          viewport:{width, height:900}, colorScheme:theme, reducedMotion:'reduce',
          ...(record ? {recordVideo:{dir:path.join(evidence, 'video'), size:{width:390, height:900}}} : {})
        });
        await context.grantPermissions(['clipboard-read', 'clipboard-write'], {origin});
        // All page requests stay on the local fixture; no production contact.
        await context.route('**/*', route => {
          assert.equal(new URL(route.request().url()).origin, origin, 'nonlocal request');
          return route.continue();
        });
        const page = await context.newPage(), errors = [], dialogs = [];
        page.on('pageerror', error => errors.push(error.message));
        page.on('dialog', async dialog => { dialogs.push(dialog.type()); await dialog.dismiss(); });
        await page.goto(origin + '/account');
        await page.evaluate(() => document.fonts.ready);
        await page.waitForFunction(n => document.querySelectorAll('.live-tunnel').length === n, current.count);
        assert.equal(await page.locator('.who .plan-badge').innerText(), `Plan · ${current.plan}`);
        assert.equal(await page.locator('.gauges .gauge').count(), 2);
        assert.match(await page.locator('.gauges').innerText(), /Transfer/);
        assert.match(await page.locator('.gauges').innerText(), /Requests: unlimited \(fair use\)/);
        assert.equal(await page.locator('#monthly-limit').count(), current.exhausted ? 1 : 0);
        assert.equal(await page.locator('#start-tunnel').count(), name === 'empty' ? 1 : 0);
        assert.equal(await page.locator('.live-tunnel:visible').count(), Math.min(4, current.count));
        if (current.count > 4) assert.equal(await page.locator('#live-tunnels-more').innerText(), `+${current.count - 4} more`);
        const measurements = await page.evaluate(() => ({viewport:innerWidth, scrollWidth:document.documentElement.scrollWidth}));
        assert.ok(measurements.scrollWidth <= width, `${name}/${theme}/${width}: horizontal overflow`);
        await page.evaluate(() => scrollTo(0, 0));
        const file = `account-${name}-${width}-${theme}.png`;
        await page.screenshot({path:path.join(evidence, file), fullPage:true, animations:'disabled'});
        if (name === 'empty') {
          assert.equal(await page.locator('#start-tunnel p').count(), 0, 'explanatory paragraphs in empty state');
          assert.match(await page.locator('.gauges').innerText(), /0 B/);
          const codes = await page.locator('#start-tunnel code').allTextContents();
          assert.deepEqual(codes, ['curl -fsSL https://tunn.to/install.sh | sh', 'tunn 3000']);
          for (const [i, button] of (await page.locator('#start-tunnel button').all()).entries()) {
            assert.equal(await button.getAttribute('data-copy'), codes[i]);
            await button.click();
            await page.waitForFunction(id => document.getElementById(id).textContent === 'Command copied', await button.getAttribute('aria-describedby'));
            assert.equal(await page.evaluate(() => navigator.clipboard.readText()), codes[i]);
            assert.equal(await button.innerText(), 'Copied');
          }
        }
        await page.evaluate(() => scrollTo(0, 0));
        if (record) {
          // Short phone journey: first commands, usage, a running tunnel, limit.
          await page.waitForTimeout(700);
          await page.locator('.gauges').scrollIntoViewIfNeeded();
          await page.waitForTimeout(700);
          for (const next of ['running', 'over-limit']) {
            current = snapshots[next];
            await page.goto(origin + '/account');
            await page.waitForTimeout(700);
          }
        }
        assert.deepEqual(errors, []);
        assert.deepEqual(dialogs, []);
        records.push({name, theme, width, count:snapshots[name].count, file, ...measurements, browserErrors:errors, dialogs});
        const video = page.video();
        await context.close();
        if (record) await video.saveAs(path.join(evidence, 'account-first-visit.webm'));
      }
    }
    const report = {result:'PASS', records, clipboard:true, emptyStateParagraphs:0, video:'account-first-visit.webm'};
    fs.writeFileSync(path.join(evidence, 'account-first-visit.json'), JSON.stringify(report, null, 2) + '\n');
    console.log(JSON.stringify(report));
  } finally {
    await browser.close();
    await new Promise(resolve => server.close(resolve));
  }
})().catch(error => { console.error(error); process.exitCode = 1; });
