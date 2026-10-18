const assert = require('node:assert/strict');
const fs = require('node:fs');
const http = require('node:http');
const path = require('node:path');
const {chromium} = require(process.env.TUNN_ACCOUNT_TUNNELS_PLAYWRIGHT_MODULE);
const fixture = JSON.parse(fs.readFileSync(process.argv[2]));
const legacyURL = '/assets/account-tunnels.js';
const legacyHTML = '<!doctype html><meta charset="utf-8"><p id="live-tunnels-status"></p><ul id="live-tunnel-list">' +
  '<li class="live-tunnel">Existing tunnel</li>'.repeat(8) +
  '</ul><p id="live-tunnels-empty" hidden>Start one</p><script defer src="' + legacyURL + '"></script>';

(async () => {
  const browser = await chromium.launch({headless:true});
  const results = [];
  try {
    for (const [warm, current] of [['legacy','legacy'], ['current','current'], ['legacy','current'], ['current','legacy']]) {
      let stage = warm, assetHits = 0, updates = 0, empty = false, failed = false;
      const errors = [];
      const server = http.createServer((req, res) => {
        if (req.url === '/warm') {
          res.setHeader('Content-Type','text/html; charset=utf-8');
          res.setHeader('Cache-Control','no-store');
          return res.end('<!doctype html><script src="' + (stage === 'legacy' ? legacyURL : fixture.url) + '"></script>');
        }
        if (req.url === '/account') {
          res.setHeader('Content-Type','text/html; charset=utf-8');
          res.setHeader('Cache-Control','no-store');
          return res.end(stage === 'legacy' ? legacyHTML : fixture.html);
        }
        if (req.url.startsWith(legacyURL)) {
          assetHits++;
          res.setHeader('Content-Type','application/javascript');
          res.setHeader('Cache-Control',fixture.cacheControl);
          return res.end(stage === 'legacy' ? fixture.legacyScript : fixture.script);
        }
        if (req.url === '/api/account/tunnels') {
          updates++;
          res.setHeader('Cache-Control','no-store');
          res.setHeader('Content-Type','application/json');
          if (failed) { res.statusCode = 503; return res.end('{}'); }
          return res.end(JSON.stringify({complete:true,tunnels:empty ? [] : fixture.listing.tunnels}));
        }
        res.statusCode = 404; res.end();
      });
      await new Promise(resolve => server.listen(0,'127.0.0.1',resolve));
      const context = await browser.newContext();
      const page = await context.newPage();
      page.on('pageerror',error => errors.push(error.message));
      try {
        const origin = 'http://127.0.0.1:' + server.address().port;
        await page.goto(origin + '/warm');
        assert.equal(assetHits,1);
        stage = current;
        const refreshed = page.waitForResponse(response => response.url().endsWith('/api/account/tunnels'));
        await page.goto(origin + '/account');
        await refreshed;
        await page.waitForFunction(() => document.querySelectorAll('.live-tunnel').length === 8);
        assert.ok(updates > 0,'cached script prevented updates');
        assert.equal(assetHits,warm === current ? 1 : 2,'unexpected browser cache behavior');
        if (current === 'current') {
          assert.equal(await page.locator('.live-tunnel:visible').count(),5);
          await page.locator('#live-tunnels-more').click();
          assert.equal(await page.locator('.live-tunnel:visible').count(),8);
          await page.locator('.live-tunnel-name').first().click();
          assert.equal(await page.locator('details[open]').count(),1);
          const retained = await page.locator('#live-tunnel-list').innerHTML();
          await page.clock.install();
          failed = true;
          await page.clock.fastForward(61000);
          await page.locator('#live-tunnels-stale').waitFor({state:'visible'});
          assert.equal(await page.locator('#live-tunnel-list').innerHTML(),retained);
          failed = false;
        }
        empty = true;
        await page.evaluate(() => document.dispatchEvent(new Event('visibilitychange')));
        await page.waitForFunction(() => document.querySelectorAll('.live-tunnel').length === 0);
        assert.deepEqual(errors,[]);
        results.push({warm,current,asset_network_requests:assetHits,update_requests:updates,disconnect_removed_rows:true,expansion_details_staleness:current === 'current'});
      } finally {
        await context.close();
        await new Promise(resolve => server.close(resolve));
      }
    }
    const report = {result:'PASS',cache_control:fixture.cacheControl,browser_request_interception:false,results};
    fs.writeFileSync(path.join(process.argv[3],'account-cache.json'),JSON.stringify(report,null,2)+'\n');
    console.log(JSON.stringify(report));
  } finally { await browser.close(); }
})().catch(error => { console.error(error); process.exitCode = 1; });
