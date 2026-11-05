'use strict';
const fs = require('node:fs');
const assert = require('node:assert/strict');
const {chromium} = require(process.env.TUNN_PLAYWRIGHT_MODULE || 'playwright');
(async () => {
  const input = JSON.parse(fs.readFileSync(0, 'utf8'));
  const base = new URL(input.base);
  const callback = new URL(input.callback);
  const browser = await chromium.launch({headless:true, args:[
    '--no-proxy-server', `--host-resolver-rules=MAP *.${base.hostname} 127.0.0.1, MAP ${base.hostname} 127.0.0.1`
  ]});
  try {
    const context = await browser.newContext({viewport:{width:390,height:844}, ignoreHTTPSErrors:true});
    await context.addCookies(Object.entries(input.cookies).map(([name,value]) => ({name,value,url:input.base,secure:true})));
    let result;
    const page = await context.newPage();
    // CDP intercepts each redirect hop. Playwright route handlers run only on
    // the first URL of a redirected request, so cannot capture OAuth callbacks.
    const cdp = await context.newCDPSession(page);
    await cdp.send('Fetch.enable', {patterns:[{urlPattern:'*',requestStage:'Request'}]});
    cdp.on('Fetch.requestPaused', async event => {
      const u = new URL(event.request.url);
      if (u.origin === callback.origin && u.pathname === callback.pathname) {
        result = u.href;
        return cdp.send('Fetch.fulfillRequest',{requestId:event.requestId,responseCode:200,
          responseHeaders:[{name:'Content-Type',value:'text/plain'}],
          body:Buffer.from('Authorization returned to test client.').toString('base64')});
      }
      if ((u.hostname === base.hostname && u.port === base.port) ||
          (u.hostname === '127.0.0.1' && u.port === String(input.oidc_port))) {
        return cdp.send('Fetch.continueRequest',{requestId:event.requestId});
      }
      await cdp.send('Fetch.failRequest',{requestId:event.requestId,errorReason:'BlockedByClient'});
      console.error('Browser refused destination',u.origin);
    });
    page.setDefaultTimeout(15000);
    page.on('console', m => { if(m.type()==='error') console.error(m.text().replace(/[?].*/g, '?[redacted]')); });
    page.on('requestfailed', r=>console.error('request failed',new URL(r.url()).pathname,r.failure()?.errorText));
    await page.goto(input.url);
    const allow = page.getByRole('button',{name:'Allow',exact:true});
    await allow.waitFor();
    assert.match(await page.locator('h1').innerText(), /Allow .* to use .* tools\?/);
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true, 'consent overflows at 390px');
    const box = await allow.boundingBox();
    assert.ok(box && box.width > 0 && box.x >= 0 && box.x + box.width <= 390);
    await page.screenshot({path:input.screenshot,fullPage:true});
    await allow.click();
    await page.waitForURL(u => u.origin === callback.origin && u.pathname === callback.pathname);
    assert.ok(result);
    const u = new URL(result), auth = new URL(input.url);
    assert.equal(u.searchParams.get('state'), auth.searchParams.get('state'));
    assert.equal(u.searchParams.get('iss'), input.base);
    assert.ok(u.searchParams.get('code'));
    process.stdout.write(JSON.stringify({callback:result,width:390,overflow:false})+'\n');
  } finally { await browser.close(); }
})().catch(e=>{console.error(e);process.exitCode=1;});
