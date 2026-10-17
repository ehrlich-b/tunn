const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {chromium} = require(process.env.TUNN_ACCOUNT_TUNNELS_PLAYWRIGHT_MODULE);
const port = process.argv[2], evidence = path.resolve(process.argv[3]);
const apex = `https://tunn.test:${port}`;
(async () => {
  const browser = await chromium.launch({headless:true,args:['--no-proxy-server','--disable-background-networking','--host-resolver-rules=MAP *.tunn.test 127.0.0.1, MAP tunn.test 127.0.0.1']});
  try {
    async function person(email) {
      const context = await browser.newContext({ignoreHTTPSErrors:true,viewport:{width:1440,height:1000}});
      context.setDefaultTimeout(12000);
      await context.route('**/auth/google?*', async route => {
        const url = new URL(route.request().url()); url.hostname = '127.0.0.1';
        const response = await route.fetch({url:url.href,headers:{...route.request().headers(),host:`tunn.test:${port}`},maxRedirects:0});
        const consent = new URL(response.headers().location), callback = new URL(consent.searchParams.get('redirect_uri'));
        callback.searchParams.set('state',consent.searchParams.get('state')); callback.searchParams.set('code',email);
        const headers = {...response.headers(),'content-type':'text/html'}; delete headers.location; delete headers['content-length'];
        await route.fulfill({response,status:200,headers,body:`<a href="${callback.href.replaceAll('&','&amp;')}">Approve verified email</a>`});
      });
      const page = await context.newPage();
      await page.goto(apex+'/account');
      await page.getByRole('link',{name:'Continue with Google'}).click();
      await page.getByRole('link',{name:'Approve verified email'}).click();
      await page.getByRole('heading',{name:'Account',exact:true}).waitFor();
      return {context,page};
    }
    async function request(context,target,options={}) {
      const url = new URL(target), host = url.host, cookies = await context.cookies(target); url.hostname = '127.0.0.1';
      return context.request.fetch(url.href,{...options,headers:{...options.headers,Host:host,Cookie:cookies.map(c => c.name+'='+c.value).join('; ')},maxRedirects:0});
    }
    const {context,page} = await person('owner@example.com');
    const errors = []; page.on('pageerror',error => errors.push(error.message));
    await page.locator('#live-tunnels-empty').waitFor({state:'visible'});
    await page.screenshot({path:path.join(evidence,'account-empty-1440.png'),fullPage:true});
    await page.evaluate(() => { window.accountPageIdentity = 'preserved'; });
    assert.equal((await request(context,apex+'/_fixture/connect',{method:'POST'})).status(),204);
    await page.locator('.live-tunnel').waitFor();
    assert.match(await page.locator('.live-tunnel').innerText(),/webhooks/);
    assert.match(await page.locator('.live-tunnel').innerText(),/HTTP/);
    assert.match(await page.locator('.live-tunnel').innerText(),/1\.2\.3/);
    assert.match(await page.locator('.live-tunnel').innerText(),/linux\/amd64/);
    assert.equal((await request(context,`https://webhooks.tunn.test:${port}/health`)).status(),200);
    await page.waitForFunction(() => document.querySelector('.live-tunnel dd:last-child time'));
    const snapshot = await request(context,apex+'/api/account/tunnels');
    assert.equal(snapshot.status(),200); assert.ok(snapshot.headers()['cache-control'].includes('no-store'));
    const listing = await snapshot.json(); assert.equal(listing.tunnels.length,1); assert.ok(listing.tunnels[0].last_request);
    for (const width of [1440,390]) {
      await page.setViewportSize({width,height:width===390?844:1000});
      assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth),true,'horizontal overflow');
      await page.screenshot({path:path.join(evidence,`account-active-${width}.png`),fullPage:true});
    }
    const other = await person('other@example.com');
    assert.equal(await other.page.locator('.live-tunnel').count(),0);
    const otherListing = await request(other.context,apex+'/api/account/tunnels?account_id=someone-else');
    assert.deepEqual((await otherListing.json()).tunnels,[]);
    const anonymous = await browser.newContext({ignoreHTTPSErrors:true});
    assert.equal((await request(anonymous,apex+'/api/account/tunnels')).status(),302);
    await anonymous.close(); await other.context.close();
    let polls = 0; page.on('request',r => { if (r.url().endsWith('/api/account/tunnels')) polls++; });
    // Dispatch the browser visibility event deterministically in headless mode.
    await page.evaluate(() => { Object.defineProperty(document,'hidden',{configurable:true,value:true}); document.dispatchEvent(new Event('visibilitychange')); });
    await page.waitForTimeout(5500); assert.equal(polls,0,'polling continued while hidden');
    await page.evaluate(() => { Object.defineProperty(document,'hidden',{configurable:true,value:false}); document.dispatchEvent(new Event('visibilitychange')); });
    await page.waitForFunction(() => document.querySelector('.live-tunnel'));
    await page.waitForTimeout(300); assert.ok(polls>0,'polling did not resume');
    assert.equal((await request(context,apex+'/_fixture/disconnect',{method:'POST'})).status(),204);
    await page.locator('#live-tunnels-empty').waitFor({state:'visible'});
    assert.equal(await page.locator('.live-tunnel').count(),0);
    assert.equal(await page.evaluate(() => window.accountPageIdentity),'preserved','page reloaded');
    assert.deepEqual(errors,[]);
    await page.screenshot({path:path.join(evidence,'account-disconnected-390.png'),fullPage:true});
    const report = {result:'PASS',connected_without_reload:true,disconnected_without_reload:true,other_account_isolated:true,anonymous_requires_sign_in:true,hidden_visibility_event_stops_polling:true,resumes_on_visible:true,viewport_widths:[390,1440],browser_errors:errors};
    fs.writeFileSync(path.join(evidence,'account-browser.json'),JSON.stringify(report,null,2)+'\n');
    console.log(JSON.stringify(report));
    await context.close();
  } finally { await browser.close(); }
})().catch(error => { console.error(error); process.exitCode=1; });
