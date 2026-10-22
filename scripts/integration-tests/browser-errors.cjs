const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {chromium} = require(process.env.TUNN_ERRORS_PLAYWRIGHT_MODULE);
const input = JSON.parse(fs.readFileSync(process.argv[2]));
const evidence = process.argv[3];
(async () => {
  const browser = await chromium.launch({headless:true, args:['--disable-background-networking']});
  const results = [];
  try {
    for (const theme of ['light','dark']) for (const width of [390,1440]) {
      const context = await browser.newContext({viewport:{width,height:width===390?844:1000},colorScheme:theme,permissions:['clipboard-read','clipboard-write']});
      let current;
      await context.route('**/*', async route => {
        const url = new URL(route.request().url());
        if (url.href === current.URL) return route.fulfill({status:current.Status,contentType:'text/html',body:current.HTML});
        if (input.assets[url.pathname]) {
          const contentType = url.pathname.endsWith('.js') ? 'application/javascript' : url.pathname.endsWith('.css') ? 'text/css' : url.pathname.endsWith('.svg') ? 'image/svg+xml' : 'application/octet-stream';
          return route.fulfill({contentType,body:Buffer.from(input.assets[url.pathname],'base64')});
        }
        // Account inventory is already server rendered; prevent live replacement.
        if (url.pathname === '/api/account/tunnels') return route.fulfill({status:503,body:'Fixture inventory unavailable'});
        return route.fulfill({status:404,body:''});
      });
      const page = await context.newPage();
      for (current of input.pages) {
        const response = await page.goto(current.URL);
        assert.equal(response.status(),current.Status);
        await page.evaluate(() => document.fonts.ready);
        assert.equal(await page.evaluate(() => document.documentElement.scrollWidth<=innerWidth),true,`${current.Name} horizontal overflow`);
        const prefix = `${current.Name}-${width}-${theme}`;
        await page.screenshot({path:path.join(evidence,prefix+'-first.png')});
        await page.screenshot({path:path.join(evidence,prefix+'.png'),fullPage:true});
        if (process.env.TUNN_ERRORS_VERIFY === '1' && !current.Name.startsWith('account-')) {
          assert.equal(await page.locator('main h1').count(),1);
          const action = page.locator('main .ctas .btn.sig');
          assert.equal(await action.count(),1,`${current.Name} needs one primary action`);
          assert.equal(await action.isVisible(),true);
          const box = await action.boundingBox();
          assert.ok(box.y+box.height<=(width===390?844:1000),`${current.Name} action below first screen`);
          if (current.Name==='ip-blocked') {
            assert.match(await page.locator('main').innerText(),/allowed network/);
            assert.match(await page.locator('main').innerText(),/owner/);
          }
          if (current.Name==='app-down') {
            assert.match(await page.locator('main').innerText(),/Visiting this link\?/);
            assert.match(await page.locator('main').innerText(),/Running this tunnel\?/);
            assert.equal(await action.innerText(),'Reload');
          }
          if (current.Name==='auth-error') assert.doesNotMatch(await page.locator('main').innerText(),/state|binding/);
          await action.focus();
          assert.equal(await action.evaluate(el=>el===document.activeElement),true);
          if (current.Name.startsWith('device-')) {
            await action.click();
            await page.waitForFunction(()=>document.querySelector('[data-copy]').textContent==='Copied');
            assert.equal(await page.evaluate(()=>navigator.clipboard.readText()),'tunn login');
          }
          if (['app-down','ip-blocked'].includes(current.Name)) {
            const reload = page.waitForResponse(r=>r.url()===current.URL);
            await action.click();
            assert.equal((await reload).status(),current.Status);
          }
        }
        results.push({name:current.Name,width,theme,status:response.status(),first:prefix+'-first.png',full:prefix+'.png'});
      }
      await context.close();
    }
    fs.writeFileSync(path.join(evidence,'screenshots.json'),JSON.stringify({result:'PASS',captures:results},null,2)+'\n');
    console.log(JSON.stringify({result:'PASS',screenshots:results.length*2}));
  } finally { await browser.close(); }
})().catch(error=>{console.error(error);process.exit(1)});
