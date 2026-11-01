"use strict";
const {chromium} = require(process.env.TUNN_PLAYWRIGHT_MODULE || '/work/cache/bs-0k78wi2i/web/node_modules/playwright');
const fs = require('fs');
(async () => {
  const [mode, url, state] = process.argv.slice(2);
  const browser = await chromium.launch({headless:true, args:['--no-proxy-server', '--host-resolver-rules=MAP *.tunn.local.127.0.0.1.nip.io 127.0.0.1, MAP tunn.local.127.0.0.1.nip.io 127.0.0.1']});
  try {
    const context = await browser.newContext({viewport:{width:390,height:844},ignoreHTTPSErrors:true, ...(mode === 'consent' ? {storageState:state} : {})});
    await context.route('**/*', route => {
      const u = new URL(route.request().url());
      if (u.hostname === '127.0.0.1' || u.hostname === 'tunn.local.127.0.0.1.nip.io' || u.hostname.endsWith('.tunn.local.127.0.0.1.nip.io')) return route.continue();
      return route.abort();
    });
    const page = await context.newPage();
    page.setDefaultTimeout(15000);
    await page.goto(url);
    if (mode === 'login') {
      await page.getByText('Continue with Mock Login').click();
      await page.getByRole('button',{name:'Authorize',exact:true}).click();
      await context.storageState({path:state});
    } else {
      await page.getByRole('button',{name:'Allow',exact:true}).click();
      await page.waitForURL(u => u.hostname === '127.0.0.1');
    }
  } finally { await browser.close(); }
})().catch(e => { console.error(e); process.exitCode=1; });
