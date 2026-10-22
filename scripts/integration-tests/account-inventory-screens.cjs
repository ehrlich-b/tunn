// Viewport/theme capture loop adapted from the account/sign-in capture harness.
const fs = require('node:fs');
const path = require('node:path');
const http = require('node:http');
const assert = require('node:assert/strict');
const {chromium} = require(process.env.TUNN_ACCOUNT_TUNNELS_PLAYWRIGHT_MODULE);
const snapshots = JSON.parse(fs.readFileSync(process.argv[2]));
const assets = process.argv[3], evidence = process.argv[4];
(async () => {
 const browser = await chromium.launch({headless:true});
 const records = [];
 let current, listing;
 const server = http.createServer((req,res) => {
  if (req.url === '/account') { res.setHeader('Content-Type','text/html'); return res.end(current.html); }
  if (req.url === '/api/account/tunnels') { res.setHeader('Content-Type','application/json'); return res.end(JSON.stringify(listing)); }
  if (req.url.startsWith('/assets/')) {
   return http.get(assets+req.url, upstream => { res.writeHead(upstream.statusCode,upstream.headers); upstream.pipe(res); }).on('error',e=>res.destroy(e));
  }
  res.writeHead(404); res.end();
 });
 await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
 const origin = 'http://127.0.0.1:'+server.address().port;
 try {
  for (const [name,snapshot] of Object.entries(snapshots)) {
   current = snapshot; listing = snapshot.listing;
   for (const theme of ['light','dark']) for (const width of [390,1440]) {
    const context = await browser.newContext({viewport:{width,height:900},colorScheme:theme,reducedMotion:'reduce'});
    const page = await context.newPage(), errors=[];
    page.on('pageerror',e=>errors.push(e.message));
    await page.goto(origin+'/account');
    await page.evaluate(()=>document.fonts.ready);
    const account = name.startsWith('account-');
    if (account) {
     await page.waitForFunction(n=>document.querySelectorAll('.live-tunnel').length===n,snapshot.count);
     assert.equal(await page.locator('.live-tunnel:visible').count(),Math.min(4,snapshot.count));
     assert.equal((await page.locator('#live-tunnels-summary').innerText()).includes('Partial list'),snapshot.partial);
     assert.equal(await page.locator('#live-tunnels-empty').isVisible(),snapshot.count===0&&!snapshot.partial);
     if (snapshot.count>4) assert.equal(await page.locator('#live-tunnels-more').innerText(),'+'+(snapshot.count-4)+' more');
    }
    const metrics = await page.evaluate(()=>({viewport:innerWidth,scrollWidth:document.documentElement.scrollWidth}));
    assert.ok(metrics.scrollWidth<=width, name+' overflow '+JSON.stringify(metrics));
    const file = name+'-'+width+'-'+theme+'.png';
    await page.screenshot({path:path.join(evidence,file),fullPage:true,animations:'disabled'});
    if (name==='account-8-false') {
     // Partial updates add proven rows without deleting previously known rows.
     const all = listing;
     listing = {...all,complete:false,tunnels:all.tunnels.slice(0,1).concat([{...all.tunnels[0],name:'new-peer',public_url:'https://new-peer.tunn.test'}])};
     await page.evaluate(()=>document.dispatchEvent(new Event('visibilitychange')));
     await page.waitForFunction(()=>document.querySelectorAll('.live-tunnel').length===9);
     assert.match(await page.locator('#live-tunnels-summary').innerText(),/Partial list/);
     listing={complete:false,tunnels:[]};
     await page.evaluate(()=>document.dispatchEvent(new Event('visibilitychange')));
     await page.waitForTimeout(100);
     assert.equal(await page.locator('.live-tunnel').count(),9);
     listing={complete:true,tunnels:[]};
     await page.evaluate(()=>document.dispatchEvent(new Event('visibilitychange')));
     await page.waitForFunction(()=>document.querySelectorAll('.live-tunnel').length===0);
     assert.ok(await page.locator('#live-tunnels-empty').isVisible());
     listing=all;
    }
    assert.deepEqual(errors,[]);
    records.push({name,width,theme,file,...metrics});
    await context.close();
   }
  }
  fs.writeFileSync(path.join(evidence,'manifest.json'),JSON.stringify({result:'PASS',records},null,2)+'\n');
  console.log(JSON.stringify({result:'PASS',screenshots:records.length,partial_updates:'retain known rows and add proven rows',overflow:false}));
 } finally { await browser.close(); await new Promise(resolve=>server.close(resolve)); }
})().catch(e=>{console.error(e);process.exitCode=1;});
