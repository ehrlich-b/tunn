'use strict';
// Offline browser checks of both rendered inspectors. The live TLS journey
// separately verifies that the publisher delivers confirmed replays once.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {chromium} = require(process.env.TUNN_INSPECT_PLAYWRIGHT_MODULE);
const evidence = path.resolve(process.argv[2]);
const root = path.resolve(__dirname,'../..');
const shared = fs.readFileSync(path.join(root,'internal/inspection/replay_validation.js'),'utf8');
const template = fs.readFileSync(path.join(evidence,'inspector-live/rendered-inspector.html'),'utf8');
const local = fs.readFileSync(path.join(root,'internal/client/inspector.html'),'utf8').replace('// REPLAY_VALIDATION',()=>shared);
assert.ok(local.includes(shared),'local fixture must preserve the embedded validator literally');
const base = {id:1,at:'2026-10-18T10:00:00Z',method:'GET',protocol:'http',path:"/hooks/customer-order-notifications-for-the-international-storefront/$&/Products(1)/a!b/a'b*c/list[0]?token=%5Bredacted%5D",
  headers:{Host:'app.test',Accept:'application/json','X-Signature':'[redacted]'},redacted_headers:['X-Signature'],query_redacted:true,
  request_bytes:4,response_bytes:2,status:202,duration_ms:12,terminal_reason:'complete',body_captured:false,body_complete:true,reconstructable:true};
const restoredPath = base.path.replace('%5Bredacted%5D','one+two%2f%ff');
const restoredHeaders = {Host:'app.test',Accept:'application/json','x-signature':'  restored\t '};
const body = 'AAH+\n/w==';
(async () => {
  fs.mkdirSync(path.join(evidence,'replay-shots'),{recursive:true});
  const browser = await chromium.launch({headless:true,args:['--disable-background-networking']});
  const results = [];
  try {
    for (const kind of ['hosted','local']) {
      const context = await browser.newContext({viewport:{width:1440,height:900}});
      const page = await context.newPage();page.setDefaultTimeout(5000);
      let events = [], posts = [], outcome = 'success';const errors = [];
      page.on('pageerror',error => errors.push(error.message));
      await page.route('**/*',async route => {
        const request = route.request(), url = new URL(request.url());
        const reply = data => route.fulfill({status:200,contentType:'application/json',body:JSON.stringify(data)});
        if (url.pathname === '/') return route.fulfill({status:200,contentType:'text/html',body:kind==='hosted'?template:local});
        if (url.pathname.endsWith('/endpoints')) return reply({endpoints:['webhooks']});
        if (url.pathname === '/api/metrics') return reply({active_streams:0,denied_admissions:0,reconnects:0,export_drops:0,history_evictions:0});
        if (url.pathname.endsWith('/requests') || url.pathname === '/api/events') return reply(kind==='hosted'?{events,session:'fixture-session',replay_supported:true}:events);
        if (url.pathname.endsWith('/prepare')) return reply({action:'fixture-action',expires_at:'2026-10-18T10:10:00Z'});
        if (url.pathname.endsWith('/replay')) {
          posts.push(request.postDataJSON());
          if (outcome === 'reject') return route.fulfill({status:409,contentType:'text/plain',body:'reconstruct every original header'});
          if (outcome === 'uncertain') return route.abort('failed');
          const replay = {...base,id:100,replay_of:1}; events.push(replay);
          return reply(kind==='hosted'?{event:replay}:replay);
        }
        return route.fulfill({status:404,body:''});
      });
      const rows = kind==='hosted'?'.request-row':'tr[data-id]';
      const button = kind==='hosted'?'#send-replay':'#replay';
      const errorBox = kind==='hosted'?'#replay-error':'#replay-errors';
      const result = kind==='hosted'?'#notice':'#result';
      async function load(volume) {
        events = Array.from({length:volume},(_,i)=>({...base,id:i+1}));
        await page.goto('http://inspector.test/');
        await page.waitForFunction(({rows,count}) => document.querySelectorAll(rows).length===count,{rows,count:Math.min(volume,8)});
      }
      async function open() {
        await page.locator(rows).last().click();
        if (kind==='hosted') {await page.locator('#prepare-replay').click();await page.locator('#replay-dialog').waitFor({state:'visible'});await page.locator('#confirm-replay').check();}
      }
      const pathField = () => kind==='hosted'?page.locator('#replay-path'):page.locator('#detail input');
      const headersField = () => kind==='hosted'?page.locator('#replay-headers'):page.locator('#detail textarea').nth(0);
      const bodyField = () => kind==='hosted'?page.locator('#replay-body'):page.locator('#detail textarea').nth(1);
      async function restore() {
        await pathField().fill(restoredPath);await headersField().fill(JSON.stringify(restoredHeaders));
        if (kind==='hosted') await page.locator('#body-format').selectOption('base64');
        await bodyField().fill(body);
      }
      for (const volume of [0,1,8,50]) {
        await load(volume);
        if (volume) await open();
        if (volume===50) assert.equal(await page.getByRole('button',{name:'+42 more',exact:true}).count(),1);
        for (const width of [390,1440]) {
          await page.setViewportSize({width,height:width===390?844:900});
          assert.equal(await page.evaluate(() => document.documentElement.scrollWidth<=innerWidth),true,kind+' overflow at '+width);
          await page.screenshot({path:path.join(evidence,'replay-shots',`${kind}-${volume}-${width}.png`),fullPage:true});
        }
      }
      await load(1);await open();
      assert.equal(await page.locator(button).isDisabled(),true);
      assert.match(await page.locator(errorBox).innerText(),/Path and query: Restore every hidden value/);
      assert.match(await page.locator(errorBox).innerText(),/Headers: Restore X-Signature/);
      assert.match(await page.locator(errorBox).innerText(),/Body: Restore the original body/);
      await restore();
      for (const [field,value,message] of [
        [headersField,'null','Headers: Enter a JSON object'],[headersField,'{}','Headers: Restore'],
        [headersField,JSON.stringify({...restoredHeaders,'x-signature':'é'.repeat(513)}),'Headers: X-Signature exceeds 1024 bytes'],
        [pathField,'/changed?token=value','Path and query: Keep the original path'],
        [pathField,'/hooks?token='+ 'é'.repeat(1100),'Path and query: Use at most 2048 bytes'],
        [bodyField,'@@@','Body: Enter valid Base64'],[bodyField,'AA==','Body: Restore exactly 4 bytes'],
        [bodyField,Buffer.alloc(65537).toString('base64'),'Body: Use at most 64 KiB']
      ]) {
        await field().fill(value);
        assert.equal(await page.locator(button).isDisabled(),true);
        assert.ok((await page.locator(errorBox).innerText()).includes(message),message);
        await page.locator(button).evaluate(button=>button.click());assert.equal(posts.length,0);
        await restore();
      }
      assert.equal(await page.locator(button).isEnabled(),true);
      await page.locator(button).evaluate(button=>{button.click();button.click();});
      await page.locator(result).getByText(kind==='hosted'?/Replay completed/:/Replay #100/).waitFor();
      assert.equal(posts.length,1);assert.equal(posts[0].path,restoredPath);assert.deepEqual(posts[0].headers,restoredHeaders);assert.equal(posts[0].body,body);
      assert.ok((await page.locator('#detail').innerText()).includes(kind==='hosted'?'replay of 1':'Replay of #1'));
      if(kind==='local')assert.equal(await page.locator('#replay').isDisabled(),true,'new replay result has unrestored fields');
      for (const mode of ['reject','uncertain']) {
        outcome=mode;await load(1);await open();await restore();await page.locator(button).click();
        await page.waitForFunction(({result,mode}) => document.querySelector(result).textContent.includes(mode==='reject'?'Request not sent.':(result==='#notice'?'may already have it':'may already have run')),{result,mode});
        const message=await page.locator(result).innerText();
        if(mode==='reject')assert.ok(!message.includes('may already'));
        if(kind==='hosted')assert.equal(await page.locator('textarea').evaluateAll(fields=>fields.some(field=>field.value.includes('restored'))),false,'raw reconstructed headers retained');
        assert.equal(await page.evaluate(()=>JSON.stringify({...localStorage,...sessionStorage}).includes('restored')),false,'reconstruction persisted in browser storage');
      }
      assert.deepEqual(errors,[]);
      results.push({kind,result:'PASS',invalid_posts:0,valid_posts:1,byte_preserving:true,known_rejection_not_sent:true,transport_uncertain:true,volumes:[0,1,8,50],widths:[390,1440]});
      await context.close();
    }
    fs.writeFileSync(path.join(evidence,'replay-browser.json'),JSON.stringify(results,null,2)+'\n');console.log(JSON.stringify(results));
  } finally {await browser.close();}
})().catch(error=>{console.error(error.stack);process.exitCode=1;});
