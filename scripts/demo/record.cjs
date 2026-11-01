"use strict";
const {chromium} = require(process.env.TUNN_PLAYWRIGHT_MODULE || '/work/cache/bs-0k78wi2i/web/node_modules/playwright');
const readline = require('readline');
(async () => {
 let browser, input;
 try {
 browser = await chromium.launch({headless:true,args:['--no-proxy-server','--host-resolver-rules=MAP *.tunn.local.127.0.0.1.nip.io 127.0.0.1, MAP tunn.local.127.0.0.1.nip.io 127.0.0.1']});
 const context = await browser.newContext({viewport:{width:390,height:844},ignoreHTTPSErrors:true,recordVideo:{dir:process.argv[2],size:{width:390,height:844}}});
 await context.route('**/*', route => {const u=new URL(route.request().url()); return (u.hostname==='127.0.0.1'||u.hostname==='tunn.local.127.0.0.1.nip.io'||u.hostname.endsWith('.tunn.local.127.0.0.1.nip.io'))?route.continue():route.abort();});
 const page = await context.newPage(); page.setDefaultTimeout(15000);
 await page.setContent('<body style="background:#111;color:#eee;font:16px monospace;white-space:pre-wrap;overflow-wrap:anywhere;padding:12px"><pre style="white-space:pre-wrap;overflow-wrap:anywhere"></pre></body>');
 await page.locator('pre').textContent();
 console.log('ready');
 input = readline.createInterface({input:process.stdin});
 for await (const line of input) {
  const event=JSON.parse(line);
  if(event.type==='terminal') { await page.setContent('<body style="background:#111;color:#eee;font:16px monospace;white-space:pre-wrap;overflow-wrap:anywhere;padding:12px"><pre style="white-space:pre-wrap;overflow-wrap:anywhere"></pre></body>'); await page.locator('pre').evaluate((e,t)=>e.textContent=t,event.text); await page.waitForTimeout(1200); }
  if(event.type==='login') { await page.goto(event.url); await page.waitForTimeout(500); await page.getByText('Continue with Mock Login').click(); await page.waitForTimeout(500); await page.getByRole('button',{name:'Authorize',exact:true}).click(); }
  if(event.type==='consent') { await page.goto(event.url); await page.getByRole('button',{name:'Allow',exact:true}).waitFor(); await page.waitForTimeout(800); await page.getByRole('button',{name:'Allow',exact:true}).click(); await page.waitForURL(u=>u.hostname==='127.0.0.1'); }
  console.log('ok');
 }
 const video=page.video(); await context.close(); console.log(await video.path());
 } finally { if (input) input.close(); process.stdin.pause(); if (browser) await browser.close(); }
})().catch(e=>{console.error(e); process.exitCode=1;});
