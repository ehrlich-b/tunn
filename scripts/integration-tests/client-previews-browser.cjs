const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {chromium} = require(process.env.TUNN_PLAYWRIGHT_MODULE);
const evidence = path.resolve(process.argv[2]);
(async () => {
  const browser = await chromium.launch({headless:true, executablePath:process.env.TUNN_CHROMIUM, args:['--disable-background-networking']});
  try {
    for (const width of [390,1280,1440]) {
      const page = await browser.newPage({viewport:{width,height:900},deviceScaleFactor:1});
      // Render actual handler output and stylesheet with all requests intercepted.
      await page.route('**/*', route => {
        const pathname = new URL(route.request().url()).pathname;
        if (pathname === '/client-previews') return route.fulfill({contentType:'text/html',body:fs.readFileSync(path.join(evidence,'client-previews.html'),'utf8')});
        if (pathname === '/guides.css') return route.fulfill({contentType:'text/css',body:fs.readFileSync(path.join(evidence,'guides.css'),'utf8')});
        return route.abort();
      });
      await page.goto('https://tunn.test/client-previews');
      const cta = page.getByRole('link',{name:'Set up your first preview'});
      await cta.waitFor({state:'visible'});
      const command=page.getByLabel('Named client preview command');
      assert.equal(await command.innerText(),'tunn 3000 --name north-preview --allow=client@example.com');
      const measurements=await page.evaluate(() => {
        const cmd=document.querySelector('[aria-label="Named client preview command"]');
        const cta=document.querySelector('a[href="#first-preview"]');
        const note=document.querySelector('.note');
        return {width:innerWidth,document:document.documentElement.scrollWidth,command:cmd.scrollWidth,commandBox:cmd.clientWidth,commandFont:getComputedStyle(cmd).fontSize,cta:cta.getBoundingClientRect().toJSON(),note:note.getBoundingClientRect().toJSON(),facts:note.innerText};
      });
      assert.ok(measurements.document<=width,JSON.stringify(measurements));
      assert.ok(measurements.command<=measurements.commandBox,JSON.stringify(measurements));
      assert.ok(measurements.cta.bottom<=900 && measurements.note.bottom<=900);
      assert.match(measurements.facts,/Keep both your local app and tunn running/);
      assert.match(measurements.facts,/allowed email/);
      await cta.click();
      assert.equal(new URL(page.url()).hash,'#first-preview');
      await page.evaluate(()=>scrollTo(0,0));
      await page.screenshot({path:path.join(evidence,`client-previews-${width}.png`),fullPage:true});
      fs.writeFileSync(path.join(evidence,`layout-${width}.json`),JSON.stringify(measurements,null,2));
      console.log(`PASS: ${width}px; command, CTA and privacy/keep-running facts readable; no overflow`);
      await page.close();
    }
  } finally { await browser.close(); }
})().catch(error=>{console.error(error);process.exit(1)});
