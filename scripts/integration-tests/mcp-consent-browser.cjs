"use strict";
const {chromium} = require(process.env.TUNN_PLAYWRIGHT_MODULE);
const fs = require("node:fs"), path = require("node:path"), assert = require("node:assert/strict");
(async () => {
  const f = JSON.parse(fs.readFileSync(0, "utf8"));
  const rules = `MAP tunn.test:${f.port} ${f.address}, MAP tools.tunn.test:${f.port} ${f.address}, MAP client.tunn.test:${f.port} ${f.address}`;
  const browser = await chromium.launch({headless:true, args:["--no-proxy-server", `--host-resolver-rules=${rules}`, `--ignore-certificate-errors-spki-list=${f.spki}`]});
  try {
    const width = f.scenario === "allow-phone" ? 390 : 1440;
    const context = await browser.newContext({viewport:{width,height:900}});
    // The browser performs real requests and follows real redirects. Refuse
    // accidental external navigation; never replace headers, HTML or responses.
    await context.route("**/*", route => {
      const u = new URL(route.request().url());
      const callback = new URL(f.callback);
      if ((["tunn.test","tools.tunn.test"].includes(u.hostname) && u.origin === new URL(f.apex.replace("tunn.test",u.hostname)).origin) || u.origin === callback.origin) return route.continue();
      return route.abort();
    });
    const page = await context.newPage(); page.setDefaultTimeout(12000);
    const cspErrors = [];
    page.on("console", message => { if(message.type() === "error") { console.log("browser:",message.text()); if (/content security policy|violates.*csp/i.test(message.text())) cspErrors.push(message.text()); } });
    await page.goto(f.login);
    await page.getByRole("button",{name:"Allow",exact:true}).waitFor();
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth),false,"consent overflow");
    assert.deepEqual(cspErrors, [], "consent CSP errors");
    if(process.env.TUNN_MCP_SCREENSHOTS) {
      fs.mkdirSync(process.env.TUNN_MCP_SCREENSHOTS,{recursive:true});
      await page.screenshot({path:path.join(process.env.TUNN_MCP_SCREENSHOTS,`consent-${f.port}-${f.scenario}.png`),fullPage:true});
    }
    const posted = page.waitForRequest(r=>r.method() === "POST" && new URL(r.url()).pathname === "/oauth/authorize");
    await page.getByRole("button",{name:f.scenario === "deny"?"Deny":"Allow",exact:true}).click();
    const request = await posted;
    const origin = (await request.allHeaders()).origin;
    console.log(JSON.stringify({origin,expected:new URL(f.apex).origin}));
    assert.equal(origin,new URL(f.apex).origin,"browser must retain the consent origin");
    await page.waitForURL(u=>u.origin === new URL(f.callback).origin && u.pathname === new URL(f.callback).pathname);
    const callback = new URL(page.url());
    assert.equal(callback.searchParams.has("code"),f.scenario !== "deny");
    if(f.scenario === "deny") assert.equal(callback.searchParams.get("error"),"access_denied");
    console.log(JSON.stringify({result:"PASS",port:f.port,scenario:f.scenario,width,realRedirect:true,headersUnmodified:true,domUnmodified:true}));
  } finally { await browser.close(); }
})().catch(error=>{console.error(error.stack);process.exitCode=1;});
