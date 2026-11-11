// The Python entrypoint and Go fixture launch this worker; no hosted service is used.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {chromium} = require(process.env.TUNN_PLAYWRIGHT_MODULE || 'playwright');
const input = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
const {apex, period, width, email, output} = input;
const run = `${period}-${width}`;
(async () => {
  const browser = await chromium.launch({headless:true, args:[
    '--no-proxy-server', '--disable-background-networking',
    `--host-resolver-rules=MAP tunn.test 127.0.0.1, MAP buy.stripe.com 127.0.0.1:${new URL(apex).port}, MAP * ~NOTFOUND`,
  ]});
  try {
    const context = await browser.newContext({ignoreHTTPSErrors:true,
      viewport:{width,height:900}, serviceWorkers:'block'});
    context.setDefaultTimeout(12000);
    const blocked = [], checkoutRedirects = [], errors = [], steps = [], responses = [];
    await context.route('**/*', async route => {
      const url = new URL(route.request().url());
      if (url.origin === apex) return route.continue();
      // Every permitted hostname resolves to the loopback TLS fixture.
      if (url.origin === 'https://buy.stripe.com' && url.pathname === `/${period}_fixture`) {
        assert.ok(url.searchParams.get('client_reference_id'));
        assert.equal(url.searchParams.get('prefilled_email'), email);
        return route.continue();
      }
      blocked.push(url.href);
      await route.abort('blockedbyclient');
    });
    const page = await context.newPage();
    page.on('request', request => {
      const url = new URL(request.url());
      if (url.origin === 'https://buy.stripe.com') {
        assert.equal(url.pathname,`/${period}_fixture`);
        assert.ok(url.searchParams.get('client_reference_id'));
        assert.equal(url.searchParams.get('prefilled_email'),email);
        checkoutRedirects.push(url.href);
      }
    });
    page.on('dialog', dialog => {errors.push('unexpected dialog: '+dialog.type()); dialog.dismiss();});
    page.on('pageerror', error => errors.push(String(error)));
    page.on('response', response => {
      const url = new URL(response.url());
      responses.push({path:url.pathname,status:response.status()});
    });
    async function capture(name, facts={}) {
      const screenshot = `${run}-${name}.png`;
      await page.screenshot({path:path.join(output,screenshot),fullPage:true});
      steps.push({name,url:page.url(),screenshot,...facts});
    }
    assert.equal((await page.goto(apex+'/pricing')).status(),200);
    await page.getByRole('link',{name:`Go Pro ${period}`,exact:true}).waitFor();
    const monthlyOffer = (await page.locator('.plan-pro .price').innerText()).trim();
    const yearlyOffer = (await page.locator('.plan-pro .plan-billing').innerText()).trim();
    assert.match(monthlyOffer,/\$5\s*\/ month/);
    assert.equal(yearlyOffer,'or $48 / year');
    await capture('pricing',{monthly_offer:monthlyOffer,yearly_offer:yearlyOffer});
    await page.getByRole('link',{name:`Go Pro ${period}`,exact:true}).click();
    await page.waitForURL('**/auth/login?**');
    assert.equal(new URL(page.url()).searchParams.get('return_to'),`/upgrade?period=${period}`);
    await capture('go-pro-sign-in',{return_to:`/upgrade?period=${period}`});
    await page.getByLabel('Email',{exact:true}).fill(email);
    await page.getByRole('button',{name:'Email me a link',exact:true}).click();
    await page.getByText('Link sent. Check your email.',{exact:true}).waitFor();
    await capture('sign-in-link-sent',{email});
    const mail = await page.evaluate(async () => {
      const response = await fetch('/_fixture/mail');
      if (response.status !== 200) throw new Error('fixture delivery failed');
      return response.json();
    });
    assert.equal(mail.to,email);
    assert.equal(new URL(mail.link).origin,apex);
    // Delivery is local; token verification, cookies and return_to are real.
    assert.equal((await page.goto(mail.link)).status(),200);
    await page.getByRole('heading',{name:'Fixture checkout',exact:true}).waitFor();
    assert.equal(checkoutRedirects.length,1);
    await page.getByText(`Pro ${period}`,{exact:true}).waitFor();
    await page.getByText(period==='monthly'?'$5/month':'$48/year',{exact:true}).waitFor();
    await capture('fixture-checkout',{before_plan:'free',provider_redirect_mapped_to_loopback:true});
    await page.getByRole('button',{name:'Pay fixture',exact:true}).click();
    await page.getByRole('heading',{name:'Fixture payment received',exact:true}).waitFor();
    await capture('signed-webhook',{http_status:200,state:'reconciled',receipt:run+'-webhook.json'});
    await page.getByRole('link',{name:'Return to account',exact:true}).click();
    await page.waitForURL('**/account?billing=return');
    assert.equal((await page.locator('.who .plan-pro').innerText()).trim(),'pro');
    assert.match((await page.locator('#billing-status').innerText()).trim(),/^Pro is on\./);
    const status = await page.evaluate(async () => {
      const response = await fetch('/api/billing/status');
      if (response.status !== 200) throw new Error('billing status failed');
      return response.json();
    });
    assert.equal(status.plan,'pro');
    assert.equal(status.state,'active');
    await capture('return-account-pro',{expected_plan:'pro',actual_plan:status.plan,state:status.state});
    assert.deepEqual(blocked,[],'unexpected external request');
    assert.deepEqual(errors,[],'browser error or dialog');
    assert.ok(responses.some(r=>r.path==='/upgrade' && r.status===302),'missing anonymous sign-in redirect');
    assert.ok(responses.some(r=>r.path==='/auth/verify' && r.status===302),'missing real magic-link verification');
    assert.ok(responses.some(r=>r.path==='/upgrade' && r.status===303),'missing authenticated checkout redirect');
    assert.ok(responses.every(r=>r.status<400),'failed page or asset request');
    fs.writeFileSync(path.join(output,run+'-browser.json'),JSON.stringify({result:'PASS',period,width,steps,
      checkout_redirects:checkoutRedirects,blocked_external_requests:blocked,browser_errors:errors,responses},null,2)+'\n');
    await context.close();
    console.log(`PASS ${run}: pricing → sign-in → fixture checkout → signed webhook → account Pro`);
  } finally { await browser.close(); }
})().catch(error=>{console.error(error);process.exitCode=1;});
