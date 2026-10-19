'use strict';
// Local TLS fixture only. Requires an existing Playwright module; no downloads.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {chromium} = require(process.env.TUNN_INSPECT_PLAYWRIGHT_MODULE);
const port = process.argv[2], evidence = path.resolve(process.argv[3]);
const apex = `https://tunn.test:${port}`, resource = `https://webhooks.tunn.test:${port}`;
(async () => {
  const browser = await chromium.launch({headless:true,args:['--no-proxy-server','--disable-background-networking','--host-resolver-rules=MAP *.tunn.test 127.0.0.1, MAP tunn.test 127.0.0.1']});
  try {
    async function person(email, viewport = {width:1440,height:900}) {
      const context = await browser.newContext({ignoreHTTPSErrors:true,viewport}); context.setDefaultTimeout(7000);
      await context.route('**/auth/google?*', async route => {
        const url = new URL(route.request().url()); url.hostname = '127.0.0.1';
        const response = await route.fetch({url:url.href,headers:{...route.request().headers(),host:`tunn.test:${port}`},maxRedirects:0});
        const consent = new URL(response.headers().location), callback = new URL(consent.searchParams.get('redirect_uri'));
        callback.searchParams.set('state',consent.searchParams.get('state')); callback.searchParams.set('code',email);
        const headers = {...response.headers(),'content-type':'text/html'}; delete headers.location; delete headers['content-length'];
        await route.fulfill({response,status:200,headers,body:`<h1>Fixture consent</h1><a href="${callback.href.replaceAll('&','&amp;')}">Approve verified email</a>`});
      });
      const page = await context.newPage();
      await page.goto(apex+'/account');
      await page.getByRole('link',{name:'Continue with Google'}).click();
      await page.getByRole('link',{name:'Approve verified email'}).click();
      await page.getByRole('heading',{name:'Account',exact:true}).waitFor();
      return {context,page};
    }
    // Node's API client does not inherit Chromium's host-resolver rules.
    // Connect only to loopback, retaining the actual request authority and the
    // normal cookies acquired through the verified browser login.
    async function fixtureRequest(context, target, options = {}) {
      const url = new URL(target), host = url.host;
      const cookies = await context.cookies(target); url.hostname = '127.0.0.1';
      return context.request.fetch(url.href,{...options,headers:{...options.headers,Host:host,Cookie:cookies.map(cookie => cookie.name+'='+cookie.value).join('; ')},maxRedirects:0});
    }
    const {context,page} = await person('owner@example.com');
    let browserErrors = []; page.on('pageerror',error => browserErrors.push(error.message));
    await page.getByRole('link',{name:'Open request inspector'}).click();
    await page.getByRole('heading',{name:'Request inspector',exact:true}).waitFor();
    await page.waitForFunction(() => document.querySelector('#endpoint').value === 'webhooks');
    await page.locator('#requests').getByText('No requests yet',{exact:true}).waitFor();
    const body = '{"event":"delivery","body_secret":"BODY_PAYLOAD_SENTINEL","unicode":"é"}\r\n';
    const sent = {headers:{'Content-Type':'application/json','User-Agent':'inspector-fixture','X-Signature':'HEADER_SENTINEL','Accept':'<img src=x onerror="window.inspectorXss=1">'},data:body};
    for (const target of ['/health','/missing','/failing','/hooks?token=QUERY_SENTINEL','/hooks?token=QUERY_SENTINEL']) {
      const headers = {...sent.headers,Accept:target === '/health' ? sent.headers.Accept : 'application/json'};
      const response = await fixtureRequest(context,resource+target,{...sent,headers,method:'POST'}); assert.ok([200,202,404,500].includes(response.status()));
    }
    await page.getByRole('button',{name:'Refresh',exact:true}).click();
    await page.waitForFunction(() => document.querySelectorAll('.request-row').length === 5);
    await page.locator('.request-row').last().click();
    assert.ok((await page.locator('#detail').innerText()).includes('<img src=x onerror='));
    assert.equal(await page.locator('#detail img').count(),0,'request content rendered as HTML');
    await page.locator('.request-row').first().click();
    await page.getByRole('button',{name:'Prepare replay',exact:true}).waitFor();
    let rendered = await page.locator('main').innerText();
    for (const secret of ['QUERY_SENTINEL','HEADER_SENTINEL','BODY_PAYLOAD_SENTINEL','RESPONSE_PAYLOAD_SENTINEL']) assert.ok(!rendered.includes(secret),'rendered secret '+secret);
    assert.equal(await page.evaluate(() => window.inspectorXss),undefined);
    assert.equal(await page.locator('#detail img').count(),0,'request content rendered as HTML');
    const listingResponse = await fixtureRequest(context,apex+'/api/inspector/webhooks/requests'); assert.equal(listingResponse.status(),200); assert.equal(listingResponse.headers()['cache-control'],'no-store');
    const listing = await listingResponse.json(), original = listing.events.at(-1);
    assert.equal(listing.events.length,5); assert.equal(original.body,undefined); assert.equal(original.body_captured,false);
    await page.screenshot({path:path.join(evidence,'inspector-1440x900.png')});
    await page.setViewportSize({width:390,height:844});
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth),true,'mobile horizontal overflow');
    await page.screenshot({path:path.join(evidence,'inspector-390x844.png')});
    await page.locator('#detail').scrollIntoViewIfNeeded();
    await page.screenshot({path:path.join(evidence,'inspector-detail-390x844.png')});
    await page.setViewportSize({width:1440,height:900});
    await page.getByRole('button',{name:'Prepare replay',exact:true}).click();
    await page.locator('#replay-dialog').waitFor({state:'visible'});
    assert.equal(await page.getByRole('button',{name:'Replay once',exact:true}).isDisabled(),true,'confirmation not required');
    fs.writeFileSync(path.join(evidence,'rendered-inspector.html'),await page.content());
    let rejectedPosts = 0;
    page.on('request', request => {if (request.method() === 'POST' && request.url().endsWith('/replay')) rejectedPosts++;});
    await page.locator('#confirm-replay').check();
    assert.equal(await page.locator('#send-replay').isDisabled(),true,'hidden values enabled replay');
    assert.match(await page.locator('#replay-error').innerText(),/Path and query: Restore every hidden value/);
    assert.match(await page.locator('#replay-error').innerText(),/Headers: Restore /);
    assert.match(await page.locator('#replay-error').innerText(),/Body: Restore the original body/);
    assert.equal(rejectedPosts,0);
    const headers = {...original.headers};
    for (const key of Object.keys(headers)) if (headers[key] === '[redacted]') {
      if (key === 'X-Signature') headers[key] = 'HEADER_SENTINEL';
      else if (key === 'User-Agent') headers[key] = 'inspector-fixture';
      else if (key === 'Connection') headers[key] = 'keep-alive';
      else throw new Error('fixture must explicitly restore '+key);
    }
    await page.locator('#replay-path').fill('/hooks?token=QUERY_SENTINEL');
    await page.locator('#replay-headers').fill(JSON.stringify(headers,null,2));
    await page.locator('#replay-body').fill(body);
    const validFields = {path:'/hooks?token=QUERY_SENTINEL',headers:JSON.stringify(headers,null,2),body};
    for (const [field,value,error] of [
      ['headers','{','Headers: Enter a JSON object'],
      ['headers','null','Headers: Enter a JSON object'],
      ['headers','{}','Headers: Restore'],
      ['headers',JSON.stringify({...headers,'X-Signature':'x'.repeat(1025)}),'Headers: X-Signature exceeds 1024 bytes.'],
      ['path','/hooks?other=value','Path and query: Keep every original query field.'],
      ['path','/hooks?token='+ 'é'.repeat(1100),'Path and query: Use at most 2048 bytes.'],
      ['body','x'.repeat(65537),'Body: Use at most 64 KiB.'],
      ['body','x','Body: Restore exactly']
    ]) {
      await page.locator('#replay-'+field).fill(value);
      assert.equal(await page.locator('#send-replay').isDisabled(),true,error);
      assert.ok((await page.locator('#replay-error').innerText()).includes(error));
      await page.locator('#send-replay').evaluate(button => button.click());
      assert.equal(rejectedPosts,0,'invalid fields made a replay POST');
      await page.locator('#replay-'+field).fill(validFields[field]);
    }
    await page.locator('#body-format').selectOption('base64');
    await page.locator('#replay-body').fill('@@@');
    assert.match(await page.locator('#replay-error').innerText(),/Body: Enter valid Base64/);
    assert.equal(await page.locator('#send-replay').isDisabled(),true);
    await page.locator('#replay-body').fill(Buffer.from(body).toString('base64'));
    assert.equal(await page.locator('#send-replay').isEnabled(),true);
    await page.locator('#confirm-replay').check();
    let replayPosts = 0;
    page.on('request',request => {if (request.method() === 'POST' && request.url().endsWith('/replay')) replayPosts++;});
    await page.screenshot({path:path.join(evidence,'inspector-confirm-1440x900.png')});
    await page.locator('#send-replay').evaluate(button => {button.click();button.click();});
    await page.locator('#notice').getByText(/Replay completed: HTTP 202/).waitFor();
    assert.equal(replayPosts,1,'double click replayed twice');
    assert.equal(rejectedPosts,1,'validation attempts sent a replay');
    const after = await (await fixtureRequest(context,apex+'/api/inspector/webhooks/requests')).json();
    assert.equal(after.events.length,6); assert.equal(after.events.at(-1).replay_of,original.id); assert.equal(after.events.at(-1).status,202);
    assert.equal(await page.locator('#replay-body').inputValue(),'','reconstruction retained after closing');
    const duplicate = await fixtureRequest(context,apex+`/api/inspector/webhooks/requests/${original.id}/replay`,{method:'POST',headers:{Origin:apex,'X-Tunn-CSRF':await page.locator('meta[name="inspector-csrf"]').getAttribute('content')},data:{session:listing.session,action:'already-used',confirmed:true}});
    assert.equal(duplicate.status(),409);
    const wrongOrigin = await fixtureRequest(context,apex+`/api/inspector/webhooks/requests/${original.id}/prepare`,{method:'POST',headers:{Origin:resource,'X-Tunn-CSRF':await page.locator('meta[name="inspector-csrf"]').getAttribute('content')},data:{session:listing.session}});
    assert.equal(wrongOrigin.status(),403);
    const anon = await browser.newContext({ignoreHTTPSErrors:true});
    assert.equal((await fixtureRequest(anon,apex+'/api/inspector/webhooks/requests')).status(),401);await anon.close();
    const stranger = await person('stranger@example.com');
    assert.equal((await fixtureRequest(stranger.context,apex+'/api/inspector/webhooks/requests')).status(),403);await stranger.context.close();
    // A handler may start redirecting after its original delivery. The replay
    // must report that redirect without contacting another configured fixture.
    assert.equal((await fixtureRequest(context,resource+'/redirect-on-replay',{headers:{'User-Agent':'inspector-fixture',Accept:'application/json'}})).status(),202);
    await page.getByRole('button',{name:'Refresh',exact:true}).click();
    await page.waitForFunction(() => document.querySelectorAll('.request-row').length === 7);
    await page.locator('.request-row').first().click();
    const redirectHistory = await (await fixtureRequest(context,apex+'/api/inspector/webhooks/requests')).json();
    const redirectEvent = redirectHistory.events.at(-1);
    await page.getByRole('button',{name:'Prepare replay',exact:true}).click();
    await page.locator('#replay-dialog').waitFor({state:'visible'});
    const redirectHeaders = {...redirectEvent.headers};
    for (const key of Object.keys(redirectHeaders)) if (redirectHeaders[key] === '[redacted]') {
      if (key === 'User-Agent') redirectHeaders[key] = 'inspector-fixture';
      else if (key === 'Connection') redirectHeaders[key] = 'keep-alive';
      else throw new Error('fixture must explicitly restore '+key);
    }
    await page.locator('#replay-headers').fill(JSON.stringify(redirectHeaders,null,2));
    await page.locator('#confirm-replay').check();
    await page.getByRole('button',{name:'Replay once',exact:true}).click();
    await page.locator('#notice').getByText(/Replay completed: HTTP 307/).waitFor();
    const redirectAfter = await (await fixtureRequest(context,apex+'/api/inspector/webhooks/requests')).json();
    assert.equal(redirectAfter.events.at(-1).replay_of,redirectEvent.id);
    assert.equal(redirectAfter.events.at(-1).status,307);
    assert.equal(redirectAfter.events.length,8);
    await page.route('**/api/inspector/webhooks/requests',route => route.fulfill({status:503,contentType:'text/plain',body:'Endpoint offline. Its request list cleared when the tunnel disconnected.'}));
    await page.getByRole('button',{name:'Refresh',exact:true}).click();
    await page.locator('#notice').getByText(/Endpoint offline/).waitFor();
    assert.equal(await page.locator('.request-row').count(),0,'stale traffic remained after offline response');
    await page.unroute('**/api/inspector/webhooks/requests');
    await page.getByRole('button',{name:'Refresh',exact:true}).click();
    await page.waitForFunction(() => document.querySelectorAll('.request-row').length === 8);
    assert.deepEqual(browserErrors,[]);
    const receipt = {result:'PASS',entry:'verified fixture Google login → Account → inspector',transport:'real TLS relay + gRPC publisher + HTTP origin',provider:'Google consent/token service fixture',original_requests:6,confirmed_replays:2,double_click_posts:1,replay_requests:replayPosts,origin_redirect_status:307,anonymous:401,wrong_owner:403,foreign_origin:403,duplicate_action:409,mobile_overflow:false,payloads_retained:false,invalid_field_posts:0,field_validation:'markers, malformed/missing/oversized fields, binary Base64; explicit one-use replay',screenshots:['inspector-1440x900.png','inspector-390x844.png','inspector-detail-390x844.png','inspector-confirm-1440x900.png']};
    fs.writeFileSync(path.join(evidence,'browser-checks.json'),JSON.stringify(receipt,null,2)+'\n');
    console.log(JSON.stringify(receipt));
  } finally {await browser.close();}
})().catch(error => {console.error(String(error.message).split('\n')[0]);process.exitCode=1;});
