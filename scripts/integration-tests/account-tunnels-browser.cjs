const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {chromium} = require(process.env.TUNN_ACCOUNT_TUNNELS_PLAYWRIGHT_MODULE);
const port = process.argv[2], evidence = path.resolve(process.argv[3]);
const schedule = process.env.TUNN_ACCOUNT_TUNNELS_POLL_SCHEDULE || 'normal';
assert.ok(['normal','delayed'].includes(schedule), `unknown poll schedule: ${schedule}`);
const apex = `https://tunn.test:${port}`;
(async () => {
  const browser = await chromium.launch({headless:true,args:['--no-proxy-server','--disable-background-networking','--host-resolver-rules=MAP *.tunn.test 127.0.0.1, MAP tunn.test 127.0.0.1']});
  try {
    async function person(email) {
      const context = await browser.newContext({ignoreHTTPSErrors:true,viewport:{width:1440,height:1000}});
      context.setDefaultTimeout(12000);
      await context.exposeBinding('pollTrace',(_,event)=>fs.appendFileSync(path.join(evidence,'ordering.jsonl'),JSON.stringify({email,...event})+'\n'));
      await context.addInitScript(() => {
        const nativeFetch = window.fetch.bind(window);
        const state = window.__accountPolls = {generation:0, requests:[], events:[]};
        function event(record, phase) {
          state.events.push({generation:record.id, phase, time:Date.now()});
          window.pollTrace?.({generation:record.id, phase, time:Date.now()});
        }
        window.fetch = async (...args) => {
          if (String(args[0]) !== '/api/account/tunnels') return nativeFetch(...args);
          const record = {id:++state.generation, settled:false, hold:state.holdNext};
          state.holdNext = undefined; state.requests.push(record);
          event(record,'request');
          const finish = () => {
            // A browser task runs after the fetch/json promise continuations, including
            // refresh's render and finally. It also runs while the fake clock is paused.
            const channel = new MessageChannel();
            channel.port1.onmessage = () => {
              record.aborted = args[1]?.signal?.aborted || false;
              record.dom = {names:Array.from(document.querySelectorAll('.live-tunnel-name'),n=>n.textContent), summary:document.querySelector('#live-tunnels-summary')?.textContent, stale:!document.querySelector('#live-tunnels-stale')?.hidden};
              record.settled = true; event(record,'settled');
              channel.port1.close(); channel.port2.close();
            };
            channel.port2.postMessage(null);
          };
          const holdBody = async () => {
            if (!record.hold) return;
            // Headers and JSON have arrived, but refresh still owns its controller.
            // Release in a browser task after visibility's abort/refresh guard, even
            // when update() uses the old ordering and never calls settleActive().
            await new Promise(resolve => {
              state.held = record.id;
              let releasing = false;
              const release = () => {
                if (releasing) return;
                releasing = true;
                document.removeEventListener('visibilitychange',visible);
                const channel = new MessageChannel();
                channel.port1.onmessage = () => {
                  event(record,'release'); state.held = undefined; state.releaseHeld = undefined; resolve();
                  channel.port1.close(); channel.port2.close();
                };
                channel.port2.postMessage(null);
              };
              const visible = () => { event(record,'visibility-while-held'); release(); };
              state.releaseHeld = release;
              document.addEventListener('visibilitychange',visible,{once:true});
              event(record,'body-held');
            });
          };
          try {
            const response = await nativeFetch(...args);
            record.status = response.status; event(record,'response');
            if (!response.ok) { await holdBody(); finish(); return response; }
            const json = response.json.bind(response);
            response.json = async () => {
              try { const data = await json(); await holdBody(); return data; }
              finally { event(record,'body'); finish(); }
            };
            return response;
          } catch (error) { record.error = error.name; event(record,'rejected'); finish(); throw error; }
        };
      });
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
    async function settled(page, generation) {
      await page.waitForFunction(id => {
        const state = window.__accountPolls;
        return state.requests.every(r=>r.settled) && (id === undefined || state.requests.some(r=>r.id===id && r.settled));
      }, generation);
    }
    const {context,page} = await person('owner@example.com');
    const errors = []; page.on('pageerror',error => errors.push(error.message));
    await page.locator('#live-tunnels-empty').waitFor({state:'visible'});
    await page.locator('#start-tunnel').waitFor({state:'visible'});
    // A known online connection suppresses onboarding even when a peer is down.
    // Show proven partial rows and identify uncertainty until all peers recover.
    await page.route('**/api/account/tunnels',route=>route.fulfill({json:{complete:false,tunnels:[{
      name:'known-online',public_url:'https://known-online.example.test',kind:'HTTP',connected_since:new Date().toISOString()
    }]}}));
    await settled(page);
    const partial = await page.evaluate(()=>{ document.dispatchEvent(new Event('visibilitychange')); return window.__accountPolls.generation; });
    await settled(page, partial);
    await page.locator('#start-tunnel').waitFor({state:'detached'});
    assert.equal(await page.locator('.live-tunnel').count(),1,'proven partial row missing');
    assert.match(await page.locator('.live-tunnel-name').innerText(),/known-online/);
    assert.match(await page.locator('#live-tunnels-summary').innerText(),/Partial list/);
    await page.unroute('**/api/account/tunnels');
    const recovered = page.waitForResponse(r=>r.url().endsWith('/api/account/tunnels'));
    await page.evaluate(()=>document.dispatchEvent(new Event('visibilitychange'))); await recovered;
    await page.waitForFunction(()=>document.querySelectorAll('.live-tunnel').length===0);
    assert.equal(await page.locator('#live-tunnels-summary').innerText(),'None online');

    await page.screenshot({path:path.join(evidence,'account-empty-1440.png'),fullPage:true});
    await page.evaluate(() => { window.accountPageIdentity = 'preserved'; });
    assert.equal((await request(context,apex+'/_fixture/connect',{method:'POST'})).status(),204);
    await page.locator('.live-tunnel').waitFor();
    assert.equal(await page.locator('#start-tunnel').count(),0,'onboarding remains after connecting');
    assert.equal(await page.locator('.gauges .gauge').count(),2,'usage meters missing');
    assert.match(await page.locator('.live-tunnel').innerText(),/webhooks/);
    assert.match(await page.locator('.live-tunnel').innerText(),/HTTP/);
    await page.locator('.live-tunnel-name').click();
    assert.match(await page.locator('.live-tunnel').innerText(),/1\.2\.3/);
    assert.match(await page.locator('.live-tunnel').innerText(),/linux\/amd64/);
    assert.equal((await request(context,`https://webhooks.tunn.test:${port}/health`)).status(),200);
    await page.waitForFunction(() => /Last request (now|\d+[mhd] ago)/.test(document.querySelector('.live-tunnel-details').textContent));
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
    const signInShots = [];
    const signIn = await anonymous.newPage();
    await signIn.goto(apex+'/auth/login');
    for (const theme of ['light','dark']) for (const width of [390,1440]) {
      await signIn.emulateMedia({colorScheme:theme}); await signIn.setViewportSize({width,height:1000});
      assert.equal(await signIn.evaluate(() => document.documentElement.scrollWidth <= innerWidth),true);
      const file = `signin-${width}-${theme}.png`; await signIn.screenshot({path:path.join(evidence,file),fullPage:true}); signInShots.push(file);
    }
    await anonymous.close(); await other.context.close();
    let polls = 0; page.on('request',r => { if (r.url().endsWith('/api/account/tunnels')) polls++; });
    await settled(page);
    // Dispatch the browser visibility event deterministically in headless mode.
    await page.evaluate(() => { Object.defineProperty(document,'hidden',{configurable:true,value:true}); document.dispatchEvent(new Event('visibilitychange')); });
    await page.waitForTimeout(5500); assert.equal(polls,0,'polling continued while hidden');
    const resumed = await page.evaluate(() => { Object.defineProperty(document,'hidden',{configurable:true,value:false}); document.dispatchEvent(new Event('visibilitychange')); return window.__accountPolls.generation; });
    await settled(page, resumed);
    await page.waitForFunction(() => document.querySelector('.live-tunnel'));
    assert.ok(polls>0,'polling did not resume');
    assert.equal((await request(context,apex+'/_fixture/disconnect',{method:'POST'})).status(),204);
    await page.locator('#live-tunnels-empty').waitFor({state:'visible'});
    assert.equal(await page.locator('.live-tunnel').count(),0);
    assert.equal(await page.locator('#start-tunnel').count(),0,'onboarding returned after disconnecting');
    assert.equal(await page.evaluate(() => window.accountPageIdentity),'preserved','page reloaded');
    assert.deepEqual(errors,[]);
    await page.screenshot({path:path.join(evidence,'account-disconnected-390.png'),fullPage:true});
    // Exercise the production renderer with deterministic account snapshots.
    // The journey above uses real authenticated endpoints and publisher connections.
    await settled(page);
    await page.clock.install({time:new Date('2026-10-17T20:00:00Z')});
    await page.clock.pauseAt(new Date('2026-10-17T20:00:01Z'));
    await settled(page);
    const names = ['forge-ssh','ehrlich-grafana','ehrlich-dash','apps-dash','apps-grafana','apps-home','apps-pmo','webhooks'];
    function fixture(count) {
      return Array.from({length:count}, (_,i) => ({
        name:names[i] || `regional-background-worker-${String(i+1).padStart(2,'0')}`,
        kind:['TCP','HTTP','HTTP','app','app','app','MCP','HTTP'][i%8],
        public_url:i===0 ? 'https://forge-ssh.development-infrastructure.example.test' : `https://${names[i] || `regional-background-worker-${i+1}`}.personal-applications.example.test${i%8===6?'/mcp':''}`,
        connected_since:new Date(Date.UTC(2026,9,17,18)-i*3600000).toISOString(),
        client_version:'1.2.3',client_host:'linux/amd64',
        last_request:i===count-1 ? undefined : new Date(Date.UTC(2026,9,17,19,59)-Math.floor(i/2)*60000).toISOString()
      })).reverse();
    }
    let data = {complete:true,tunnels:[]}, failed = false;
    await page.route('**/api/account/tunnels',async route => {
      // Snapshot at request time; changing the next inventory cannot change an
      // already-active response or let its completion stand in for a new poll.
      const reply = failed ? {status:503,body:'Unavailable'} : {json:structuredClone(data)};
      await route.fulfill(reply);
    });
    async function settleActive() {
      await page.evaluate(() => {
        const state = window.__accountPolls;
        if (state.held !== undefined) {
          const record = state.requests.find(r=>r.id===state.held);
          if (record.hold === 'failed') document.dispatchEvent(new Event('visibilitychange'));
          else state.releaseHeld();
        }
      });
      await settled(page);
    }
    async function update() {
      await settleActive();
      const expected = failed || !data.complete ? await page.locator('.live-tunnel-name').allTextContents() :
        [...data.tunnels].sort((a,b)=>(Date.parse(b.last_request)||0)-(Date.parse(a.last_request)||0) || a.name.localeCompare(b.name)).map(t=>t.name);
      const generation = await page.evaluate(() => {
        const before = window.__accountPolls.generation;
        document.dispatchEvent(new Event('visibilitychange'));
        return {before, after:window.__accountPolls.generation};
      });
      assert.equal(generation.after,generation.before+1,'update did not start its own poll');
      await settled(page, generation.after);
      await page.waitForFunction(({id,names}) => {
        const record = window.__accountPolls.requests.find(r=>r.id===id);
        const actual = Array.from(document.querySelectorAll('.live-tunnel-name'),n=>n.textContent);
        return record?.settled && JSON.stringify(record.dom.names)===JSON.stringify(names) &&
          JSON.stringify(actual)===JSON.stringify(names) &&
          document.querySelector('#live-tunnels-summary').textContent===(names.length?`${names.length} online`:'None online');
      }, {id:generation.after,names:expected});
    }
    async function advance(milliseconds) {
      await settleActive();
      await page.clock.fastForward(milliseconds);
      // fastForward can return after a timer starts fetch but before its body,
      // render and finally. Drain that generation before the next visibility.
      await settleActive();
    }
    async function delayedPoll(label, milliseconds) {
      if (schedule !== 'delayed') {
        if (milliseconds !== undefined) await advance(milliseconds);
        return;
      }
      await settled(page);
      await page.evaluate(label => { window.__accountPolls.holdNext = label; },label);
      if (milliseconds === undefined) {
        await page.evaluate(() => document.dispatchEvent(new Event('visibilitychange')));
      } else {
        // Leave this timer's body active for update() to encounter. The fixture's
        // release listener is independent of both update() and advance().
        await page.clock.fastForward(milliseconds);
      }
      await page.waitForFunction(() => window.__accountPolls.held !== undefined);
    }
    const shots = [], metrics = [];
    for (const count of [0,1,8,30]) {
      data = {complete:true,tunnels:fixture(count)};
      await update();
      await page.waitForFunction(n => document.querySelectorAll('.live-tunnel').length===n,count);
      assert.equal(await page.locator('#live-tunnels-summary').innerText(),count?`${count} online`:'None online');
      assert.equal(await page.locator('.live-tunnel:visible').count(),Math.min(4,count));
      assert.equal(await page.locator('.live-tunnel details[open]').count(),0);
      if (count>4) assert.equal(await page.locator('#live-tunnels-more').innerText(),`+${count-4} more`);
      const sorted = [...data.tunnels].sort((a,b) => (Date.parse(b.last_request)||0)-(Date.parse(a.last_request)||0) || a.name.localeCompare(b.name));
      assert.deepEqual(await page.locator('.live-tunnel-name').allTextContents(),sorted.map(t=>t.name));
      for (const theme of ['light','dark']) for (const width of [390,1440]) {
        await page.emulateMedia({colorScheme:theme}); await page.setViewportSize({width,height:1000});
        await page.evaluate(() => scrollTo(0,0));
        const measurement = await page.locator('.live-tunnels').evaluate(section => ({height:section.getBoundingClientRect().height,width:section.getBoundingClientRect().width,overflow:document.documentElement.scrollWidth>innerWidth}));
        assert.equal(measurement.overflow,false,'horizontal overflow');
        assert.ok(measurement.height <= (width===390?420:260),`section height ${measurement.height} at ${width}, count ${count}`);
        for (const row of await page.locator('.live-tunnel:visible summary').all()) {
          const box = await row.boundingBox(); assert.ok(box.height <= (width===390?58:22),'row wraps beyond design');
        }
        const text = await page.locator('.live-tunnels').innerText();
        assert.doesNotMatch(text,/polling|interval|tab|cach|every.*second|retrying|currently connected/i);
        const file = `tunnels-${count}-${width}-${theme}.png`;
        await page.screenshot({path:path.join(evidence,file),fullPage:true});
        shots.push(file); metrics.push({count,theme,viewport:width,...measurement,file});
      }
      if (count===8) {
        await page.setViewportSize({width:1440,height:1000});
        await page.locator('#live-tunnels-more').click();
        assert.equal(await page.locator('.live-tunnel:visible').count(),8);
        assert.equal(await page.locator('#live-tunnels-more').getAttribute('aria-expanded'),'true');
        // Native disclosure is keyboard accessible; a public link stays a link.
        await page.locator('.live-tunnel summary').first().focus(); await page.keyboard.press('Enter');
        assert.equal(await page.locator('.live-tunnel details[open]').count(),1);
        assert.match(await page.locator('.live-tunnel-details:visible').innerText(),/Client 1\.2\.3 · linux\/amd64 · Last request/);
        await update(); assert.equal(await page.locator('.live-tunnel details[open]').count(),1,'refresh lost disclosure state');
        await page.locator('.live-tunnel summary').first().evaluate(node=>node.blur());
        for (const theme of ['light','dark']) {
          await page.emulateMedia({colorScheme:theme});
          const height = await page.locator('.live-tunnels').evaluate(s=>s.getBoundingClientRect().height);
          assert.ok(height<=260,`expanded section height ${height}`);
          const file = `tunnels-8-1440-${theme}-expanded-details.png`;
          await page.screenshot({path:path.join(evidence,file),fullPage:true});shots.push(file);metrics.push({count,theme,viewport:1440,height,expanded:true,details:true,file});
        }
        await page.locator('.live-tunnel-name').first().click();
        assert.equal(await page.locator('.live-tunnel details[open]').count(),0);
        await page.locator('#live-tunnels-more').click();
        assert.equal(await page.locator('.live-tunnel:visible').count(),4);
      }
    }
    const beforeFailure = await page.locator('#live-tunnel-list').innerHTML();
    failed = true; await delayedPoll('failed'); await update();
    assert.equal(await page.locator('#live-tunnel-list').innerHTML(),beforeFailure,'failed poll changed list');
    assert.equal(await page.locator('#live-tunnels-stale').isVisible(),false);
    await delayedPoll('fresh-at-60s',60000); await update();
    assert.equal(await page.locator('#live-tunnels-stale').isVisible(),false,'stale warning at exactly 60 seconds');
    // Probe both sides of production's freshness boundary, rather than merely
    // comparing two fake Date.now() readings. No complete poll intervenes.
    await delayedPoll('stale-at-60s-plus-1ms',1); await update();
    assert.equal(await page.locator('#live-tunnels-stale').innerText(),'last updated 1 min ago');
    await delayedPoll('later-staleness',60999); await update();
    assert.equal(await page.locator('#live-tunnels-stale').innerText(),'last updated 2 min ago');
    assert.equal(await page.locator('#live-tunnel-list').innerHTML(),beforeFailure);
    await page.screenshot({path:path.join(evidence,'tunnels-stale-1440-dark.png'),fullPage:true});
    failed = false; data = {complete:false,tunnels:[]}; await delayedPoll('partial-retention'); await update();
    assert.equal(await page.locator('#live-tunnel-list').innerHTML(),beforeFailure,'partial response cleared good list');
    data = {complete:true,tunnels:fixture(1)}; await delayedPoll('complete-recovery'); await update();
    assert.equal(await page.locator('#live-tunnels-stale').isVisible(),false,'fresh response did not clear warning');
    data = {complete:true,tunnels:[]}; await update();
    assert.equal(await page.locator('.live-tunnel').count(),0,'disconnect did not drop row');
    assert.deepEqual(errors,[]);
    const pollState = await page.evaluate(()=>window.__accountPolls);
    const delayedEvents = pollState.events.filter(e=>['body-held','visibility-while-held','release'].includes(e.phase));
    const heldPolls = pollState.requests.filter(r=>r.hold);
    if (schedule === 'delayed') {
      assert.deepEqual(heldPolls.map(r=>r.hold),['failed','fresh-at-60s','stale-at-60s-plus-1ms','later-staleness','partial-retention','complete-recovery']);
      for (const record of heldPolls) {
        assert.ok(record.settled && !record.error,'delayed body did not reach refresh');
        const phases = ['request','response','body-held'];
        if (record.hold === 'failed') phases.push('visibility-while-held');
        phases.push('release');
        if (record.status===200) phases.push('body');
        phases.push('settled');
        assert.deepEqual(pollState.events.filter(e=>e.generation===record.id).map(e=>e.phase),phases);
        assert.equal(record.aborted,record.hold==='failed','unexpected abort at delayed boundary');
        if (record.hold === 'complete-recovery') {
          assert.equal(record.dom.names.length,1,'delayed recovery did not render');
          assert.equal(record.dom.stale,false,'delayed recovery did not clear staleness');
        }
      }
    }
    const report = {result:'PASS',schedule,delayedEvents,heldPolls,pollState,connected_without_reload:true,disconnected_without_reload:true,other_account_isolated:true,anonymous_requires_sign_in:true,hidden_visibility_event_stops_polling:true,resumes_on_visible:true,failed_poll_keeps_list:true,partial_response_keeps_list:true,stale_after_60_seconds:true,recovers_after_outage:true,sort_by_last_request_then_name:true,inline_expansion_and_keyboard_details:true,viewport_widths:[390,1440],shots,signInShots,metrics,browser_errors:errors};
    fs.writeFileSync(path.join(evidence,'account-browser.json'),JSON.stringify(report,null,2)+'\n');
    console.log(JSON.stringify(report));
    await context.close();
  } finally { await browser.close(); }
})().catch(error => { console.error(error); process.exitCode=1; });
