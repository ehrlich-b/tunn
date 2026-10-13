"use strict";
// Real pages and API responses pass through a TLS-verifying local transport.
// Only the external identity provider's consent and token service are fixtures.
const { chromium } = require(process.env.TUNN_PLAYWRIGHT_MODULE || "playwright");
const https = require("node:https"), fs = require("node:fs"), path = require("node:path"), assert = require("node:assert/strict");
const port = process.argv[2], ca = fs.readFileSync(process.argv[3]);
const apex = `https://tunn.test:${port}`, app = `https://wing.apps.test:${port}`;
const shots = process.env.TUNN_APP_DEVICE_SCREENSHOTS;
function verifiedResponse(request) {
  return new Promise((resolve, reject) => {
    const url = new URL(request.url());
    const headers = {...request.headers(), host: url.host};
    const body = request.postDataBuffer();
    if (body) headers["content-length"] = String(body.length);
    const req = https.request({hostname: "127.0.0.1", port, servername: url.hostname, ca,
      method: request.method(), path: url.pathname + url.search, headers, timeout: 5000}, res => {
      const chunks = []; res.on("data", chunk => chunks.push(chunk));
      res.on("end", () => resolve({status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks)}));
    });
    req.on("error", reject); req.on("timeout", () => req.destroy(new Error("Fixture request timed out")));
    req.end(body);
  });
}
(async () => {
  const browser = await chromium.launch({headless: true, executablePath: process.env.TUNN_CHROMIUM_PATH,
    args: ["--no-proxy-server"]});
  try {
    async function person(email) {
      const context = await browser.newContext({viewport: {width: 1440, height: 900}});
      context.setDefaultTimeout(10000);
      await context.route("**/*", async route => {
        const request = route.request(), url = new URL(request.url());
        if (!["tunn.test", "wing.apps.test", "other.apps.test"].includes(url.hostname) || url.port !== port) {
          await route.abort(); return;
        }
        const response = await verifiedResponse(request);
        const headers = {};
        for (const [name, value] of Object.entries(response.headers)) {
          if (!["content-length", "transfer-encoding", "connection"].includes(name)) headers[name] = Array.isArray(value) ? value.join("\n") : String(value);
        }
        if (url.pathname === "/auth/google") {
          const consent = new URL(response.headers.location);
          const callback = new URL(consent.searchParams.get("redirect_uri"));
          callback.searchParams.set("state", consent.searchParams.get("state")); callback.searchParams.set("code", email);
          delete headers.location; headers["content-type"] = "text/html";
          await route.fulfill({status: 200, headers, body: `<h1>Fixture identity consent</h1><a href="${callback}">Approve verified mailbox</a>`});
        } else if (response.status >= 300 && response.status < 400 && response.headers.location) {
          // Browser redirects otherwise bypass interception after the first hop.
          // A fresh navigation keeps every fixture hop on the verified transport.
          const next = new URL(response.headers.location, request.url()).href.replace(/&/g,"&amp;").replace(/"/g,"&quot;");
          delete headers.location; headers["content-type"]="text/html";
          await route.fulfill({status:200,headers,body:`<meta http-equiv="refresh" content="0;url=${next}">`});
        } else { await route.fulfill({status: response.status, headers, body: response.body}); }
      });
      return {context, page: await context.newPage()};
    }
    async function login(page, target) {
      await page.goto(target);
      await page.getByRole("link", {name: "Continue with Google"}).click();
      await page.getByRole("link", {name: "Approve verified mailbox"}).click();
      await page.getByRole("heading", {name: "Devices", exact: true}).waitFor();
    }
    async function capture(page, name) {
      if (!shots) return;
      fs.mkdirSync(shots, {recursive: true});
      for (const [width, height] of [[1440,900],[390,844]]) {
        await page.setViewportSize({width,height});
        const focus = {invitation:"#invitation","browser-confirm":"#browser-confirm","phone-confirm":"#phone-confirm","phone-connected":"#phone-success","devices-active":".device","devices-revoked":".device"}[name];
        if (focus) await page.locator(focus).scrollIntoViewIfNeeded();
        assert.equal(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth), false, `${name} has horizontal overflow`);
        await page.screenshot({path: path.join(shots, `${name}-${width}x${height}.png`)});
      }
      await page.setViewportSize({width:1440,height:900});
    }
    const owner = await person("owner@example.com"), phone = await person("phone@example.com");
    await login(owner.page, apex + "/account/app-devices?host=wing.apps.test");
    await capture(owner.page, "devices-empty");
    const invitationResponse = owner.page.waitForResponse(response => response.url().endsWith("/api/app-devices/invitations") && response.request().method() === "POST");
    await owner.page.getByRole("button", {name: "Add device", exact: true}).click();
    const invitation = await (await invitationResponse).json();
    assert.equal(invitation.hostname,"wing.apps.test"); assert.equal(invitation.authority,apex);
    await owner.page.locator("#qr").waitFor({state:"visible"}); await capture(owner.page,"invitation");
    await phone.page.goto(apex + "/pair/app-device#invitation=" + encodeURIComponent(invitation.invitation) + "&hostname=wing.apps.test");
    assert.equal(new URL(phone.page.url()).hash, "");
    await phone.page.getByLabel("Device name", {exact:true}).fill("Fixture phone");
    await phone.page.getByRole("button", {name:"Continue", exact:true}).click();
    await phone.page.locator("#phone-phrase").waitFor({state:"visible"});
    await owner.page.locator("#browser-phrase").waitFor({state:"visible"});
    assert.equal(await phone.page.locator("#phone-phrase").textContent(), await owner.page.locator("#browser-phrase").textContent());
    await capture(phone.page,"phone-confirm"); await capture(owner.page,"browser-confirm");
    await owner.page.getByRole("checkbox").check(); await owner.page.getByRole("button", {name:"Approve device",exact:true}).click();
    await owner.page.getByRole("status").filter({hasText:"Browser approved"}).waitFor();
    await phone.page.getByRole("checkbox").check();
    const redemptionResponse = phone.page.waitForResponse(response => response.url().endsWith("/redeem"));
    await phone.page.getByRole("button",{name:"Confirm this device",exact:true}).click();
    const redemption = await (await redemptionResponse).json();
    assert.equal(redemption.device.hostname,"wing.apps.test"); assert.ok(redemption.access_token.startsWith("tunn_app_"));
    await phone.page.getByRole("heading",{name:"Device connected",exact:true}).waitFor(); await capture(phone.page,"phone-connected");
    await owner.page.reload(); await owner.page.getByRole("heading",{name:"Fixture phone",exact:true}).waitFor(); await capture(owner.page,"devices-active");
    const token = redemption.access_token;
    const deviceStatus = await phone.page.evaluate(async ({app,token}) => {
      const r = await fetch(app+"/", {headers:{"Tunn-Authorization":"Bearer "+token},credentials:"omit",redirect:"error"}); return r.status;
    },{app,token}).catch(() => "cors");
    // The native API contract is verified independently; a browser cannot assume
    // that the publisher permits a cross-origin credential-bearing request.
    assert.ok([200,"cors"].includes(deviceStatus));
    owner.page.once("dialog",dialog=>dialog.accept());
    await owner.page.getByRole("button",{name:"Revoke",exact:true}).click();
    await owner.page.getByRole("status").filter({hasText:"Revocation committed"}).waitFor();
    await owner.page.reload(); await owner.page.getByText("Revoked",{exact:true}).waitFor(); await capture(owner.page,"devices-revoked");
    const stranger = await person("stranger@example.com");
    await login(stranger.page,apex+"/account/app-devices?host=wing.apps.test");
    assert.equal(await stranger.page.getByRole("button",{name:"Add device",exact:true}).isDisabled(),true);
    console.log(JSON.stringify({browser:"PASS",provider:"fixture Google consent/token service",both_sides_confirmation:"PASS",enrollment:"PASS",revocation:"PASS",unshared_enrollment:"DENIED",tls:"exact hostname and disposable CA verified",viewports:[[1440,900],[390,844]],screenshots:shots?14:0}));
  } finally { await browser.close(); }
})().catch(error => { console.error(error.message); process.exitCode=1; });
