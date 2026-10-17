"use strict";
(() => {
  const root = document.body, get = id => document.getElementById(id);
  const status = message => { get("status").textContent = message; };
  const host = root.dataset.host, csrf = root.dataset.csrf;
  let invitation, claim, verifier, credential, timer;
  async function request(path, input, json = false) {
    const options = input === undefined ? {cache: "no-store"} : {
      method: "POST", cache: "no-store", redirect: "error",
      headers: {"Content-Type": json ? "application/json" : "application/x-www-form-urlencoded"},
      body: json ? JSON.stringify(input) : new URLSearchParams({csrf_token: csrf, hostname: host, scope: root.dataset.owner === "true" ? "hostname" : "self", ...input})
    };
    const response = await fetch("/api/app-devices" + path, options);
    const result = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(result.error || `Request failed (${response.status})`);
    return {response, result};
  }
  function action(id, fn) {
    const button = get(id); if (!button) return;
    button.addEventListener("click", async () => {
      button.disabled = true;
      try { await fn(); } catch (error) { status(error.message); }
      finally { button.disabled = false; }
    });
  }
  if (root.dataset.phone === "true") {
    const fragment = new URLSearchParams(location.hash.slice(1));
    const handle = fragment.get("invitation"), hostname = fragment.get("hostname");
    history.replaceState(null, "", location.pathname);
    if (new URL(root.dataset.authority).origin !== location.origin || !handle || !hostname) {
      get("phone-start").hidden = true; status("Invalid invitation. Create a new QR in your signed-in browser."); return;
    }
    get("phone-host").textContent = hostname;
    action("claim", async () => {
      const bytes = crypto.getRandomValues(new Uint8Array(32));
      verifier = btoa(String.fromCharCode(...bytes)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
      const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier));
      const challenge = btoa(String.fromCharCode(...new Uint8Array(digest))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
      const {result} = await request("/claims", {invitation: handle, hostname, name: get("device-name").value.trim(), code_challenge: challenge, code_challenge_method: "S256"}, true);
      claim = result; get("phone-start").hidden = true; get("phone-confirm").hidden = false;
      get("confirm-host").textContent = claim.hostname; get("phone-phrase").textContent = claim.phrase; status("");
    });
    let lastRedeem = 0;
    action("redeem", async () => {
      if (!get("phone-match").checked) throw new Error("Confirm that both screens match first.");
      if (Date.now() - lastRedeem < 5000) throw new Error("Wait 5 seconds before checking again.");
      lastRedeem = Date.now();
      const {response, result} = await request(`/claims/${encodeURIComponent(claim.claim_id)}/redeem`, {code_verifier: verifier, hostname, phrase: claim.phrase, confirmed: true}, true);
      if (response.status === 202) { status("Waiting for browser approval. Approve there, then confirm here again."); return; }
      credential = result.access_token; verifier = undefined;
      get("phone-confirm").hidden = true; get("phone-success").hidden = false;
      get("phone-expiry").textContent = `Access to ${hostname} expires ${new Date(result.expires_at).toLocaleString()}.`; status("");
    });
    return;
  }
  action("invite", async () => {
    if (timer) clearInterval(timer);
    const {result} = await request("/invitations", {}); invitation = result;
    get("qr").src = result.qr_png; get("invitation").hidden = false; get("browser-confirm").hidden = true;
    get("browser-match").checked = false;
    get("invitation-expiry").textContent = `Expires ${new Date(result.expires_at).toLocaleTimeString()}. Single use.`;
    status("");
    timer = setInterval(async () => {
      try {
        const {result} = await request(`/invitations/${encodeURIComponent(invitation.id)}`);
        if (result.claim_id) {
          claim = result; get("browser-confirm").hidden = false;
          get("claim-name").textContent = result.name; get("browser-phrase").textContent = result.phrase;
          clearInterval(timer);
        }
      } catch (error) { clearInterval(timer); status(error.message); get("qr").removeAttribute("src"); }
    }, 5000);
  });
  action("approve", async () => {
    if (!get("browser-match").checked) throw new Error("Confirm that both screens match first.");
    await request(`/claims/${encodeURIComponent(claim.claim_id)}/approve`, {phrase: claim.phrase, confirmed: "true"});
    get("browser-confirm").hidden = true; get("qr").removeAttribute("src");
    status("Browser approved. Confirm on the device to finish enrollment.");
  });
  async function revoke(path, input, description) {
    if (!window.confirm(description)) return;
    const {result} = await request(path, input);
    status(`Revocation committed at ${new Date(result.revoked_at).toLocaleTimeString()}. Active connections close within 5 seconds.`);
    document.querySelectorAll(".revoke").forEach(button => {
      if (path === "/revoke-all" || button.dataset.id === input.device_id) {
        button.disabled = true; button.textContent = "Revoked";
      }
    });
  }
  action("revoke-all", () => revoke("/revoke-all", {}, `Revoke the devices shown for ${host}? Pending enrollments in this scope also end.`));
  document.querySelectorAll(".revoke").forEach(button => button.addEventListener("click", async () => {
    try { await revoke("/revoke", {device_id: button.dataset.id}, `Revoke this device's access to ${host}?`); }
    catch (error) { status(error.message); }
  }));
})();
