/* Synthetic UI fixture only. No network, credentials, storage or real grants. */
"use strict";
globalThis.AccessFixture = Object.freeze({
  create(recipe) {
    if (!["mcp", "browser"].includes(recipe)) throw new Error("Unknown recipe");
    let revoked = false;
    let online = true;
    let upstreamOperations = 0;
    const caller = recipe === "mcp" ? "cinder-agent-fixture" : "reviewer@mosslight.invalid";
    const operation = recipe === "mcp" ? "read_almanac" : "read_status";
    return {
      caller, operation,
      token: recipe === "mcp" ? "fixture-cinder-7A-not-a-credential" : "fixture-mosslight-9B-not-a-credential",
      request(subject = caller, tool = operation) {
        if (subject !== caller || tool !== operation) return { state: "denied", status: 403, result: "Caller or operation not granted" };
        if (revoked) return { state: "revoked", status: 403, result: "Fixture grant revoked" };
        if (!online) return { state: "offline", status: 503, result: "Fixture origin asleep" };
        upstreamOperations += 1;
        return { state: "success", status: 200, result: recipe === "mcp" ? "orbital-garden: green" : "layout-check: ready" };
      },
      revoke() { revoked = true; return this.request(); },
      setOffline() { online = false; return this.request(); },
      get upstreamOperations() { return upstreamOperations; },
    };
  },
});

if (typeof document !== "undefined") {
  const panel = document.querySelector("[data-recipe]");
  if (panel) {
    let fixture = AccessFixture.create(panel.dataset.recipe);
    let start = null;
    let clock = null;
    const elapsed = document.getElementById("elapsed");
    const result = document.getElementById("fixture-result");
    const audit = document.getElementById("fixture-audit");
    const token = document.getElementById("fixture-token");
    function show(reply) {
      result.dataset.state = reply.state;
      result.textContent = `${reply.state.toUpperCase()} · simulated ${reply.status} · ${reply.result}`;
      audit.textContent = `Synthetic upstream operations: ${fixture.upstreamOperations}. No real service was called.`;
    }
    function updateClock() {
      elapsed.textContent = `Simulated worksheet elapsed: ${((performance.now() - start) / 1000).toFixed(1)} seconds. Ineligible for demand evidence.`;
    }
    panel.addEventListener("click", event => {
      const action = event.target.closest("button")?.dataset.action;
      if (action === "success") show(fixture.request());
      if (action === "denied") show(fixture.request("uninvited-fixture.invalid"));
      if (action === "ungranted") show(fixture.request(fixture.caller, "write_secret"));
      if (action === "revoked") show(fixture.revoke());
      if (action === "offline") show(fixture.setOffline());
      if (action === "reset") {
        fixture = AccessFixture.create(panel.dataset.recipe);
        show({ state: "ready", status: "—", result: "Fresh synthetic fixture. Choose a state." });
        clearInterval(clock); clock = null; start = null;
        elapsed.textContent = "Timer not started. Timing this fixture does not measure real onboarding.";
        document.querySelector('[data-action="timer-start"]').disabled = false;
        document.querySelector('[data-action="timer-stop"]').disabled = true;
      }
      if (action === "timer-start" && clock === null) {
        start = performance.now(); updateClock(); clock = setInterval(updateClock, 500);
        event.target.disabled = true;
        document.querySelector('[data-action="timer-stop"]').disabled = false;
      }
      if (action === "timer-stop" && start !== null) {
        updateClock(); clearInterval(clock); clock = null;
        event.target.disabled = true;
      }
    });
    token.textContent = fixture.token;
  }
}
