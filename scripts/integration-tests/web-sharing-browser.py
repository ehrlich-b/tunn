#!/usr/bin/env python3
"""Clean Chromium journey against the TLS Go fixture; no recipient bypass headers.

Run: TUNN_SHARE_BROWSER_PYTHON=/path/to/playwright/python go test -p=1 -count=1
     -v ./internal/host -run '^TestWebSharingBrowserJourney$'
Only Google's external consent/token service is mocked. The real relay serves
login, verifies callback state/PKCE/verified email, sets cookies, checks live
permissions, renders dashboard forms and records access decisions.
"""
import json
import sys
import time
from urllib.parse import parse_qs, urlencode, urlparse
from playwright.sync_api import sync_playwright

port = sys.argv[1]
apex = f"https://tunn.test:{port}"
resource = f"https://api.tunn.test:{port}/"
with sync_playwright() as pw:
    browser = pw.chromium.launch(headless=True, args=[
        "--no-proxy-server", "--host-resolver-rules=MAP *.tunn.test 127.0.0.1, MAP tunn.test 127.0.0.1"])
    def person(email):
        context = browser.new_context(ignore_https_errors=True)
        context.set_default_timeout(5000)
        def consent(route):
            response = route.fetch(url=urlparse(route.request.url)._replace(netloc=f"127.0.0.1:{port}").geturl(),
                                   headers={**route.request.headers, "host": f"tunn.test:{port}"},
                                   max_redirects=0, timeout=5000)
            query = parse_qs(urlparse(response.headers["location"]).query)
            callback = query["redirect_uri"][0] + "?" + urlencode({"state": query["state"][0], "code": email})
            headers = {k: v for k, v in response.headers.items() if k not in ("location", "content-length")}
            headers["content-type"] = "text/html"
            route.fulfill(response=response, status=200, headers=headers, body=f'<h1>Fixture Google consent</h1><a href="{callback}">Approve verified email</a>')
        context.route("**/auth/google?*", consent)
        return context, context.new_page()
    def login(page):
        page.get_by_role("link", name="Continue with Google").click()
        page.get_by_role("link", name="Approve verified email").click(timeout=5000)
    owner_context, owner = person("owner@example.com")
    owner.goto(apex + "/account/sharing?tunnel=api")
    login(owner)
    owner.get_by_role("heading", name="Share access", exact=True).wait_for()
    owner.evaluate("navigator.clipboard.writeText = async text => { window.copiedSharingLink = text; }")
    owner.get_by_role("button", name="Copy link", exact=True).click()
    assert owner.locator("#sharing-copy").inner_text() == "Link copied"
    assert owner.evaluate("window.copiedSharingLink") == resource.rstrip("/")
    # Resource stayed private before sharing and anonymous visitors see sign-in.
    alice_context, alice = person("alice@example.com")
    alice.goto(resource)
    assert "/auth/login" in alice.url
    start = time.monotonic()
    owner.get_by_label("Email", exact=True).fill("alice@example.com")
    owner.get_by_role("button", name="Share", exact=True).click()
    owner.get_by_role("button", name="Remove access").wait_for()
    login(alice)
    assert "jsonrpc" in alice.locator("body").inner_text()
    share_ms = (time.monotonic() - start) * 1000
    # Reuse only the ordinary browser cookie for the next session.
    alice.goto(resource)
    assert "jsonrpc" in alice.locator("body").inner_text()
    stranger_context, stranger = person("stranger@example.com")
    stranger.goto(resource)
    login(stranger)
    assert "Access denied" in stranger.locator("body").inner_text()
    # A copied resource link gives the wrong signed-in identity no permission.
    assert stranger.goto(resource).status == 403
    start = time.monotonic()
    owner.get_by_role("button", name="Remove access").click()
    assert alice.goto(resource).status == 403
    revoke_ms = (time.monotonic() - start) * 1000
    assert share_ms < 30_000
    assert revoke_ms < 5_000
    owner.goto(apex + "/account/sharing?tunnel=api")
    owner.locator(".sharing-recent summary").click()
    assert "alice@example.com" in owner.locator("body").inner_text()
    print(json.dumps({"clean_browser": "PASS", "share_to_recipient_in_ms": round(share_ms, 2),
                      "revoke_to_next_request_denied_ms": round(revoke_ms, 2),
                      "second_session": "PASS", "wrong_person": "DENIED",
                      "provider": "mocked Google consent and token service"}))
    browser.close()
