import json
import sys
from urllib.parse import urlencode
from playwright.sync_api import sync_playwright

port = sys.argv[1]
apex = f"https://tunn.test:{port}"
resource = f"https://api.tunn.test:{port}"
with sync_playwright() as pw:
    browser = pw.chromium.launch(headless=True, args=[
        "--no-proxy-server", "--ignore-certificate-errors-spki-list=" + sys.argv[2], "--host-resolver-rules=MAP *.tunn.test 127.0.0.1, MAP tunn.test 127.0.0.1, MAP evil.test 127.0.0.1"])
    context = browser.new_context()
    page = context.new_page()
    page.goto(apex + "/review/login?email=alice@example.com")
    page.goto(resource + "/")
    js_cookie = page.evaluate("document.cookie")
    assert "tunn_auth" not in js_cookie
    # Chromium must retain its real cache: do not install Playwright routes.
    first = page.evaluate("""async () => { const r=await fetch('/asset.js'); return {status:r.status, text:await r.text(), cache:r.headers.get('cache-control'), vary:r.headers.get('vary'), headers:Object.fromEntries(r.headers)}; }""")
    assert first["status"] == 200 and first["text"] == "PRIVATE-ASSET-REVIEW"
    repeated = page.evaluate("""async () => {const r=await fetch('/asset.js', {cache:'force-cache'}); return {status:r.status, text:await r.text()};}""")
    admin = context.new_page()
    admin.goto(apex + "/review/revoke")
    second = page.evaluate("""async () => { const r=await fetch('/asset.js', {cache:'force-cache'}); return {status:r.status, text:await r.text()}; }""")
    network = page.evaluate("""async () => (await fetch('/asset.js', {cache:'no-store'})).status""")
    # Test URL-standard backslash handling without contacting an outside host.
    redirect_page = context.new_page()
    # redirect_page.route("**/*", lambda route: route.fulfill(status=200, body="outside origin") if "evil.test" in __import__("urllib.parse", fromlist=["urlsplit"]).urlsplit(route.request.url).netloc else route.continue_())
    redirect_page.goto(apex + "/review/redirect?" + urlencode({"return_to": "/\\evil.test:" + port + "/"}))
    print(json.dumps({"first_asset": first, "cached_after_revocation": second["status"] == 200 and second["text"] == first["text"],
                      "network_after_revocation": network, "platform_cookie_visible_to_js": "tunn_auth" in js_cookie,
                      "backslash_redirect_final_url": redirect_page.url}))
    browser.close()
