#!/usr/bin/env python3
"""Layout acceptance against snapshots from the real authenticated handler."""
import json
import os
from pathlib import Path
import sys
from playwright.sync_api import sync_playwright

snapshots = json.loads(Path(sys.argv[1]).read_text())
evidence = Path(sys.argv[2])
before = os.environ.get("TUNN_SHARING_BEFORE") == "1"
metrics = []
with sync_playwright() as pw:
    browser = pw.chromium.launch(headless=True)
    for snapshot in snapshots:
        for theme in ("light", "dark"):
            for width, height in ((390, 844), (1440, 1000)):
                context = browser.new_context(viewport={"width": width, "height": height}, color_scheme=theme)
                page = context.new_page()
                # The rendered page contains its real CSS. No production contact.
                page.route("**/*", lambda route: route.fulfill(status=200, content_type="text/html", body=snapshot["HTML"]) if route.request.resource_type == "document" else route.fulfill(status=200, body=""))
                page.goto("https://sharing.test/account/sharing")
                prefix = f'{snapshot["Name"]}-{width}-{theme}'
                page.screenshot(path=str(evidence / (prefix + "-first.png")))
                page.screenshot(path=str(evidence / (prefix + ".png")), full_page=True)
                form = page.locator('form:has(input[type="email"])')
                share = form.get_by_role("button", name="Share", exact=True)
                box = share.bounding_box() if share.count() else None
                metrics.append({"fixture": snapshot["Name"], "tunnels": snapshot["Tunnels"], "people": snapshot["People"], "theme": theme, "width": width, "share_bottom": box["y"]+box["height"] if box else None})
                if not before:
                    assert page.evaluate("document.documentElement.scrollWidth <= innerWidth"), prefix + " overflow"
                    assert page.get_by_role("combobox", name="Tunnel", exact=True).locator("option").count() == snapshot["Tunnels"] if snapshot["Tunnels"] else page.get_by_role("link", name="Start a tunnel", exact=True).count() == 1
                    if snapshot["People"]:
                        assert box and box["y"]+box["height"] <= height, prefix + " add control below screen"
                        assert page.locator(".sharing-person").count() == snapshot["People"]
                        assert page.locator(".sharing-person:visible").count() == min(4, snapshot["People"])
                        if snapshot["People"] > 4:
                            assert page.locator(".sharing-more summary").inner_text() == f'+{snapshot["People"]-4} more'
                            page.locator(".sharing-more summary").click()
                            assert page.locator(".sharing-person:visible").count() == snapshot["People"]
                        assert page.locator(".sharing-person").get_by_text("Expires", exact=False).count() == 1
                        assert not form.locator('details').get_attribute("open")
                        assert form.locator('input[name="expires"]').input_value() == ""
                        assert not page.locator(".sharing-recent").get_attribute("open")
                        page.locator(".sharing-recent summary").click()
                        text = page.locator(".sharing-recent").inner_text()
                        assert "Sign-in required" in text and "Access denied" in text
                        assert "authentication_required" not in text and "unknown_internal_reason" not in text
                        page.screenshot(path=str(evidence / (prefix + "-expanded.png")), full_page=True)
                        form.locator(".sharing-expiry summary").click()
                        assert form.get_by_label("Expires at (UTC)").is_visible()
                        page.screenshot(path=str(evidence / (prefix + "-expiry.png")), full_page=True)
                        rows = page.locator(".sharing-person .sharing-name").all_text_contents()
                        assert len(set(rows)) == snapshot["People"]
                    if snapshot["Name"] == "sharing-public":
                        assert form.count() == 0
                        assert "without --public" in page.locator("main").inner_text()
                        assert "Anyone with this link" in page.locator("main").inner_text()
                    text = page.locator("main").inner_text().lower()
                    for forbidden in ("polling", "refreshed", "15 minutes", "web resource", "denied:", "no scheduled expiry", "group:"):
                        assert forbidden not in text, (prefix, forbidden)
                context.close()
    browser.close()
(evidence / "layout.json").write_text(json.dumps({"before": before, "checks": metrics}, indent=2)+"\n")
print(json.dumps({"result": "PASS", "before": before, "views": len(metrics), "required_screenshots": len(metrics)*2}))
