#!/usr/bin/env python3
"""Extract reviewable exact visible draft copy from the two source pages."""
import hashlib
from html.parser import HTMLParser
from pathlib import Path

ROOT = Path(__file__).resolve().parent


class VisibleText(HTMLParser):
    def __init__(self):
        super().__init__()
        self.ignore = 0
        self.parts = []

    def handle_starttag(self, tag, attrs):
        if tag in {"head", "script", "style"}:
            self.ignore += 1
        if not self.ignore and tag in {"p", "h1", "h2", "h3", "li", "pre", "button", "a", "footer"}:
            self.parts.append("\n")
        if not self.ignore and tag == "br":
            self.parts.append("\n")

    def handle_endtag(self, tag):
        if tag in {"head", "script", "style"}:
            self.ignore -= 1
        if not self.ignore and tag in {"p", "h1", "h2", "h3", "li", "pre", "button", "a", "footer"}:
            self.parts.append("\n")
        if tag == "br" and not self.ignore:
            self.parts.append("\n")

    def handle_startendtag(self, tag, attrs):
        if tag == "br" and not self.ignore:
            self.parts.append("\n")

    def handle_data(self, data):
        if not self.ignore:
            self.parts.append(data)


def copy_packet():
    parts = ["# Exact landing draft copy\n\nGenerated from the source pages; text whitespace is normalized. HTML sources govern layout, links and controls. No publication is approved.\n"]
    for name in ("index.html", "team.html"):
        source = (ROOT / "site" / name).read_bytes()
        reader = VisibleText()
        reader.feed(source.decode())
        lines = [' '.join(line.split()) for line in ''.join(reader.parts).splitlines() if line.strip()]
        parts.append(f"\n## {name}\n\nSource SHA-256: `{hashlib.sha256(source).hexdigest()}`\n\n```text\n" + '\n'.join(lines) + "\n```\n")
    parts.append("\n## Dynamic fixture copy\n\nThe exact interactive strings are in `site/walkthrough.js`. The invented MCP token is `fixture-cinder-7A-not-a-credential`; the browser token is `fixture-mosslight-9B-not-a-credential`. Allowed results are `orbital-garden: green` and `layout-check: ready`. State labels are SUCCESS, DENIED, REVOKED and OFFLINE, each marked simulated. The timer states that its measurement is ineligible for demand evidence. No actual connector, session, login or service is involved.\n")
    return ''.join(parts)


if __name__ == "__main__":
    destination = ROOT / "DRAFT-COPY.md"
    destination.write_text(copy_packet())
    print(f"Wrote {destination.relative_to(ROOT)} from the two local variants")
