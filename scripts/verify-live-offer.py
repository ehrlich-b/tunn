#!/usr/bin/env python3
"""Read back a public tunn checkpoint without signing in or leaving its origin."""

import argparse
import hashlib
from html.parser import HTMLParser
from http.client import HTTPException
import json
import re
import urllib.error
import urllib.parse
import urllib.request


TIMEOUT = 10


def origin(url):
    parsed = urllib.parse.urlsplit(url)
    if (parsed.scheme not in ("http", "https") or not parsed.hostname
            or parsed.username is not None or parsed.password is not None):
        raise ValueError("expected an HTTP(S) URL without credentials")
    return parsed.scheme, parsed.hostname, parsed.port or (443 if parsed.scheme == "https" else 80)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class Reader:
    def __init__(self, base):
        self.origin = origin(base)
        parsed = urllib.parse.urlsplit(base)
        if parsed.path not in ("", "/") or parsed.query or parsed.fragment:
            raise ValueError("BASE_URL must be an origin, without a path, query or fragment")
        self.base = base.rstrip("/") + "/"
        # Ignore ambient proxies and cookies; inspect redirects without following them.
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())

    def url(self, path):
        url = urllib.parse.urljoin(self.base, path)
        if origin(url) != self.origin or urllib.parse.urlsplit(url).fragment:
            raise ValueError("URL leaves BASE_URL origin or contains a fragment")
        return url

    def download_url(self, path):
        url = urllib.parse.urljoin(self.base, path)
        parsed = urllib.parse.urlsplit(url)
        if origin(url) == ("https", "tunn.to", 443):
            # stage-release.py names the public origin even for a local tree.
            # Read its download paths from BASE_URL without contacting production.
            if not parsed.path.startswith("/dl/") or parsed.query or parsed.fragment:
                raise ValueError("expected a canonical download path without query or fragment")
            return self.url(parsed.path)
        return self.url(url)

    def request(self, path, method="GET"):
        if method not in ("GET", "HEAD"):
            raise ValueError("only GET and HEAD are allowed")
        req = urllib.request.Request(self.url(path), method=method)
        try:
            return self.opener.open(req, timeout=TIMEOUT)
        except urllib.error.HTTPError as response:
            return response

    def read(self, path):
        with self.request(path) as response:
            if response.status != 200:
                raise ValueError(f"{path}: HTTP {response.status}")
            return response.read()

    def digest(self, path):
        with self.request(path) as response:
            if response.status != 200:
                raise ValueError(f"binary: HTTP {response.status}")
            digest = hashlib.sha256()
            for chunk in iter(lambda: response.read(65536), b""):
                digest.update(chunk)
            return digest.hexdigest()


class Page(HTMLParser):
    # Inline markup does not add whitespace within a rendered word. Block
    # boundaries and explicit line breaks do separate the surrounding text.
    SEPARATORS = frozenset((
        "address", "article", "aside", "blockquote", "br", "caption", "dd",
        "details", "div", "dl", "dt", "fieldset", "figcaption", "figure",
        "footer", "form", "h1", "h2", "h3", "h4", "h5", "h6", "header",
        "hr", "li", "main", "nav", "ol", "p", "pre", "section", "summary",
        "table", "tbody", "td", "tfoot", "th", "thead", "tr", "ul",
    ))

    def __init__(self, body):
        super().__init__(convert_charrefs=True)
        self.parts = []
        self.links = []
        self.link = None
        self.ignored = 0
        self.feed(body.decode("utf-8"))
        self.text = " ".join("".join(self.parts).split())
        if not self.text:
            raise ValueError("empty page")

    def handle_starttag(self, tag, attrs):
        if tag in ("script", "style"):
            self.ignored += 1
        if tag in self.SEPARATORS:
            self.handle_data(" ")
        if tag == "a" and not self.ignored:
            self.link = [dict(attrs).get("href", ""), []]

    def handle_endtag(self, tag):
        if tag in ("script", "style"):
            self.ignored = max(0, self.ignored - 1)
        if tag in self.SEPARATORS:
            self.handle_data(" ")
        if tag == "a" and self.link is not None:
            self.links.append((self.link[0], " ".join("".join(self.link[1]).split())))
            self.link = None

    def handle_data(self, data):
        if not self.ignored:
            self.parts.append(data)
            if self.link is not None:
                self.link[1].append(data)


def require(condition, message):
    if not condition:
        raise ValueError(message)


def check_version(feed, expected):
    require(feed["tag_name"] == expected, f"expected {expected}, got {feed['tag_name']}")


def check_checksums(reader, feed):
    assets = feed["assets"]
    require(isinstance(assets, list) and bool(assets), "no download assets")
    by_name = {}
    for asset in assets:
        name = asset["name"]
        require(isinstance(name, str) and re.fullmatch(r"[A-Za-z0-9_.-]+", name), "invalid asset name")
        require(name not in by_name, "duplicate download asset")
        by_name[name] = reader.download_url(asset["browser_download_url"])
    sums = reader.read(by_name["SHA256SUMS"]).decode("utf-8")
    checksums = {}
    for line in sums.splitlines():
        match = re.fullmatch(r"([a-fA-F0-9]{64}) [ *]([A-Za-z0-9_.-]+)", line)
        require(match is not None, "malformed SHA256SUMS")
        digest, name = match.groups()
        require(name not in checksums, "duplicate checksum")
        checksums[name] = digest.lower()
    binaries = set(by_name) - {"SHA256SUMS", "checksums.txt"}
    require(bool(binaries), "no listed binaries")
    for name in sorted(binaries):
        require(name in checksums, f"missing checksum: {name}")
        require(reader.digest(by_name[name]) == checksums[name], f"sha256 mismatch: {name}")


def check_pricing(reader):
    page = Page(reader.read("/pricing"))
    require("checkout is not available" not in page.text.lower(), "checkout unavailable")
    links = [href for href, text in page.links if text == "Go Pro monthly"]
    require(len(links) == 1, "missing unique Go Pro monthly link")
    offer = urllib.parse.urlsplit(reader.url(links[0]))
    require(offer.path == "/upgrade" and urllib.parse.parse_qs(offer.query) == {"period": ["monthly"]},
            "monthly link does not select monthly checkout")
    # Read only the signed-out redirect; do not visit login or a payment provider.
    with reader.request(links[0]) as response:
        require(response.status in (302, 303), f"monthly checkout: HTTP {response.status}")
        target = urllib.parse.urlsplit(reader.url(response.headers.get("Location", "")))
        require(target.path == "/auth/login" and urllib.parse.parse_qs(target.query).get("return_to")
                == ["/upgrade?period=monthly"], "monthly checkout lost its login return path")


def check_page(reader, path, forbidden):
    page = Page(reader.read(path))
    require(forbidden.lower() not in page.text.lower(), f"{path} contains '{forbidden}'")


def verify(reader, expected):
    feed = None
    feed_error = None
    try:
        feed = json.loads(reader.read("/dl/latest.json"))
    except (ValueError, OSError, HTTPException) as error:
        feed_error = error

    def with_feed(check):
        if feed_error is not None:
            raise ValueError(f"cannot read latest.json: {feed_error}")
        check(feed)

    checks = (
        ("version", lambda: with_feed(lambda data: check_version(data, expected))),
        ("checksums", lambda: with_feed(lambda data: check_checksums(reader, data))),
        ("pricing", lambda: check_pricing(reader)),
        ("about", lambda: check_page(reader, "/about", "Being confirmed")),
        ("mcp", lambda: check_page(reader, "/mcp-to-claude", "not yet been verified")),
    )
    failed = False
    for name, check in checks:
        try:
            check()
            print(f"PASS: {name}")
        except (ValueError, OSError, HTTPException, KeyError, TypeError) as error:
            # One line per check even if a remote response has embedded newlines.
            print(f"FAIL: {name}: {' '.join(str(error).split())}")
            failed = True
    return int(failed)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("base_url", metavar="BASE_URL")
    parser.add_argument("--expect-version", required=True, metavar="vX.Y.Z")
    args = parser.parse_args(argv)
    try:
        reader = Reader(args.base_url)
    except ValueError as error:
        parser.error(str(error))
    return verify(reader, args.expect_version)


if __name__ == "__main__":
    raise SystemExit(main())
