#!/usr/bin/env python3
"""Check inspector HTML structure and every embedded script without a listener."""
import argparse
from html.parser import HTMLParser
from pathlib import Path
import shutil
import subprocess
import sys

VOID = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source", "track", "wbr"}


class InspectorHTML(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.stack = []
        self.scripts = []
        self.current_script = None

    def handle_starttag(self, tag, attrs):
        if tag not in VOID:
            self.stack.append(tag)
        if tag == "script":
            self.current_script = []

    def handle_startendtag(self, tag, attrs):
        if tag not in VOID:
            raise ValueError(f"Unexpected self-closing {tag}")

    def handle_endtag(self, tag):
        if not self.stack or self.stack.pop() != tag:
            raise ValueError(f"Mismatched closing {tag}")
        if tag == "script":
            self.scripts.append("".join(self.current_script))
            self.current_script = None

    def handle_data(self, data):
        if self.current_script is not None:
            self.current_script.append(data)


parser = argparse.ArgumentParser()
parser.add_argument("files", nargs="+", type=Path)
args = parser.parse_args()
node = shutil.which("node")
if not node:
    sys.exit("REQUIRED/UNRUN: installed Node is needed for syntax checking; no download is attempted")
scratch = Path.cwd() / ".scratch"
scratch.mkdir(exist_ok=True)
count = 0
try:
    with (scratch / "inspect-syntax.log").open("w") as log:
        for path in args.files:
            html = InspectorHTML()
            html.feed(path.read_text())
            html.close()
            if html.stack or not html.scripts:
                raise ValueError(f"Incomplete HTML or missing script: {path}")
            for script in html.scripts:
                count += 1
                target = scratch / f"inspect-script-{count}.js"
                target.write_text(script)
                result = subprocess.run([node, "--check", str(target)], stdout=log, stderr=log, timeout=10, check=False)
                if result.returncode:
                    raise ValueError(f"Invalid script in {path}; see .scratch/inspect-syntax.log")
except (ValueError, subprocess.TimeoutExpired) as error:
    sys.exit(f"FAIL: {error}")
print(f"PASS: {len(args.files)} HTML files and {count} embedded scripts")
