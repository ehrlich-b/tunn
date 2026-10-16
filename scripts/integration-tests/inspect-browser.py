#!/usr/bin/env python3
"""Run the generated inspector journey in a disposable, offline Chrome profile."""
import argparse
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

parser = argparse.ArgumentParser()
parser.add_argument("fixture", type=Path)
args = parser.parse_args()
root = Path.cwd()
scratch = root / ".scratch"
fixture = args.fixture.resolve()
if not fixture.is_relative_to(scratch):
    parser.error("fixture must be under the clone's .scratch directory")
chrome = os.environ.get("INSPECT_CHROME") or shutil.which("chromium") or shutil.which("google-chrome")
if not chrome and sys.platform == "darwin":
    chrome = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
if not chrome or not Path(chrome).is_file():
    sys.exit("REQUIRED/UNRUN: set INSPECT_CHROME to an installed Chrome/Chromium executable; no downloads are attempted")
profile = Path(tempfile.mkdtemp(prefix="inspect-chrome-", dir=scratch))
command = [chrome, "--headless", "--disable-gpu", "--disable-background-networking",
           "--disable-component-update", "--disable-sync", "--disable-extensions",
           "--disable-breakpad", "--no-first-run", "--no-default-browser-check",
           "--disable-features=MediaRouter,OptimizationHints,AutofillServerCommunication",
           "--host-resolver-rules=MAP * ~NOTFOUND", "--renderer-process-limit=2",
           f"--user-data-dir={profile}", f"--crash-dumps-dir={scratch / 'inspect-crashes'}", "--dump-dom", "--virtual-time-budget=5000",
           fixture.as_uri()]
try:
    with (scratch / "inspect-browser-dom.html").open("w") as output, (scratch / "inspect-browser.log").open("w") as error:
        result = subprocess.run(command, stdout=output, stderr=error, timeout=45, check=False)
except subprocess.TimeoutExpired:
    sys.exit("FAIL: browser fixture exceeded 45 seconds; see .scratch/inspect-browser.log")
dom = (scratch / "inspect-browser-dom.html").read_text()
if result.returncode or 'data-inspect-acceptance="PASS"' not in dom:
    diagnostic = (scratch / "inspect-browser.log").read_text()
    if "Operation not permitted" in diagnostic and "Failed to bind()" in diagnostic:
        sys.exit("REQUIRED/UNRUN: Chrome profile listener denied; run the browser fixture on the operator host")
    sys.exit(f"FAIL: browser fixture (exit {result.returncode}); see .scratch/inspect-browser-dom.html and .scratch/inspect-browser.log")
print("PASS: actual serverless Chrome UI journey; API/target transport is covered separately")
