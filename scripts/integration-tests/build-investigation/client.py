#!/usr/bin/env python3
"""Official Python MCP SDK + deterministic synthetic build investigation.

No hosted model calls occur. The diagnosis is conditional on remote search/read
evidence, including a check that the pipeline has not already run generation.
"""

import argparse
import asyncio
import importlib.metadata
import json
import ssl
import sys
import time
from datetime import timedelta
from pathlib import Path

import httpx
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client
from mcp.types import Implementation


def diagnose(documents):
    package = json.loads("\n".join(line["text"] for line in documents.get("package.json", {}).get("lines", [])))
    scripts = package.get("scripts", {})
    if not scripts.get("generate:schema") or scripts.get("build") != "tsc -p tsconfig.json" or scripts.get("prebuild"):
        raise ValueError("Package scripts do not support a skipped-generation diagnosis")
    if any("generate:schema" in line["text"] for line in documents.get("ci/build.yml", {}).get("lines", [])):
        raise ValueError("CI already runs generation; skipped-generation diagnosis is unsupported")
    requirements = [
        ("logs/build-4821.log", "error TS2307: Cannot find module './generated/schema'"),
        ("package.json", '"generate:schema":'),
        ("package.json", '"build": "tsc -p tsconfig.json"'),
        ("ci/build.yml", "- run: npm run build"),
        ("docs/build.md", "Before compiling on a clean checkout, run npm run generate:schema."),
        (".gitignore", "src/generated/"),
    ]
    evidence = []
    for path, text in requirements:
        matches = [line for line in documents.get(path, {}).get("lines", []) if text in line["text"]]
        if not matches:
            raise ValueError(f"Missing diagnosis evidence in {path}")
        evidence.append({"citation": f"{path}:{matches[0]['number']}", "text": matches[0]["text"]})
    return evidence


async def investigate(args):
    started = time.monotonic()
    headers = {}
    if args.token_file:
        token = Path(args.token_file).read_text().strip()
        if not token or "\r" in token or "\n" in token:
            raise ValueError("Token file must contain one nonempty line")
        headers[args.auth_header] = f"Bearer {token}"
    if args.host:
        headers["Host"] = args.host
    tls = ssl.create_default_context(cafile=args.ca_cert) if args.ca_cert else True
    report = {
        "client": f"official-python-sdk@{importlib.metadata.version('mcp')}",
        "investigator": "deterministic evidence checks; no hosted model",
        "tool_calls": 0,
    }
    async with httpx.AsyncClient(headers=headers, verify=tls, timeout=10, trust_env=False) as http_client:
        async with streamable_http_client(args.endpoint, http_client=http_client) as (read, write, _):
            async with ClientSession(read, write, read_timeout_seconds=timedelta(seconds=10),
                                     client_info=Implementation(name="tunn-build-investigator-python", version="1")) as session:
                initialized = await session.initialize()
                report["protocol"] = initialized.protocolVersion

                async def call(name, arguments):
                    result = await session.call_tool(name, arguments)
                    if result.isError:
                        raise ValueError(f"{name} returned a tool error")
                    report["tool_calls"] += 1
                    if report["tool_calls"] == 1:
                        report["first_tool_ms"] = round((time.monotonic() - started) * 1000, 3)
                    if result.structuredContent is None:
                        raise ValueError(f"{name} omitted structured evidence")
                    return result.structuredContent

                failures = await call("build.search", {"query": "TS2307"})
                if len(failures["matches"]) != 1:
                    raise ValueError("Expected one missing-module failure")
                failure = await call("build.read", {"path": failures["matches"][0]["path"]})
                generation = await call("build.search", {"query": "generate:schema"})
                paths = {failure["path"], "ci/build.yml", ".gitignore"}
                paths.update(match["path"] for match in generation["matches"])
                documents = {failure["path"]: failure}
                for path in sorted(paths):
                    if path not in documents:
                        documents[path] = await call("build.read", {"path": path})
                report["evidence"] = diagnose(documents)
                report["diagnosis"] = "The clean CI checkout never generates src/generated/schema.ts before TypeScript compilation."
                report["recommendation"] = "Run npm run generate:schema after npm ci and before npm run build; keep generated files untracked."
                report["useful_answer_ms"] = round((time.monotonic() - started) * 1000, 3)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--endpoint", required=True)
    parser.add_argument("--token-file")
    parser.add_argument("--auth-header", choices=["Authorization", "Tunn-Authorization"], default="Authorization")
    parser.add_argument("--ca-cert", help="PEM CA certificate for a local TLS relay")
    parser.add_argument("--host", help="HTTP Host for local tunnel routing")
    args = parser.parse_args()
    try:
        report = asyncio.run(asyncio.wait_for(investigate(args), timeout=20))
    except Exception as error:
        print(f"Investigation failed ({type(error).__name__}); no diagnosis emitted.", file=sys.stderr)
        return 1
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
