#!/usr/bin/env python3
"""Summarize saved Go JSON events, counting leaf tests rather than parents."""
import collections
import json
from pathlib import Path

root = Path(__file__).parent


def summarize(path):
    events = []
    for line in path.read_text().splitlines():
        try:
            event = json.loads(line)
        except ValueError:
            continue
        if "Action" in event:
            events.append(event)
    parents = set()
    for event in events:
        name = event.get("Test", "")
        parts = name.split("/")
        for i in range(1, len(parts)):
            parents.add((event.get("Package"), "/".join(parts[:i])))
    tests, all_tests, packages = collections.Counter(), collections.Counter(), collections.Counter()
    failures = []
    for event in events:
        action = event["Action"]
        if action not in ("pass", "fail", "skip"):
            continue
        name = event.get("Test")
        if name:
            all_tests[action] += 1
            if (event.get("Package"), name) in parents:
                continue
            tests[action] += 1
        else:
            packages[action] += 1
        if action == "fail":
            failures.append({"package": event.get("Package"), "test": name})
    stderr = path.with_suffix(".stderr")
    raw = path.read_text() + (stderr.read_text() if stderr.exists() else "")
    return {"leaf_tests": dict(tests), "test_outcomes_including_parents": dict(all_tests), "packages": dict(packages),
            "failures": failures, "race_warnings": raw.count("WARNING: DATA RACE")}


summary = {p.name: summarize(p) for p in sorted(root.glob("*.jsonl"))
           if p.name != "govulncheck.jsonl"}
assert (root / "full-serial.exit").read_text().strip() == "0"
assert not summary["full-serial.jsonl"]["failures"]
assert (root / "carrier-mcp-race-repeat.exit").exists()
baseline_failures = {(f["package"], f["test"])
                     for f in summary["carrier-mcp-race-repeat.jsonl"]["failures"]}
race_failures = {(f["package"], f["test"])
                 for f in summary["full-race-serial.jsonl"]["failures"]}
assert race_failures <= baseline_failures, race_failures - baseline_failures
assert summary["full-race-serial.jsonl"]["race_warnings"] == 0
(root / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
lines = ["Carrier baseline 8cb0b92505fdaaaf7497005aea7521e84f157ee1:",
         "  supplied full-suite.diff: full suite 0 failures; race 0 failures/warnings",
         "Fix source 139abea637e4521967766eacad0d7c1d9b48679c:"]
for name in ("full-serial.jsonl", "full-race-serial.jsonl"):
    result = summary[name]
    code = (root / (name.removesuffix(".jsonl") + ".exit")).read_text().strip()
    lines.append(f"  {name}: exit {code}; test/subtest outcomes {result['test_outcomes_including_parents']}; "
                 f"leaf tests {result['leaf_tests']}; "
                 f"packages {result['packages']}; 0 race warnings")
lines.append("  Race failures: inherited MCP cleanup timeouts only, independently reproduced")
lines.append("  under default -race on unchanged carrier 8cb0b92 (carrier-mcp-race-repeat.jsonl).")
lines.append("  All final race failed tests/packages are in that exact-source baseline failure set.")
lines.append("  New failed tests/packages vs independently reproduced carrier baseline: 0")
lines.append("Intermediate failures are preserved in summary.json and commands.md.")
(root / "comparison.txt").write_text("\n".join(lines) + "\n")
print("\n".join(lines))
