#!/usr/bin/env python3
"""Public HTTP observations and UTC reports using only the Python standard library."""

import argparse
from collections import defaultdict
from datetime import datetime, timedelta, timezone
import fcntl
import http.client
import json
import math
import os
from pathlib import Path
import time
import urllib.error
import urllib.parse
import urllib.request

UTC = timezone.utc
PATHS = ("/healthz", "/readyz", "/", "/dl/latest.json")


def stamp(value):
    return value.astimezone(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


def parse_stamp(value):
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("timestamp must have a timezone")
    return parsed.astimezone(UTC)


def base_url(value):
    parsed = urllib.parse.urlsplit(value)
    if (parsed.username or parsed.password or parsed.query or parsed.fragment
            or parsed.path not in ("", "/")):
        raise ValueError("base URL must be an origin without credentials")
    if not (parsed.scheme == "https" and parsed.hostname == "tunn.to"
            and parsed.port in (None, 443)):
        if not (parsed.scheme == "http" and parsed.hostname in ("127.0.0.1", "::1")):
            raise ValueError("use https://tunn.to or an HTTP loopback test server")
    return value.rstrip("/")


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def request(origin, path, timeout):
    started = time.monotonic()
    result = {"path": path, "method": "GET", "status": None, "ok": False, "error": None}
    # No ambient proxy, cookies, netrc, authorization or redirect forwarding.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    req = urllib.request.Request(origin + path, method="GET", headers={
        "User-Agent": "tunn-status-observer/1", "Accept": "*/*"})
    try:
        with opener.open(req, timeout=timeout) as response:
            result["status"] = response.status
            result["ok"] = response.status == 200
            # Header latency avoids downloading/storing public page bodies.
    except urllib.error.HTTPError as exc:
        result["status"] = exc.code
        result["error"] = "http_error"
        exc.close()
    except (urllib.error.URLError, TimeoutError, OSError, ValueError, http.client.HTTPException) as exc:
        # Store only exception classes, never response bodies or error URLs.
        result["error"] = type(exc).__name__
    result["latency_ms"] = round((time.monotonic() - started) * 1000, 3)
    return result


def append(path, row):
    payload = (json.dumps(row, sort_keys=True, allow_nan=False) + "\n").encode()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    try:
        with os.fdopen(fd, "ab", closefd=False) as output:
            output.write(payload)
            output.flush()
            os.fsync(fd)
    finally:
        os.close(fd)


def collect(directory, origin, timeout):
    origin = base_url(origin)
    started = datetime.now(UTC)
    raw = directory / "raw"
    raw.mkdir(parents=True, exist_ok=True, mode=0o700)
    path = raw / (started.date().isoformat() + ".jsonl")
    # A torn write is evidence, not permission to rewrite historical observations.
    if path.exists() and path.stat().st_size:
        with path.open("rb") as source:
            source.seek(-1, os.SEEK_END)
            if source.read(1) != b"\n":
                raise ValueError("incomplete JSONL tail; preserve and investigate before collecting")
    for endpoint in PATHS:
        result = request(origin, endpoint, timeout)
        result.update(version=1, timestamp=stamp(started), origin=origin)
        append(path, result)


def observations(directory):
    rows, corrupt = [], 0
    for path in sorted((directory / "raw").glob("*.jsonl")):
        with path.open() as source:
            for line in source:
                try:
                    row = json.loads(line)
                    timestamp = parse_stamp(row["timestamp"])
                    if (row["version"] != 1 or row["path"] not in PATHS
                            or row["method"] != "GET" or type(row["ok"]) is not bool
                            or row["ok"] != (row["status"] == 200)
                            or not math.isfinite(row["latency_ms"]) or row["latency_ms"] < 0
                            or not line.endswith("\n")):
                        raise ValueError("invalid observation")
                    base_url(row["origin"])
                    rows.append((timestamp, row))
                except (KeyError, ValueError, TypeError, OverflowError):
                    corrupt += 1
    if len({row["origin"] for _, row in rows}) > 1:
        raise ValueError("mixed origins; use a separate data directory per origin")
    return sorted(rows, key=lambda item: item[0]), corrupt


def percentile(values, fraction):
    return sorted(values)[max(0, math.ceil(len(values) * fraction) - 1)] if values else None


def summary(rows, start, end, availability, latency):
    # Include the first observation's minute and exclude the end minute boundary.
    first = start.replace(second=0, microsecond=0)
    expected = max(0, math.ceil((end - first).total_seconds() / 60))
    endpoints = {}
    for path in PATHS:
        slots = defaultdict(list)
        for timestamp, row in rows:
            if row["path"] == path and start <= timestamp < end:
                slots[timestamp.replace(second=0, microsecond=0)].append(row)
        successful = sum(all(row["ok"] for row in bucket) for bucket in slots.values())
        times = [row["latency_ms"] for bucket in slots.values() for row in bucket if row["ok"]]
        observed = len(slots)
        conservative = 100 * successful / expected if expected else None
        p95 = percentile(times, .95)
        endpoints[path] = {
            "expected_minutes": expected, "observed_minutes": observed,
            "missing_minutes": max(0, expected - observed),
            "failed_minutes": observed - successful,
            "coverage_pct": 100 * observed / expected if expected else None,
            "observed_uptime_pct": 100 * successful / observed if observed else None,
            "availability_including_gaps_pct": conservative,
            "latency_ms": {"p50": percentile(times, .5), "p95": p95, "max": max(times) if times else None},
            "slo_met": conservative is not None and conservative >= availability
            and p95 is not None and p95 <= latency,
        }
    return endpoints


def report(directory, now, availability=99.9, latency=1000):
    rows, corrupt = observations(directory)
    if rows and rows[-1][0] > now:
        raise ValueError("observations are in the future; check the system clock")
    start = rows[0][0] if rows else None
    elapsed = max(0, (now - start).total_seconds() / 86400) if start else 0
    endpoints = summary(rows, start, now + timedelta(microseconds=1), availability, latency) if start else {}
    return {
        "generated_at": stamp(now), "start_date": stamp(start) if start else None,
        "origin": rows[0][1]["origin"] if rows else None,
        "target_days": 30, "elapsed_days": round(elapsed, 6),
        "days_remaining_to_30": max(0, math.ceil(30 - elapsed)),
        "corrupt_records": corrupt, "observations": len(rows),
        "targets": {"availability_pct": availability, "p95_header_latency_ms": latency},
        "endpoints": endpoints,
        "thirty_days_complete": elapsed >= 30 and corrupt == 0
        and all(item["missing_minutes"] == 0 for item in endpoints.values()),
    }


def rollup(directory, now):
    rows, corrupt = observations(directory)
    if corrupt:
        raise ValueError("corrupt records; preserve raw files and investigate before rollup")
    if not rows:
        return []
    if rows[-1][0] > now:
        raise ValueError("observations are in the future; check the system clock")
    output = directory / "daily"
    output.mkdir(exist_ok=True, mode=0o700)
    day = rows[0][0].replace(hour=0, minute=0, second=0, microsecond=0)
    written = []
    while day.date() < now.date():
        path = output / (day.date().isoformat() + ".json")
        if not path.exists():
            end = day + timedelta(days=1)
            result = {"date": day.date().isoformat(), "origin": rows[0][1]["origin"],
                      "endpoints": summary(rows, max(day, rows[0][0]), end, 99.9, 1000)}
            with path.open("x") as destination:
                json.dump(result, destination, sort_keys=True, indent=2, allow_nan=False)
                destination.write("\n")
                destination.flush()
                os.fsync(destination.fileno())
            written.append(str(path))
        day += timedelta(days=1)
    return written


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("probe", "rollup", "report"))
    parser.add_argument("--data-dir", type=Path, required=True)
    parser.add_argument("--base-url", default="https://tunn.to")
    parser.add_argument("--timeout", type=float, default=8)
    parser.add_argument("--availability", type=float, default=99.9)
    parser.add_argument("--latency-ms", type=float, default=1000)
    args = parser.parse_args()
    if not (0 < args.timeout <= 10 and 0 <= args.availability <= 100 and 0 < args.latency_ms < math.inf):
        parser.error("timeout must be (0,10], availability [0,100], latency finite and positive")
    directory = args.data_dir.expanduser().resolve()
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    # All commands share a lock so reports never read an in-progress append.
    with (directory / ".observer.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        try:
            if args.command == "probe":
                collect(directory, args.base_url, args.timeout)
            elif args.command == "rollup":
                print(json.dumps({"written": rollup(directory, datetime.now(UTC))}))
            else:
                print(json.dumps(report(directory, datetime.now(UTC), args.availability, args.latency_ms),
                                 indent=2, sort_keys=True, allow_nan=False))
        except (OSError, ValueError) as exc:
            parser.exit(1, str(exc) + "\n")


if __name__ == "__main__":
    main()
