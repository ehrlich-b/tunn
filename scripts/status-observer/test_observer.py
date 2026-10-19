from datetime import datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

import observer


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.server.requests.append((self.command, self.path, dict(self.headers)))
        if self.path == "/readyz":
            self.send_response(503)
        elif self.path == "/dl/latest.json":
            self.send_response(302)
            self.send_header("Location", "/must-not-follow")
        else:
            self.send_response(200)
        self.end_headers()

    def log_message(self, *_):
        pass


class ObserverTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.data = Path(self.temp.name)
        self.start = datetime(2026, 1, 1, 23, 58, tzinfo=observer.UTC)

    def row(self, timestamp, path, ok=True, latency=12):
        return {"version": 1, "timestamp": observer.stamp(timestamp),
                "origin": "http://127.0.0.1:1234", "method": "GET", "path": path,
                "ok": ok, "status": 200 if ok else 503, "error": None,
                "latency_ms": latency}

    def seed(self, timestamp, ok=True):
        raw = self.data / "raw"
        raw.mkdir(exist_ok=True)
        for path in observer.PATHS:
            observer.append(raw / (timestamp.date().isoformat() + ".jsonl"),
                            self.row(timestamp, path, ok))

    def test_fake_server_get_only_no_credentials_no_redirects_and_append(self):
        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        server.requests = []
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(thread.join)
        self.addCleanup(server.shutdown)
        origin = "http://127.0.0.1:" + str(server.server_port)
        with patch.dict(os.environ, {"http_proxy": "http://127.0.0.1:1", "HTTP_PROXY": "http://127.0.0.1:1"}):
            observer.collect(self.data, origin, 1)
            before = next((self.data / "raw").glob("*.jsonl")).read_bytes()
            observer.collect(self.data, origin, 1)
        self.assertEqual([item[:2] for item in server.requests],
                         [("GET", path) for path in observer.PATHS] * 2)
        for _, _, headers in server.requests:
            self.assertFalse({key.lower() for key in headers} & {"cookie", "authorization", "proxy-authorization"})
        contents = next((self.data / "raw").glob("*.jsonl")).read_bytes()
        self.assertTrue(contents.startswith(before))
        rows, corrupt = observer.observations(self.data)
        self.assertEqual((len(rows), corrupt), (8, 0))
        self.assertEqual([row["status"] for _, row in rows[:4]], [200, 503, 200, 302])
        self.assertEqual([row["ok"] for _, row in rows[:4]], [True, False, True, False])
        self.assertTrue(all(row["latency_ms"] >= 0 for _, row in rows))
        print("Fake HTTP server: eight GETs, fixed four paths, no credentials or redirect follow; append prefix intact.")

    def test_connection_failures_are_durable_observations(self):
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
            # Bound, non-listening socket deterministically refuses connections.
            observer.collect(self.data, "http://127.0.0.1:" + str(port), .1)
        rows, corrupt = observer.observations(self.data)
        self.assertEqual((len(rows), corrupt), (4, 0))
        self.assertTrue(all(not row["ok"] and row["error"] for _, row in rows))

    def test_timeout_and_malformed_http_are_recorded(self):
        for error in (TimeoutError(), observer.http.client.BadStatusLine("invalid")):
            with self.subTest(error=type(error).__name__):
                with patch.object(observer.urllib.request.OpenerDirector, "open", side_effect=error):
                    result = observer.request("https://tunn.to", "/healthz", .1)
                self.assertFalse(result["ok"])
                self.assertEqual(result["error"], type(error).__name__)

    def test_rotation_and_rollups_preserve_raw_and_previous_summaries(self):
        self.seed(self.start)
        self.seed(self.start + timedelta(minutes=1), False)
        first = (self.data / "raw/2026-01-01.jsonl").read_bytes()
        self.seed(self.start + timedelta(minutes=2))
        self.assertEqual((self.data / "raw/2026-01-01.jsonl").read_bytes(), first)
        now = self.start + timedelta(days=3)
        self.assertEqual(len(observer.rollup(self.data, now)), 3)
        daily = self.data / "daily/2026-01-01.json"
        previous = daily.read_bytes()
        self.assertEqual(observer.rollup(self.data, now), [])
        self.assertEqual(daily.read_bytes(), previous)
        self.assertEqual((self.data / "raw/2026-01-01.jsonl").read_bytes(), first)
        one = json.loads(previous)["endpoints"]["/healthz"]
        self.assertEqual((one["expected_minutes"], one["failed_minutes"]), (2, 1))
        empty = json.loads((self.data / "daily/2026-01-03.json").read_text())["endpoints"]["/"]
        self.assertEqual((empty["expected_minutes"], empty["missing_minutes"]), (1440, 1440))
        print("UTC rotation and daily catch-up: raw bytes and existing daily summaries unchanged; missing day has 1440 gaps.")

    def test_report_counts_gaps_failures_duplicates_and_latency(self):
        self.seed(self.start)
        self.seed(self.start + timedelta(minutes=2))
        self.seed(self.start + timedelta(minutes=2), False)
        result = observer.report(self.data, self.start + timedelta(minutes=3))
        endpoint = result["endpoints"]["/healthz"]
        self.assertEqual((endpoint["expected_minutes"], endpoint["observed_minutes"],
                          endpoint["missing_minutes"], endpoint["failed_minutes"]), (4, 2, 2, 1))
        self.assertEqual(endpoint["observed_uptime_pct"], 50)
        self.assertEqual(endpoint["availability_including_gaps_pct"], 25)
        self.assertEqual(endpoint["latency_ms"], {"p50": 12, "p95": 12, "max": 12})
        self.assertFalse(endpoint["slo_met"])
        self.assertFalse(result["thirty_days_complete"])

    def test_start_date_days_remaining_and_30_day_completeness(self):
        empty = observer.report(self.data, self.start)
        self.assertIsNone(empty["start_date"])
        self.assertEqual(empty["days_remaining_to_30"], 30)
        self.seed(self.start)
        for elapsed, remaining in ((0, 30), (1, 29), (29, 1), (30, 0), (31, 0)):
            result = observer.report(self.data, self.start + timedelta(days=elapsed))
            self.assertEqual(result["start_date"], observer.stamp(self.start))
            self.assertEqual(result["days_remaining_to_30"], remaining)
            self.assertFalse(result["thirty_days_complete"])
        rows = [(self.start + timedelta(minutes=minute), self.row(self.start + timedelta(minutes=minute), path))
                for minute in range(30 * 1440 + 1) for path in observer.PATHS]
        with patch.object(observer, "observations", return_value=(rows, 0)):
            result = observer.report(self.data, self.start + timedelta(days=30))
        self.assertTrue(result["thirty_days_complete"])
        self.assertTrue(all(item["slo_met"] for item in result["endpoints"].values()))
        print("Clock: null start before observations; remaining days 30/29/1/0/0; only complete coverage earns 30-day completion.")

    def test_corrupt_tail_is_preserved_and_never_counts_as_success(self):
        self.seed(self.start)
        raw = self.data / "raw/2026-01-01.jsonl"
        with raw.open("ab") as output:
            output.write(b'{"timestamp":')
        contents = raw.read_bytes()
        result = observer.report(self.data, self.start + timedelta(days=30))
        self.assertEqual(result["corrupt_records"], 1)
        self.assertFalse(result["thirty_days_complete"])
        with self.assertRaisesRegex(ValueError, "corrupt"):
            observer.rollup(self.data, self.start + timedelta(days=1))
        with patch.object(observer, "datetime") as clock:
            clock.now.return_value = self.start
            with self.assertRaisesRegex(ValueError, "incomplete"):
                observer.collect(self.data, "http://127.0.0.1:1", .1)
        self.assertEqual(raw.read_bytes(), contents)

    def test_invalid_origins_and_future_clock(self):
        for origin in ("http://tunn.to", "https://user:password@tunn.to", "https://tunn.to/a",
                       "https://example.com", "https://tunn.to/?secret=yes", "https://tunn.to/#x"):
            with self.subTest(origin=origin), self.assertRaises(ValueError):
                observer.base_url(origin)
        self.seed(self.start)
        with self.assertRaisesRegex(ValueError, "future"):
            observer.report(self.data, self.start - timedelta(seconds=1))

    def test_cli_report_and_invalid_configuration(self):
        script = str(Path(observer.__file__).resolve())
        result = subprocess.run([sys.executable, script, "report", "--data-dir", str(self.data)],
                                capture_output=True, text=True, check=True)
        self.assertEqual(json.loads(result.stdout)["days_remaining_to_30"], 30)
        for flags in (["--timeout", "nan"], ["--timeout", "11"], ["--latency-ms", "inf"]):
            result = subprocess.run([sys.executable, script, "probe", "--data-dir", str(self.data), *flags],
                                    capture_output=True, text=True)
            self.assertEqual(result.returncode, 2)

    def test_user_timer_contract(self):
        directory = Path(observer.__file__).parent
        for name in ("tunn-status", "tunn-status-rollup"):
            timer = (directory / (name + ".timer")).read_text()
            self.assertIn("Persistent=true", timer)
            self.assertIn("WantedBy=timers.target", timer)
            service = (directory / (name + ".service")).read_text()
            self.assertIn("UMask=0077", service)
            self.assertIn("Nice=10", service)
            self.assertNotIn("--base-url", service)
        self.assertIn("OnCalendar=*-*-* *:*:00 UTC", (directory / "tunn-status.timer").read_text())


if __name__ == "__main__":
    unittest.main()
