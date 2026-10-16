#!/usr/bin/env python3
"""Exercise schedule installation in disposable homes with a launchctl substitute."""
import importlib.util
import os
from pathlib import Path
import plistlib
import signal
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock


REPO = Path(__file__).resolve().parents[1]
RENDERER = REPO / "scripts/cert-renewal-plist.py"
SPEC = importlib.util.spec_from_file_location("cert_renewal_plist", RENDERER)
renderer = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(renderer)


class ScheduleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="tunn-schedule-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.home = self.root / "home & <operator>"
        self.home.mkdir()
        self.shim = self.root / "shim"
        self.shim.mkdir()
        self.calls = self.root / "launchctl.calls"
        launchctl = self.shim / "launchctl"
        launchctl.write_text('#!/bin/sh\nprintf "%s\\n" "$*" >> "$SCHEDULE_CALLS"\n')
        launchctl.chmod(0o700)
        self.env = dict(os.environ, HOME=str(self.home),
                        PATH=f"{self.shim}:{os.environ['PATH']}",
                        SCHEDULE_CALLS=str(self.calls),
                        TUNN_CERT_DOMAIN="example.com", TUNN_FLY_APP="example-relay",
                        TUNN_CERT_EMAIL="operator@example.com")
        self.destination = self.home / "Library/LaunchAgents/com.ehrlich.tunn-cert-renewal.plist"
        self.command = ["make", "--no-print-directory", "cert-install-schedule"]

    def make(self, expected=0):
        result = subprocess.run(self.command, cwd=REPO, env=self.env,
                                capture_output=True, text=True, timeout=20)
        self.assertEqual(result.returncode, expected, result.stdout + result.stderr)
        return result

    def seed(self):
        self.make()
        previous = self.destination.read_bytes()
        self.calls.unlink()
        return previous

    def assert_private_job(self):
        self.assertFalse(self.destination.is_symlink())
        mode = self.destination.stat().st_mode
        self.assertTrue(stat.S_ISREG(mode))
        self.assertEqual(stat.S_IMODE(mode), 0o600)
        return plistlib.loads(self.destination.read_bytes())

    def test_fresh_install_and_repeat(self):
        self.make()
        job = self.assert_private_job()
        self.assertEqual(job["Label"], "com.ehrlich.tunn-cert-renewal")
        self.assertEqual(job["ProgramArguments"], [str(REPO / "renew-certs.sh")])
        self.assertEqual(job["WorkingDirectory"], str(REPO))
        self.assertEqual(job["EnvironmentVariables"]["HOME"], str(self.home))
        self.assertEqual(job["EnvironmentVariables"]["TUNN_CERT_EMAIL"], "operator@example.com")
        self.assertIs(job["RunAtLoad"], True)
        self.assertIs(type(job["StartInterval"]), int)
        self.assertEqual(job["StartInterval"], 86400)
        self.assertEqual(job["ThrottleInterval"], 3600)
        self.env["TUNN_CERT_EMAIL"] = "updated@example.com"
        self.make()
        job = self.assert_private_job()
        self.assertEqual(job["EnvironmentVariables"]["TUNN_CERT_EMAIL"], "updated@example.com")
        self.assertEqual(len(self.calls.read_text().splitlines()), 4)

    def test_replaces_permissive_file_with_private_file(self):
        self.seed()
        self.destination.chmod(0o644)
        self.make()
        self.assert_private_job()

    def test_replaces_symlink_without_touching_target(self):
        previous = self.seed()
        target = self.root / "other.plist"
        target.write_bytes(previous)
        target.chmod(0o644)
        self.destination.unlink()
        self.destination.symlink_to(target)
        self.env["TUNN_CERT_EMAIL"] = "updated@example.com"
        self.make()
        self.assert_private_job()
        self.assertEqual(target.read_bytes(), previous)
        self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o644)

    def test_render_failure_preserves_previous_definition(self):
        previous = self.seed()
        self.env["TUNN_CERT_EMAIL"] = "operator\x01@example.com"
        result = self.make(expected=2)
        self.assertIn("ValueError", result.stderr)
        self.assertEqual(self.destination.read_bytes(), previous)
        self.assertFalse(self.calls.exists())
        self.assertEqual(list(self.destination.parent.iterdir()), [self.destination])
        self.env["TUNN_CERT_EMAIL"] = "retry@example.com"
        self.make()
        self.assert_private_job()

    def test_validation_failure_preserves_previous_definition(self):
        previous = self.seed()
        with self.assertRaises(plistlib.InvalidFileException):
            renderer.install(self.destination, b"incomplete plist")
        self.assertEqual(self.destination.read_bytes(), previous)
        self.assertEqual(list(self.destination.parent.iterdir()), [self.destination])

    def test_replace_failure_preserves_previous_definition(self):
        previous = self.seed()
        with mock.patch.object(renderer.os, "replace", side_effect=OSError("replace failed")):
            with self.assertRaisesRegex(OSError, "replace failed"):
                renderer.install(self.destination, previous)
        self.assertEqual(self.destination.read_bytes(), previous)
        self.assertEqual(list(self.destination.parent.iterdir()), [self.destination])

    def test_interruption_before_replacement_preserves_previous_definition(self):
        previous = self.seed()
        marker = self.root / "staged"
        wrapper = self.shim / "python3"
        wrapper.write_text(f"#!{sys.executable}\n" + '''import os, pathlib, runpy, signal, sys
def pause_before_replace(source, destination):
    pathlib.Path(os.environ["SCHEDULE_STAGED"]).touch()
    signal.pause()
    raise RuntimeError("unexpected continuation")
os.replace = pause_before_replace
sys.argv = sys.argv[1:]
runpy.run_path(sys.argv[0], run_name="__main__")
''')
        wrapper.chmod(0o700)
        self.env["SCHEDULE_STAGED"] = str(marker)
        process = subprocess.Popen(self.command, cwd=REPO, env=self.env,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   start_new_session=True)
        try:
            deadline = time.monotonic() + 10
            while not marker.exists() and process.poll() is None and time.monotonic() < deadline:
                time.sleep(0.01)
            self.assertTrue(marker.exists(), "installer did not reach replacement")
            self.assertEqual(self.destination.read_bytes(), previous)
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGTERM)
            process.communicate(timeout=10)
        self.assertNotEqual(process.returncode, 0)
        self.assertEqual(self.destination.read_bytes(), previous)
        self.assertFalse(self.calls.exists())
        wrapper.unlink()
        self.make()
        self.assert_private_job()


if __name__ == "__main__":
    unittest.main(verbosity=2)
