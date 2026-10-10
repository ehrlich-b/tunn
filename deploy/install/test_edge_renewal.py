"""Wildcard renewal correctness using fixture executables, never live tools."""

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


# Every network, certificate, authentication and publication executable is a
# fixture. Only the explicitly listed local file/text utilities reach the OS.
FAKE_COMMAND = r'''
import base64
import json
import os
from pathlib import Path
import stat
import subprocess
import sys

name = Path(sys.argv[0]).name
args = sys.argv[1:]
root = Path(os.environ["TUNN_EDGE_FIXTURE_ROOT"])
scenario = os.environ["TUNN_EDGE_SCENARIO"]
with (root / "events").open("a") as stream:
    stream.write(json.dumps({"command": name, "args": args}) + "\n")
lineage = root / "certbot" / "config" / "live" / "edge.example.com"
published = root / "published"

if name == "certbot":
    credentials = root / "certbot" / "cloudflare.ini"
    assert stat.S_IMODE(credentials.stat().st_mode) == 0o600
    assert credentials.read_text() == "dns_cloudflare_api_token = fixture-cloudflare-token\n"
    if scenario == "certbot_failure":
        sys.exit(2)
    lineage.mkdir(parents=True, exist_ok=True)
    (lineage / "fullchain.pem").write_text("fixture-certificate\n")
    (lineage / "privkey.pem").write_text("fixture-private-key\n")
elif name == "openssl":
    if args[0] == "s_client":
        print("serial=NEW" if scenario == "already_current" or published.exists() and scenario != "never_current" else "serial=OLD")
    elif args[0] == "x509":
        if "-checkend" in args:
            sys.exit(1 if scenario == "expires_soon" else 0)
        if "-checkhost" in args:
            host = args[args.index("-checkhost") + 1]
            if "TUNN_EDGE_REAL_TLS_FILE" in os.environ:
                result = subprocess.run([os.environ["TUNN_EDGE_REAL_OPENSSL"], "x509", "-in",
                                         os.environ["TUNN_EDGE_REAL_TLS_FILE"], "-noout", "-checkhost", host],
                                        capture_output=True, timeout=5)
                sys.exit(result.returncode)
            sys.exit(1 if scenario == "wrong_domain" or scenario == "missing_wildcard" and host != "edge.example.com" else 0)
        if "-pubkey" in args:
            print("fixture-public-key")
        elif "-serial" in args:
            print("serial=NEW" if "-in" in args else sys.stdin.read().strip())
        else:
            print("fixture certificate metadata")
    elif args[0] == "pkey":
        if "-pubin" in args:
            sys.stdout.write(sys.stdin.read())
        else:
            print("different-public-key" if scenario == "mismatched_key" else "fixture-public-key")
elif name == "flyctl":
    assert args[:2] == ["secrets", "import"], "fixture must not authenticate"
    assert os.environ["FLY_API_TOKEN"] == "fixture-fly-token"
    values = dict(line.split("=", 1) for line in sys.stdin.read().splitlines())
    assert set(values) == {"TUNN_CERT_DATA", "TUNN_KEY_DATA", "TUNN_CLOUDFLARE_API_TOKEN"}
    assert base64.b64decode(values["TUNN_CERT_DATA"]) == b"fixture-certificate\n"
    assert base64.b64decode(values["TUNN_KEY_DATA"]) == b"fixture-private-key\n"
    assert values["TUNN_CLOUDFLARE_API_TOKEN"] == "fixture-cloudflare-token"
    if scenario == "publication_failure":
        sys.exit(1)
    published.write_text("fixture publication completed")
elif name == "curl":
    assert args[-1] == "https://edge.example.com/"
    sys.exit(22 if scenario in ("health_failure", "wrong_domain", "missing_wildcard") else 0)
elif name in ("security", "jq"):
    raise AssertionError("fixture environment supplies tokens; no credential lookup is allowed")
elif name != "sleep":
    raise AssertionError("unexpected fixture command " + name)
'''


class RenewalTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="edge renewal fixture ")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.script = Path(__file__).resolve().parents[2] / "renew-certs.sh"
        for name in ("certbot", "curl", "flyctl", "jq", "openssl", "security", "sleep"):
            command = self.bin / name
            command.write_text(f"#!{sys.executable}\n" + FAKE_COMMAND)
            command.chmod(0o700)
        for name in ("mkdir", "chmod", "rm", "shasum", "awk", "sed", "tr", "head", "cut", "base64"):
            executable = shutil.which(name)
            self.assertIsNotNone(executable, f"fixture requires local utility {name}")
            (self.bin / name).symlink_to(executable)

    def run_renewal(self, scenario="success", existing=False, real_certificate=None):
        if existing:
            (self.root / "certbot" / "config" / "live" / "edge.example.com").mkdir(parents=True)
        env = {"PATH": str(self.bin), "TUNN_EDGE_FIXTURE_ROOT": str(self.root),
               "TUNN_EDGE_SCENARIO": scenario, "TUNN_CERT_DOMAIN": "edge.example.com",
               "TUNN_FLY_APP": "fixture-app", "TUNN_CERT_EMAIL": "fixture@example.com",
               "TUNN_CERTBOT_ROOT": str(self.root / "certbot"),
               "TUNN_CLOUDFLARE_API_TOKEN": "fixture-cloudflare-token",
               "FLY_API_TOKEN": "fixture-fly-token"}
        if real_certificate is not None:
            env.update(TUNN_EDGE_REAL_TLS_FILE=str(real_certificate), TUNN_EDGE_REAL_OPENSSL=shutil.which("openssl"))
        result = subprocess.run(["/bin/bash", str(self.script)], env=env, cwd=self.root,
                                capture_output=True, text=True, timeout=20)
        self.assertFalse((self.root / "certbot" / "cloudflare.ini").exists(), "credential file survived workflow exit")
        for secret in ("fixture-cloudflare-token", "fixture-fly-token", "fixture-private-key"):
            self.assertNotIn(secret, result.stdout + result.stderr)
        events = [json.loads(line) for line in (self.root / "events").read_text().splitlines()]
        return result, events

    def test_initial_issue_and_successful_publication(self):
        result, events = self.run_renewal()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue((self.root / "published").exists())
        issue = next(event for event in events if event["command"] == "certbot")
        self.assertEqual(issue["args"][0], "certonly")
        self.assertIn("edge.example.com", issue["args"])
        self.assertIn("*.edge.example.com", issue["args"])
        self.assertEqual(sum(event["command"] == "flyctl" for event in events), 1)
        self.assertIn("Certificate deployed", result.stdout)

    def test_existing_lineage_renews_and_already_current_avoids_publication(self):
        result, events = self.run_renewal("already_current", existing=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        renew = next(event for event in events if event["command"] == "certbot")
        self.assertEqual(renew["args"][0], "renew")
        self.assertFalse(any(event["command"] == "flyctl" for event in events))
        self.assertIn("already current", result.stdout)

    def test_certbot_failure_retains_credentials_privately_until_cleanup(self):
        result, events = self.run_renewal("certbot_failure")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(any(event["command"] == "flyctl" for event in events))

    def test_expiring_certificate_refuses_publication(self):
        result, events = self.run_renewal("expires_soon")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("expires within 30 days", result.stderr)
        self.assertFalse(any(event["command"] == "flyctl" for event in events))

    def test_mismatched_key_refuses_publication(self):
        result, events = self.run_renewal("mismatched_key")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("do not match", result.stderr)
        self.assertFalse(any(event["command"] == "flyctl" for event in events))

    def test_wrong_domain_refuses_publication(self):
        result, events = self.run_renewal("wrong_domain")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(any(event["command"] == "flyctl" for event in events))

    def test_missing_wildcard_refuses_publication(self):
        result, events = self.run_renewal("missing_wildcard")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(any(event["command"] == "flyctl" for event in events))

    def test_publication_failure_reports_failure_and_cleans_up(self):
        result, events = self.run_renewal("publication_failure")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.root / "published").exists())
        self.assertFalse(any(event["command"] == "curl" for event in events))

    def test_expected_serial_must_become_visible(self):
        result, events = self.run_renewal("never_current")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("did not become healthy", result.stderr)
        self.assertEqual(sum(event["command"] == "sleep" for event in events), 15)
        self.assertFalse(any(event["command"] == "curl" for event in events))

    def test_health_failure_is_not_reported_as_success(self):
        result, events = self.run_renewal("health_failure")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("did not become healthy", result.stderr)
        self.assertEqual(sum(event["command"] == "curl" for event in events), 15)

    def test_real_certificate_names_are_checked_before_publication(self):
        openssl = shutil.which("openssl")
        self.assertIsNotNone(openssl, "fixture requires local openssl for certificate generation")
        cert, key = self.root / "real-certificate.pem", self.root / "real-key.pem"
        for names, valid in (("DNS:other.example.com", False), ("DNS:edge.example.com", False),
                             ("DNS:edge.example.com,DNS:tunn-cert-check.edge.example.com", False),
                             ("DNS:edge.example.com,DNS:*.edge.example.com", True)):
            with self.subTest(names=names):
                (self.root / "events").unlink(missing_ok=True)
                (self.root / "published").unlink(missing_ok=True)
                subprocess.run([openssl, "req", "-x509", "-newkey", "ed25519", "-nodes", "-days", "90",
                                "-subj", "/CN=edge.example.com", "-addext", "subjectAltName=" + names,
                                "-keyout", str(key), "-out", str(cert)], check=True,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)
                result, events = self.run_renewal(real_certificate=cert)
                self.assertEqual(result.returncode == 0, valid, result.stderr)
                self.assertEqual(any(event["command"] == "flyctl" for event in events), valid)
                if not valid:
                    self.assertIn("must cover the apex and wildcard", result.stderr)


if __name__ == "__main__":
    unittest.main()
