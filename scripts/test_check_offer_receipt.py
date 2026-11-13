#!/usr/bin/env python3
"""Offline stdlib receipts; none of these fixtures establishes a live fact."""

import ast
from contextlib import redirect_stdout
import copy
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import secrets
import socket
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch


SCRIPT = Path(__file__).with_name("check-offer-receipt.py")
spec = importlib.util.spec_from_file_location("check_offer_receipt", SCRIPT)
receipt = importlib.util.module_from_spec(spec)
spec.loader.exec_module(receipt)
HEAD, VERSION, DIGEST = "a" * 40, "v1.2.3", hashlib.sha256(b"fixture client").hexdigest()


def fixture():
    data = {
        "schema_version": 1, "evidence_kind": receipt.SYNTHETIC,
        "observed_at": "2026-11-12T12:00:00Z", "source_head": HEAD,
        "version": VERSION, "client_sha256": DIGEST,
        "public_report_sha256": hashlib.sha256(receipt.PUBLIC_REPORT).hexdigest(),
        "authenticated": {
            "account_plan": "Free", "second_name_offer": True,
            "period": "monthly", "amount_minor": 500, "currency": "USD",
            "provenance": {"source": "private_window_and_client",
                           "redacted_evidence_sha256": hashlib.sha256(b"synthetic offer").hexdigest()},
            "merchant": {"confirmed": True, "display_name": "Synthetic merchant only",
                         "provenance": {"source": "existing_merchant_dashboard",
                                        "redacted_evidence_sha256": hashlib.sha256(b"synthetic merchant").hexdigest()}}}}
    data["signature"] = receipt.signature(data, receipt.FIXTURE_KEY)
    return data


class ReceiptTests(unittest.TestCase):
    def check(self, data, report=receipt.PUBLIC_REPORT, key=receipt.FIXTURE_KEY):
        with patch.object(socket, "socket", side_effect=AssertionError("network forbidden")):
            return receipt.check(data, report, HEAD, VERSION, DIGEST, key)

    def test_required_synthetic_matrix(self):
        cases = {}
        cases["complete_synthetic"] = (fixture(), {"real_operator_observation"})
        data = fixture()
        del data["authenticated"]["merchant"]
        cases["missing_merchant"] = (data, {"authenticated.merchant.confirmed",
                                           "authenticated.merchant.provenance.source"})
        data = fixture()
        data["version"] = "v9.9.9"
        cases["wrong_version"] = (data, {"version"})
        data = fixture()
        data["authenticated"]["period"] = "yearly"
        cases["wrong_period"] = (data, {"authenticated.period"})
        data = fixture()
        data["client_sha256"] = "b" * 64
        cases["changed_digest"] = (data, {"client_sha256"})
        data = fixture()
        del data["authenticated"]
        cases["absent_authenticated_observation"] = (data, {"authenticated.second_name_offer",
                                                           "authenticated.merchant.confirmed"})
        for name, (data, expected) in cases.items():
            with self.subTest(case=name):
                # Valid signatures cannot rescue missing or inconsistent facts.
                data["signature"] = receipt.signature(data, receipt.FIXTURE_KEY)
                result = self.check(data)
                self.assertFalse(result["complete"])
                self.assertEqual(result["evidence_kind"], receipt.SYNTHETIC)
                self.assertTrue(result["operator_signature_valid"])
                self.assertTrue(expected.issubset(result["missing_fields"]))
                if name == "complete_synthetic":
                    self.assertEqual(result["missing_fields"], ["real_operator_observation"])
                print(json.dumps({"case": name, **result}, sort_keys=True))

    def test_unsigned_untrusted_and_tampered_observations(self):
        for key in (None, b"short", secrets.token_bytes(32)):
            result = self.check(fixture(), key=key)
            self.assertIn("operator_signature", result["missing_fields"])
        data = fixture()
        data["authenticated"]["amount_minor"] = 999
        self.assertIn("operator_signature", self.check(data)["missing_fields"])
        data = fixture()
        data["evidence_kind"] = "OPERATOR_OBSERVATION"
        data["signature"] = receipt.signature(data, receipt.FIXTURE_KEY)
        self.assertEqual(self.check(data)["evidence_kind"], receipt.SYNTHETIC)
        self.assertFalse(self.check(data)["complete"])

    def test_real_observation_path_requires_every_field_and_trusted_key(self):
        # Exercise the operator branch in memory only; no live receipt is emitted.
        data = fixture()
        data["evidence_kind"] = "OPERATOR_OBSERVATION"
        key = secrets.token_bytes(32)
        data["signature"] = receipt.signature(data, key)
        self.assertTrue(self.check(data, key=key)["complete"])
        for path in ("observed_at", "source_head", "version", "client_sha256", "signature",
                     "public_report_sha256", "authenticated.account_plan",
                     "authenticated.second_name_offer", "authenticated.period",
                     "authenticated.amount_minor", "authenticated.currency",
                     "authenticated.provenance", "authenticated.merchant"):
            with self.subTest(path=path):
                altered = copy.deepcopy(data)
                parent = altered
                parts = path.split(".")
                for part in parts[:-1]:
                    parent = parent[part]
                del parent[parts[-1]]
                if path != "signature":
                    altered["signature"] = receipt.signature(altered, key)
                self.assertFalse(self.check(altered, key=key)["complete"])

    def test_public_redirect_alone_and_failed_checks_are_insufficient(self):
        for report in (b"302 /auth/login\n", b"PASS: pricing\n",
                       receipt.PUBLIC_REPORT.replace(b"PASS: checksums", b"FAIL: checksums")):
            self.assertIn("public_checks", self.check(fixture(), report)["missing_fields"])
        data = fixture()
        del data["authenticated"]
        result = self.check(data)
        self.assertTrue(result["public_checks_passed"])
        self.assertFalse(result["complete"])
        self.assertIn("authenticated.second_name_offer", result["missing_fields"])

    def test_invalid_types_and_provenance(self):
        for path, value in (("observed_at", "2026-02-30T00:00:00Z"), ("observed_at", ""),
                            ("schema_version", True), ("evidence_kind", "production-fixture"),
                            ("authenticated", []), ("authenticated.account_plan", "Pro"),
                            ("authenticated.second_name_offer", "true"),
                            ("authenticated.amount_minor", True), ("authenticated.amount_minor", 0),
                            ("authenticated.currency", "usd"),
                            ("authenticated.provenance", {}),
                            ("authenticated.merchant.confirmed", False),
                            ("authenticated.merchant.display_name", " "),
                            ("authenticated.merchant.provenance.source", "public_302")):
            with self.subTest(path=path, value=value):
                data = fixture()
                parent = data
                parts = path.split(".")
                for part in parts[:-1]:
                    parent = parent[part]
                parent[parts[-1]] = value
                data["signature"] = receipt.signature(data, receipt.FIXTURE_KEY)
                # It must fail for a reason beyond merely being synthetic.
                self.assertTrue(set(self.check(data)["missing_fields"]) - {"real_operator_observation"})

    def test_cli_template_and_redacted_errors(self):
        with tempfile.TemporaryDirectory() as work:
            root = Path(work)
            data, report, key = (root / name for name in ("observation.json", "public.txt", "key"))
            data.write_text(json.dumps(fixture()))
            report.write_bytes(receipt.PUBLIC_REPORT)
            key.write_bytes(receipt.FIXTURE_KEY)
            command = [sys.executable, "-B", str(SCRIPT), "--observation", str(data),
                       "--public-report", str(report), "--operator-key", str(key),
                       "--expect-source-head", HEAD, "--expect-version", VERSION,
                       "--expect-client-sha256", DIGEST]
            def run(args=command):
                proc = subprocess.run(args, capture_output=True, text=True, timeout=10)
                self.assertEqual(proc.returncode, 1, proc.stderr)
                self.assertFalse(proc.stderr)
                result = json.loads(proc.stdout)
                self.assertFalse(result["complete"])
                return result, proc.stdout
            result, _ = run()
            self.assertEqual(result["evidence_kind"], receipt.SYNTHETIC)
            for payload in ('{"signature":"one","signature":"two"}', '[1]',
                            '{"cookie":"DO_NOT_ECHO","account_id":"DO_NOT_ECHO",'
                            '"credential":"DO_NOT_ECHO"}', '{"broken":'):
                data.write_text(payload)
                _, output = run()
                self.assertNotIn("DO_NOT_ECHO", output)
                self.assertNotIn("cookie", output)
                self.assertNotIn("account_id", output)
                self.assertNotIn("credential", output)
            data.write_text(Path(__file__).with_name("offer-receipt.template.json").read_text())
            result, _ = run()
            self.assertIn("authenticated.merchant.confirmed", result["missing_fields"])
            self.assertIn("operator_signature", result["missing_fields"])
            result, _ = run([sys.executable, "-B", str(SCRIPT)])
            self.assertIn("observed_at", result["missing_fields"])
            result, _ = run([*command, "--operator-key", str(root / "absent-key")])
            self.assertIn("operator_key_input", result["missing_fields"])

    def test_actual_public_stdout_contract_loopback_only(self):
        spec = importlib.util.spec_from_file_location("public_fixture", SCRIPT.with_name("test_verify_live_offer.py"))
        public = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(public)
        public.LiveOfferTests.setUpClass()
        server = public.LiveOfferTests.server
        server.case, server.requests = "passing", []
        connect = socket.create_connection
        def loopback(address, *args, **kwargs):
            self.assertEqual(address, ("127.0.0.1", server.server_port))
            return connect(address, *args, **kwargs)
        try:
            output = io.StringIO()
            with patch.object(socket, "create_connection", loopback), redirect_stdout(output):
                self.assertEqual(public.verify.main([server.base, "--expect-version", public.VERSION]), 0)
            self.assertEqual(output.getvalue().encode(), receipt.PUBLIC_REPORT)
            self.assertFalse(any(path.startswith("/auth/") for _, _, path in server.requests))
        finally:
            public.LiveOfferTests.tearDownClass()

    def test_stdlib_only_and_no_network_imports(self):
        for path in (SCRIPT, Path(__file__)):
            for node in ast.walk(ast.parse(path.read_text())):
                names = ([alias.name for alias in node.names] if isinstance(node, ast.Import)
                         else [node.module] if isinstance(node, ast.ImportFrom) else [])
                for name in names:
                    self.assertIn(name.split(".")[0], sys.stdlib_module_names)
                    if path == SCRIPT:
                        self.assertNotIn(name.split(".")[0], ("socket", "urllib", "http"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
