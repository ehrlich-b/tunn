#!/usr/bin/env python3
"""Import a signed, redacted operator observation without making any requests."""

import argparse
from datetime import datetime
import hashlib
import hmac
import json
from pathlib import Path
import re
import subprocess
import sys


SYNTHETIC = "SYNTHETIC_FIXTURE_ONLY"
# Public verify-live-offer.py stdout is the contract; a pricing PASS only proves
# the signed-out login return path, never the authenticated offer or merchant.
PUBLIC_REPORT = "".join(f"PASS: {name}\n" for name in
                        ("version", "checksums", "pricing", "about", "mcp")).encode()
FIXTURE_KEY = b"SYNTHETIC_FIXTURE_ONLY-not-an-operator-key"
DOMAIN = b"tunn-offer-observation-v1\x00"


def signing_bytes(observation):
    """Canonical UTF-8 JSON, excluding only the top-level signature."""
    return DOMAIN + json.dumps(
        {k: v for k, v in observation.items() if k != "signature"},
        sort_keys=True, separators=(",", ":"), ensure_ascii=True,
        allow_nan=False).encode("ascii")


def signature(observation, key):
    return hmac.new(key, signing_bytes(observation), hashlib.sha256).hexdigest()


def hex_string(value, size):
    return isinstance(value, str) and re.fullmatch(f"[0-9a-f]{{{size}}}", value) is not None


def timestamp(value):
    if not isinstance(value, str) or not re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", value):
        return False
    try:
        datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
        return True
    except ValueError:
        return False


def check(observation, public_report, expected_head, expected_version, expected_digest, key=None):
    """Return names of missing/invalid proof; never echo untrusted input values."""
    missing = []

    def need(condition, field):
        if not condition:
            missing.append(field)

    def obj(value):
        return value if isinstance(value, dict) else {}

    def schema(value, fields):
        need(isinstance(value, dict) and not (set(value) - set(fields.split())), "schema")

    data = obj(observation)
    schema(observation, "schema_version evidence_kind observed_at source_head version client_sha256 public_report_sha256 authenticated signature")
    need(type(data.get("schema_version")) is int and data["schema_version"] == 1, "schema_version")
    kind = data.get("evidence_kind")
    synthetic = kind == SYNTHETIC or key == FIXTURE_KEY
    need(kind in ("OPERATOR_OBSERVATION", SYNTHETIC), "evidence_kind")
    need(timestamp(data.get("observed_at")), "observed_at")
    need(hex_string(expected_head, 40) and data.get("source_head") == expected_head, "source_head")
    need(isinstance(expected_version, str) and re.fullmatch(r"v\d+\.\d+\.\d+", expected_version)
         and data.get("version") == expected_version, "version")
    need(hex_string(expected_digest, 64) and data.get("client_sha256") == expected_digest, "client_sha256")
    need(public_report == PUBLIC_REPORT, "public_checks")
    need(data.get("public_report_sha256") == hashlib.sha256(public_report).hexdigest(),
         "public_report_sha256")
    auth = obj(data.get("authenticated"))
    schema(data.get("authenticated"), "account_plan second_name_offer period amount_minor currency provenance merchant")
    need(auth.get("account_plan") == "Free", "authenticated.account_plan")
    need(auth.get("second_name_offer") is True, "authenticated.second_name_offer")
    need(auth.get("period") == "monthly", "authenticated.period")
    need(type(auth.get("amount_minor")) is int and auth["amount_minor"] > 0,
         "authenticated.amount_minor")
    need(isinstance(auth.get("currency"), str)
         and re.fullmatch(r"[A-Z]{3}", auth["currency"]), "authenticated.currency")

    def provenance(value, prefix, allowed_sources):
        proof = obj(value)
        schema(value, "source redacted_evidence_sha256")
        need(proof.get("source") in allowed_sources, prefix + ".source")
        need(hex_string(proof.get("redacted_evidence_sha256"), 64),
             prefix + ".redacted_evidence_sha256")

    provenance(auth.get("provenance"), "authenticated.provenance", ("private_window_and_client",))
    merchant = obj(auth.get("merchant"))
    schema(auth.get("merchant"), "confirmed display_name provenance")
    need(merchant.get("confirmed") is True, "authenticated.merchant.confirmed")
    name = merchant.get("display_name")
    need(isinstance(name, str) and bool(name.strip()) and len(name) <= 200,
         "authenticated.merchant.display_name")
    provenance(merchant.get("provenance"), "authenticated.merchant.provenance",
               ("existing_merchant_dashboard", "existing_redacted_receipt"))
    supplied_signature = data.get("signature")
    signed = False
    if isinstance(key, bytes) and len(key) >= 32 and hex_string(supplied_signature, 64):
        try:
            signed = hmac.compare_digest(signature(data, key), supplied_signature)
        except (ValueError, TypeError):
            pass
    need(signed, "operator_signature")
    if synthetic:
        missing.append("real_operator_observation")
    return {"complete": not missing, "evidence_kind": SYNTHETIC if synthetic else "OPERATOR_OBSERVATION",
            "missing_fields": sorted(set(missing)), "operator_signature_valid": signed,
            "public_checks_passed": public_report == PUBLIC_REPORT,
            "scope": "offer_and_merchant_observation_only_not_payment_or_activation"}


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate field")
        result[key] = value
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true", help="run offline stdlib fixtures")
    parser.add_argument("--observation", type=Path)
    parser.add_argument("--public-report", type=Path, help="unaltered verify-live-offer.py stdout")
    parser.add_argument("--expect-source-head")
    parser.add_argument("--expect-version")
    parser.add_argument("--expect-client-sha256")
    parser.add_argument("--operator-key", type=Path, help="independently trusted local HMAC key; never in JSON")
    args = parser.parse_args(argv)
    if args.self_test:
        return subprocess.call([sys.executable, "-B", str(Path(__file__).with_name("test_check_offer_receipt.py"))])
    # Missing inputs are a normal incomplete receipt, not an invitation to log in.
    observation, public_report, key = {}, b"", None
    errors = []
    try:
        if args.observation:
            observation = json.loads(args.observation.read_text(), object_pairs_hook=unique_object)
    except (OSError, ValueError, RecursionError):
        errors.append("observation_input")
    try:
        if args.public_report:
            public_report = args.public_report.read_bytes()
    except OSError:
        errors.append("public_report_input")
    try:
        if args.operator_key:
            key = args.operator_key.read_bytes()
    except OSError:
        errors.append("operator_key_input")
    result = check(observation, public_report, args.expect_source_head,
                   args.expect_version, args.expect_client_sha256, key)
    if errors:
        result["complete"] = False
        result["missing_fields"] = sorted(set(result["missing_fields"] + errors))
    print(json.dumps(result, sort_keys=True))
    return int(not result["complete"])


if __name__ == "__main__":
    raise SystemExit(main())
