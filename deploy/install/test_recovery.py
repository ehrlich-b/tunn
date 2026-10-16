"""Functional recovery fixtures: disposable roots, fake executors, no listeners."""

from contextlib import closing
import json
import os
from pathlib import Path
import random
import shutil
import sqlite3
import ssl
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import artifacts
import selfhost


class Interrupted(BaseException):
    """Simulate process death, bypassing ordinary exception rollback."""


class ArtifactTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="install fixture ")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.installation = artifacts.Installation(self.root / "installation with spaces", create=True)
        self.first = self.fixture_binary("v1")
        self.second = self.fixture_binary("v2")

    def fixture_binary(self, version, valid=True):
        path = self.root / f"candidate {version}"
        text = artifacts.HELP_MARKER.decode() if valid else "another executable"
        path.write_text(f"#!/bin/sh\n# {version}\nprintf '%s\\n' '{text}'\n")
        path.chmod(0o755)
        return path

    def install(self, binary, checkpoint=lambda _: None):
        with self.installation.locked():
            return self.installation.install(binary, artifacts.digest(binary), checkpoint)

    def test_double_install_and_paths_with_spaces(self):
        expected = self.install(self.first)
        timestamp = self.installation.binary.stat().st_mtime_ns
        self.assertEqual(expected, self.install(self.first))
        self.assertEqual(timestamp, self.installation.binary.stat().st_mtime_ns)
        self.assertEqual(self.installation.binary.read_bytes(), self.first.read_bytes())
        self.assertEqual(self.installation.marker.stat().st_mode & 0o777, 0o600)

    def test_interrupted_upgrade_reconciles_all_publication_boundaries(self):
        original = self.install(self.first)
        for boundary in ("journal", "selection", "state"):
            with self.subTest(boundary=boundary):
                def interrupt(phase):
                    if phase == boundary:
                        raise Interrupted()

                with self.assertRaises(Interrupted):
                    self.install(self.second, interrupt)
                with self.assertRaisesRegex(ValueError, "interrupted"):
                    self.installation.inspect()
                with self.installation.locked():
                    self.assertEqual(original, self.installation.reconcile())
                    self.assertEqual(original, self.installation.reconcile())
                self.assertEqual(self.first.read_bytes(), self.installation.binary.read_bytes())

    def test_bad_replacement_and_checksum_keep_prior_selection(self):
        original = self.install(self.first)
        invalid = self.fixture_binary("wrong tool", valid=False)
        with self.assertRaisesRegex(ValueError, "not a runnable tunn"):
            self.install(invalid)
        with self.installation.locked():
            with self.assertRaisesRegex(ValueError, "checksum mismatch"):
                self.installation.install(self.second, "0" * 64)
        self.assertEqual(original, self.installation.inspect())
        self.assertEqual(self.first.read_bytes(), self.installation.binary.read_bytes())

    def test_missing_or_wrong_help_banner_keeps_prior_selection(self):
        original = self.install(self.first)
        binary = os.environ.get("TUNN_TEST_BINARY")
        self.assertIsNotNone(binary, "fixture gate must stage an offline build in TUNN_TEST_BINARY")
        result = subprocess.run([binary, "--help"], capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0)
        help_text = (result.stdout + result.stderr).decode()
        self.assertIn("Start\n  tunn login", help_text)
        for name, text in (
            ("missing", ""),
            ("stale", "tunn - expose localhost to the internet"),
            ("wrong heading", help_text.replace("Start\n", "Stop\n", 1)),
            ("wrong command", help_text.replace("tunn login", "other login", 1)),
        ):
            with self.subTest(banner=name):
                candidate = self.fixture_binary(name)
                candidate.write_text(f"#!/bin/sh\ncat <<'TUNN_HELP'\n{text}\nTUNN_HELP\n")
                with self.assertRaisesRegex(ValueError, "not a runnable tunn"):
                    self.install(candidate)
                self.assertEqual(original, self.installation.inspect())
                self.assertEqual(self.first.read_bytes(), self.installation.binary.read_bytes())

    def test_replacement_os_error_automatically_restores_prior_selection(self):
        original = self.install(self.first)
        select = self.installation.select

        def fail(checksum):
            if checksum == artifacts.digest(self.second):
                raise PermissionError("fixture running Windows executable is locked")
            return select(checksum)

        with patch.object(self.installation, "select", side_effect=fail):
            with self.assertRaises(PermissionError):
                self.install(self.second)
        self.assertEqual(original, self.installation.inspect())
        self.assertEqual(self.first.read_bytes(), self.installation.binary.read_bytes())

    def test_upgrade_rollback_repeated_removal_retains_profile_and_credentials(self):
        profile = self.installation.root / "host.yaml"
        credential = self.installation.root / "token"
        profile.write_text("version: 1\nmachine: preserved-host\n")
        credential.write_text("existing-user-owned-credential")
        credential.chmod(0o600)
        original = self.install(self.first)
        self.install(self.second)
        with self.installation.locked():
            result = self.installation.rollback()
            self.assertEqual(original["current"], result["current"])
            self.assertEqual(self.first.read_bytes(), self.installation.binary.read_bytes())
            self.installation.remove()
            self.installation.remove()
            self.assertFalse(self.installation.binary.exists())
            self.installation.rollback()  # Removal is reversible while retained artifacts remain.
        self.assertEqual(profile.read_text(), "version: 1\nmachine: preserved-host\n")
        self.assertEqual(credential.read_text(), "existing-user-owned-credential")
        self.assertEqual(credential.stat().st_mode & 0o777, 0o600)

    def test_schema_tamper_and_unmarked_roots_are_rejected(self):
        self.install(self.first)
        data = artifacts.read_json(self.installation.marker)
        data["version"] = 2
        artifacts.write_json(self.installation.marker, data)
        with self.assertRaisesRegex(ValueError, "schema"):
            self.installation.inspect()
        foreign = self.root / "user owned directory"
        foreign.mkdir()
        (foreign / "profile").write_text("never overwrite")
        with self.assertRaisesRegex(ValueError, "nonempty"):
            artifacts.Installation(foreign, create=True)
        self.assertEqual((foreign / "profile").read_text(), "never overwrite")

    def test_selected_and_retained_artifact_tamper_fail_closed(self):
        self.install(self.first)
        self.install(self.second)
        release = self.installation.release(artifacts.digest(self.first))
        release.chmod(0o755)
        release.write_text("changed")
        before = self.installation.binary.read_bytes()
        with self.installation.locked():
            with self.assertRaisesRegex(ValueError, "checksum"):
                self.installation.rollback()
        self.assertEqual(before, self.installation.binary.read_bytes())
        self.installation.binary.write_text("untracked")
        with self.assertRaisesRegex(ValueError, "differs"):
            self.installation.inspect()

    def test_real_binary_install_and_host_cli_diagnostics(self):
        binary_path = os.environ.get("TUNN_TEST_BINARY")
        self.assertIsNotNone(binary_path, "fixture gate must stage an offline build in TUNN_TEST_BINARY")
        binary = Path(binary_path)
        self.install(binary)
        credential = self.root / "publisher token"
        credential.write_text("fixture-self-hosted-credential")
        credential.chmod(0o600)
        profile = self.root / "host with spaces.yaml"
        profile.write_text(f'version: 1\nmachine: stable-fixture\ntoken_file: {json.dumps(str(credential))}\n'
                           'tunnels:\n  - name: fixture-http\n    kind: http\n    target: "8080"\n    allow: [fixture@example.test]\n')
        profile.chmod(0o600)
        command = [str(self.installation.binary), "service"]
        checked = subprocess.run([*command, "check", "--config", str(profile)], capture_output=True, timeout=10)
        self.assertEqual(checked.returncode, 0, checked.stderr.decode())
        self.assertIn(b"stable-fixture", checked.stdout)
        self.assertNotIn(credential.read_bytes(), checked.stdout + checked.stderr)
        for platform in ("darwin", "linux", "windows"):
            result = subprocess.run([*command, "install", "--dry-run", "--os", platform, "--config", str(profile)],
                                    capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr.decode())
            self.assertIn(str(profile).encode(), result.stdout)
            self.assertNotIn(b"fixture-self-hosted-credential", result.stdout + result.stderr)
        profile.write_text(profile.read_text().replace("version: 1", "version: 99"))
        result = subprocess.run([*command, "check", "--config", str(profile)], capture_output=True, timeout=10)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b"version must be 1", result.stderr)
        self.assertNotIn(credential.read_bytes(), result.stdout + result.stderr)

    def test_seeded_artifact_transitions_preserve_identity_and_selection(self):
        rng = random.Random(20261010)
        binaries = [self.first, self.second, self.fixture_binary("v3")]
        digests = {artifacts.digest(binary): binary for binary in binaries}
        profile = self.installation.root / "host.yaml"
        profile.write_text("version: 1\nmachine: stable-edge-fixture\n")
        credential = self.installation.root / "token"
        credential.write_text("fixture-owner-identity")
        credential.chmod(0o600)
        model = {"version": 1, "current": None, "previous": None}
        for step in range(100):
            action = rng.choice(("install", "rollback", "remove", "reconcile"))
            with self.subTest(seed=20261010, step=step, action=action):
                with self.installation.locked():
                    if action == "install":
                        binary = rng.choice(binaries)
                        checksum = artifacts.digest(binary)
                        result = self.installation.install(binary, checksum)
                        if model["current"] != checksum:
                            model = {"version": 1, "current": checksum, "previous": model["current"]}
                    elif action == "rollback" and model["previous"] is None:
                        with self.assertRaisesRegex(ValueError, "no previous"):
                            self.installation.rollback()
                        result = self.installation.inspect()
                    else:
                        result = getattr(self.installation, action)()
                        if action == "rollback":
                            model = {"version": 1, "current": model["previous"], "previous": model["current"]}
                        elif action == "remove" and model["current"] is not None:
                            model = {"version": 1, "current": None, "previous": model["current"]}
                self.assertEqual(result, model)
                self.assertEqual(self.installation.inspect(), model)
                self.assertFalse(self.installation.pending.exists())
                if model["current"] is None:
                    self.assertFalse(self.installation.binary.exists())
                else:
                    self.assertEqual(self.installation.binary.read_bytes(), digests[model["current"]].read_bytes())
                self.assertEqual(profile.read_text(), "version: 1\nmachine: stable-edge-fixture\n")
                self.assertEqual(credential.read_text(), "fixture-owner-identity")
                self.assertEqual(credential.stat().st_mode & 0o777, 0o600)

    def test_interrupted_first_install_rollback_and_remove_reconcile(self):
        for action in ("first install", "rollback", "remove"):
            for boundary in ("journal", "selection", "state"):
                with self.subTest(action=action, boundary=boundary):
                    installation = artifacts.Installation(self.root / f"{action}-{boundary}", create=True)
                    with installation.locked():
                        if action != "first install":
                            installation.install(self.first, artifacts.digest(self.first))
                        if action == "rollback":
                            installation.install(self.second, artifacts.digest(self.second))
                        original = installation.inspect()
                        if action == "first install":
                            selected = artifacts.digest(self.first)
                            new = {"version": 1, "current": selected, "previous": None}
                            # Stage through the actual installer, including candidate checks.
                            change = lambda checkpoint: installation.install(self.first, selected, checkpoint)
                        else:
                            selected = original["previous"] if action == "rollback" else None
                            new = {"version": 1, "current": selected, "previous": original["current"]}
                            change = lambda checkpoint: installation.transition(original, new, checkpoint)

                        def interrupt(phase):
                            if phase == boundary:
                                raise Interrupted()

                        with self.assertRaises(Interrupted):
                            change(interrupt)
                        with self.assertRaisesRegex(ValueError, "interrupted"):
                            installation.inspect()
                        self.assertEqual(installation.reconcile(), original)
                        self.assertEqual(installation.reconcile(), original)
                        self.assertFalse(installation.pending.exists())
                        if original["current"] is None:
                            self.assertFalse(installation.binary.exists())
                        else:
                            self.assertEqual(artifacts.digest(installation.binary), original["current"])

    def test_competing_install_lock_retains_selection(self):
        original = self.install(self.first)
        contender = artifacts.Installation(self.installation.root)
        with self.installation.locked():
            with self.assertRaises(OSError):
                with contender.locked():
                    self.fail("competing installation acquired an owned lock")
        self.assertEqual(self.installation.inspect(), original)
        with contender.locked():
            self.assertEqual(contender.inspect(), original)

    def test_symlink_candidate_and_selected_binary_are_refused(self):
        candidate = self.root / "candidate alias"
        candidate.symlink_to(self.first)
        with self.installation.locked():
            with self.assertRaisesRegex(ValueError, "non-symlink"):
                self.installation.install(candidate, artifacts.digest(self.first))
        self.assertIsNone(self.installation.inspect()["current"])
        original = self.install(self.first)
        selected = self.installation.binary
        selected.unlink()
        selected.symlink_to(self.first)
        with self.assertRaisesRegex(ValueError, "non-symlink"):
            self.installation.inspect()
        self.assertTrue(selected.is_symlink())
        self.assertEqual(artifacts.read_json(self.installation.marker), original)
        self.assertEqual(self.first.read_text().splitlines()[1], "# v1")


class SelfhostTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not shutil.which("openssl"):
            raise RuntimeError("REQUIRED/UNRUN: operator must stage openssl for fixture TLS generation")
        cls.temporary = tempfile.TemporaryDirectory(prefix="selfhost TLS fixture ")
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.tls = Path(cls.temporary.name)
        with tempfile.TemporaryFile(dir=cls.tls) as output:
            subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                            "-subj", "/CN=relay.example.test", "-keyout", str(cls.tls / "key.pem"),
                            "-out", str(cls.tls / "cert.pem")], check=True, stdout=output, stderr=output, timeout=20)
        (cls.tls / "key.pem").chmod(0o600)

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="selfhost fixture ")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.path = self.root / "relay.json"
        self.db = self.root / "relay database.sqlite"
        self.connection = sqlite3.connect(self.db)
        self.addCleanup(self.connection.close)
        self.connection.execute("PRAGMA journal_mode=WAL")
        self.connection.execute("CREATE TABLE owned_names(host_id TEXT, name TEXT, owner TEXT)")
        self.connection.execute("INSERT INTO owned_names VALUES ('stable-host', 'stable-name', 'same-owner')")
        self.connection.commit()
        self.db.chmod(0o600)
        self.data = {"version": 1, "domain": "relay.example.test", "http2_addr": "127.0.0.1:18443",
                     "http3_addr": "127.0.0.1:18443", "internal_grpc_addr": "127.0.0.1:15051",
                     "cert_file": str(self.tls / "cert.pem"), "key_file": str(self.tls / "key.pem"),
                     "db_path": str(self.db), "client_secret": "fixture-client-" + "a" * 32,
                     "jwt_secret": "fixture-jwt-" + "b" * 32, "host_mode": True}
        artifacts.write_json(self.path, self.data)

    def test_export_import_preserves_config_tls_and_committed_wal_identity(self):
        bundle = self.root / "private export"
        imported = self.root / "import with spaces"
        selfhost.export_config(self.path, bundle)
        selfhost.import_config(bundle, imported)
        new = selfhost.load(imported / "relay.json", require_database=True)
        for key in self.data.keys() - selfhost.ASSETS.keys():
            self.assertEqual(new[key], self.data[key])
        with closing(selfhost.database(new["db_path"])) as database:
            self.assertEqual(database.execute("SELECT * FROM owned_names").fetchall(),
                             [("stable-host", "stable-name", "same-owner")])
        for name in (*selfhost.ASSETS.values(), "relay.json"):
            self.assertEqual((imported / name).stat().st_mode & 0o777, 0o600)
        self.assertEqual(imported.stat().st_mode & 0o777, 0o700)
        self.assertEqual(self.path.read_text(), (json.dumps(self.data, sort_keys=True, indent=2) + "\n"))

    def test_import_never_overwrites_existing_profile(self):
        bundle = self.root / "export"
        selfhost.export_config(self.path, bundle)
        with self.assertRaisesRegex(ValueError, "never overwritten"):
            selfhost.import_config(bundle, self.root)
        with self.assertRaisesRegex(ValueError, "never overwritten"):
            selfhost.export_config(self.path, bundle)
        self.assertEqual(selfhost.load(self.path), self.data)

    def test_corrupt_snapshot_leaves_no_partial_destination(self):
        bundle = self.root / "export"
        imported = self.root / "import"
        selfhost.export_config(self.path, bundle)
        (bundle / "database.sqlite").write_bytes(b"fixture corrupt database")
        with self.assertRaisesRegex(ValueError, "checksum"):
            selfhost.import_config(bundle, imported)
        self.assertFalse(imported.exists())

    def test_bad_tls_and_version_rejected_without_config_repair(self):
        with patch.dict(os.environ, {"TUNN_DB_PATH": "/should-never-be-used", "FLY_APP_NAME": "unwanted"}):
            env = selfhost.environment(selfhost.load(self.path))
        self.assertEqual(env["TUNN_DB_PATH"], str(self.db))
        self.assertEqual(env["TUNN_PUBLIC_MODE"], "false")
        self.assertNotIn("FLY_APP_NAME", env)
        self.data["version"] = 2
        artifacts.write_json(self.path, self.data)
        with self.assertRaisesRegex(ValueError, "schema"):
            selfhost.load(self.path)
        self.data["version"] = 1
        bad_key = self.root / "invalid key.pem"
        bad_key.write_text("fixture-invalid-key")
        bad_key.chmod(0o600)
        self.data["key_file"] = str(bad_key)
        artifacts.write_json(self.path, self.data)
        with self.assertRaises(ssl.SSLError):
            selfhost.load(self.path)
        self.assertEqual(bad_key.read_text(), "fixture-invalid-key")

    def test_unknown_fields_and_public_internal_listener_are_rejected(self):
        for change in ({"unexpected": True}, {"version": True}, {"internal_grpc_addr": "0.0.0.0:15051"}):
            with self.subTest(change=change):
                data = dict(self.data, **change)
                artifacts.write_json(self.path, data)
                with self.assertRaises(ValueError):
                    selfhost.load(self.path)
                self.assertEqual(artifacts.read_json(self.path), data)

    def test_invalid_listeners_and_colliding_tcp_ports_are_rejected(self):
        for value in ("localhost:8443", "127.0.0.1]:8443", "::1:8443", "[[::1]]:8443", "127.0.0.1:0", "127.0.0.1:65536", "0.0.0.0:15051"):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    selfhost.schema(dict(self.data, http2_addr=value))
        selfhost.schema(dict(self.data, http2_addr="[::1]:18443"))

    def test_import_copy_failure_does_not_publish_partial_configuration(self):
        bundle, imported = self.root / "export", self.root / "import"
        selfhost.export_config(self.path, bundle)
        copy = shutil.copyfile
        count = 0

        def fail(source, target):
            nonlocal count
            count += 1
            if count == 2:
                raise PermissionError("fixture cannot stage replacement key")
            return copy(source, target)

        with patch.object(selfhost.shutil, "copyfile", side_effect=fail):
            with self.assertRaises(PermissionError):
                selfhost.import_config(bundle, imported)
        self.assertFalse(imported.exists())
        self.assertEqual(list(self.root.glob(".tunn-import-*")), [])
        self.assertEqual(selfhost.load(self.path), self.data)

    def test_selfhost_distribution_upgrade_and_rollback_with_fake_manager(self):
        installation = artifacts.Installation(self.root / "relay installation", create=True)
        calls = []

        def fake_manager(action):
            self.assertIn(action, ("start", "stop", "restart"))
            calls.append(action)
            if action != "stop":
                selfhost.load(self.path, require_database=True)
                installation.inspect()

        candidates = []
        for version in (1, 2):
            binary = self.root / f"relay candidate {version}"
            binary.write_text(f"#!/bin/sh\n# version {version}\nprintf '%s\\n' '{artifacts.HELP_MARKER.decode()}'\n")
            binary.chmod(0o755)
            candidates.append(binary)
        with installation.locked():
            installation.install(candidates[0], artifacts.digest(candidates[0]))
            fake_manager("start")
            fake_manager("stop")
            bundle = self.root / "before upgrade"
            selfhost.export_config(self.path, bundle)
            installation.install(candidates[1], artifacts.digest(candidates[1]))
            fake_manager("restart")
            fake_manager("stop")
            installation.rollback()
            fake_manager("start")
        self.assertEqual(installation.binary.read_bytes(), candidates[0].read_bytes())
        self.assertEqual(calls, ["start", "stop", "restart", "stop", "start"])
        self.assertEqual(selfhost.load(self.path), self.data)
        self.assertEqual(self.connection.execute("SELECT * FROM owned_names").fetchall(),
                         [("stable-host", "stable-name", "same-owner")])


if __name__ == "__main__":
    unittest.main()
