"""Offline regressions: synthetic credentials, fake transports, no socket binds."""

import base64
import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import unittest
from unittest.mock import MagicMock, patch

import canary
from kit import Config, SERVICES, private_file
import runner


class KitTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.path = self.root / "host.json"
        self.data = {"host": "forge", "tunn_binary": "/opt/test/tunn", "wt_binary": "/opt/test/wt",
                     "work_dir": str(self.root), "dashboard_port": 3000, "dashboard_path": "/health",
                     "allow_emails": ["owner@example.test"], "mcp_tools": ["list_sessions", "get_status"]}
        self.save_config()

    def save_config(self):
        self.path.write_text(json.dumps(self.data))
        self.path.chmod(0o600)

    def credentials(self, expiration=None):
        directory = self.root / "credentials"
        directory.mkdir(exist_ok=True, mode=0o700)
        claims = {"exp": expiration if expiration is not None else time.time() + 3600}
        payload = base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip("=")
        (directory / "token").write_text(f"synthetic.{payload}.synthetic")
        (directory / "token").chmod(0o600)
        return directory

    def test_commands_and_environment_keep_services_private(self):
        config = Config(self.path)
        commands = {service: config.command(service) for service in SERVICES}
        self.assertEqual(commands["ssh"][-1], "127.0.0.1:22")
        self.assertEqual(commands["wt"][-3:], ["/opt/test/wt", "mcp", "stdio"])
        self.assertIn("list_sessions,get_status", commands["wt"])
        self.assertIn("--allow=owner@example.test", commands["dashboard"])
        self.assertIn("--id=forge-dashboard", commands["dashboard"])
        self.assertEqual(commands["dashboard"][-1], "http://127.0.0.1:3000")
        self.assertFalse(any("--public" in command or "--insecure" in command for command in commands.values()))
        with patch.dict(os.environ, {"TUNN_ENV": "dev", "TUNN_SECRET": "synthetic-unwanted-secret",
                                    "TUNN_PUBLIC_MODE": "true", "TUNN_CLIENT_SECRET": "unwanted"}):
            env = config.environment(self.root / "credentials")
        self.assertEqual(env["TUNN_ENV"], "prod")
        self.assertEqual(env["TUNN_SECRET"], "")
        self.assertEqual(env["TUNN_PUBLIC_MODE"], "false")
        self.assertNotIn("TUNN_CLIENT_SECRET", env)
        self.assertEqual(env["TUNN_CONFIG_DIR"], str(self.root / "credentials"))

    def test_forge_and_rig_have_separate_credentials(self):
        forge = Config(self.path).paths(self.root)[1]
        self.data["host"] = "rig"
        self.save_config()
        config = Config(self.path)
        rig = config.paths(self.root)[1]
        self.assertNotEqual(forge, rig)
        self.assertIn("rig-wt", config.command("wt"))

    def test_rejects_unsafe_or_unreviewed_configs(self):
        changes = [("host", "other"), ("tunn_binary", "./tunn"), ("wt_binary", "/home/CHANGE_ME/wt"),
                   ("work_dir", "/does-not-exist"), ("dashboard_port", True), ("dashboard_port", 65536),
                   ("dashboard_path", "//external.test"), ("dashboard_path", "/\r\n"),
                   ("allow_emails", []), ("allow_emails", ["@example.test"]),
                   ("allow_emails", ["owner@example.invalid"]), ("mcp_tools", []),
                   ("mcp_tools", ["REPLACE_TOOL"]), ("mcp_tools", ["bad,name"])]
        original = dict(self.data)
        for key, value in changes:
            with self.subTest(key=key, value=value):
                self.data = dict(original, **{key: value})
                self.save_config()
                with self.assertRaises(ValueError):
                    Config(self.path)

    def test_rejects_readable_or_symlinked_config(self):
        self.path.chmod(0o644)
        with self.assertRaises(ValueError):
            Config(self.path)
        self.path.chmod(0o600)
        link = self.root / "link.json"
        link.symlink_to(self.path)
        with self.assertRaises(ValueError):
            Config(link)

    def test_login_expiry_and_private_token_permissions(self):
        credentials = self.credentials()
        runner.validate_credentials(credentials)
        (credentials / "token").chmod(0o644)
        with self.assertRaises(ValueError):
            runner.validate_credentials(credentials)
        self.credentials(expiration=time.time() - 1)
        with self.assertRaisesRegex(ValueError, "expired"):
            runner.validate_credentials(credentials)

    def test_health_does_not_create_or_repair_private_directories(self):
        config = Config(self.path)
        with self.assertRaises(FileNotFoundError):
            runner.health(config, self.root / "missing", self.root / "missing-credentials")
        self.assertFalse((self.root / "missing").exists())
        credentials = self.credentials()
        credentials.chmod(0o755)
        with self.assertRaises(ValueError):
            runner.validate_credentials(credentials)
        self.assertEqual(credentials.stat().st_mode & 0o777, 0o755)

    def test_logging_bounds_lines_and_redacts_split_credentials(self):
        logger = MagicMock()
        stream = MagicMock()
        chunks = [b"hello tunn_ep_synth", b"eticcredential\nAuthorization: Bearer secret\n",
                  b"x" * 4096, b"x" * 4096, b"trailing-secret\nnormal\n", b""]
        with patch.object(runner.os, "read", side_effect=chunks):
            runner.capture_output(stream, logger)
        messages = "\n".join(str(call.args) for call in logger.info.call_args_list)
        self.assertNotIn("syntheticcredential", messages)
        self.assertNotIn("Bearer secret", messages)
        self.assertNotIn("trailing-secret", messages)
        self.assertIn("overlong child output omitted", messages)
        self.assertIn("normal", messages)

    def test_log_rotation_is_bounded_and_private(self):
        logger = runner.log_for(self.root, "test-rotation")
        handler = logger.handlers[0]
        self.addCleanup(handler.close)
        self.addCleanup(logger.removeHandler, handler)
        handler.maxBytes = 256
        for _ in range(100):
            logger.info("%s", "bounded" * 20)
        files = list((self.root / "logs").iterdir())
        self.assertLessEqual(len(files), 4)
        self.assertTrue(all(path.stat().st_size < 512 for path in files))
        self.assertTrue(all(path.stat().st_mode & 0o777 == 0o600 for path in files))
        self.assertEqual((self.root / "logs").stat().st_mode & 0o777, 0o700)
        private_file(self.root / "logs/test-rotation.log")

    def test_supervisor_retries_and_cleans_status(self):
        credentials = self.credentials()
        config = Config(self.path)
        stopping = MagicMock()
        stopping.is_set.side_effect = [False, False, False, False, True]
        process = MagicMock(pid=12345, returncode=1)
        process.poll.return_value = 1
        logger = MagicMock()
        with patch.object(runner, "log_for", return_value=logger), \
             patch.object(runner.os, "access", return_value=True), \
             patch.object(runner, "capture_output"), \
             patch.object(runner, "stop_process") as stop, \
             patch.object(runner.subprocess, "Popen", return_value=process) as popen:
            runner.supervise(config, "ssh", self.root, credentials, stopping)
        self.assertEqual(popen.call_count, 2)
        self.assertEqual(stop.call_count, 2)
        self.assertEqual([c.args[0] for c in stopping.wait.call_args_list], [5, 10])
        self.assertEqual(popen.call_args.kwargs["env"]["TUNN_ENV"], "prod")
        self.assertTrue(popen.call_args.kwargs["start_new_session"])
        self.assertTrue(all(call.args[0] == config.command("ssh") for call in popen.call_args_list))
        self.assertEqual(config.command("ssh")[-3:], ["--name", "forge-ssh", "127.0.0.1:22"])
        self.assertFalse((self.root / "ssh.json").exists())

    def test_versioned_config_rejects_unknown_schemas_without_rewriting_legacy(self):
        original = self.path.read_bytes()
        Config(self.path)  # Existing unversioned profiles remain readable.
        self.assertEqual(self.path.read_bytes(), original)
        self.data["version"] = 1
        self.save_config()
        self.assertEqual(Config(self.path).host, "forge")
        for version in (2, True, "1"):
            self.data["version"] = version
            self.save_config()
            with self.assertRaisesRegex(ValueError, "version"):
                Config(self.path)

    def test_expired_login_prevents_supervisor_from_starting_a_new_identity(self):
        credentials = self.credentials(expiration=time.time() - 1)
        config = Config(self.path)
        original = (credentials / "token").read_bytes()
        stopping = MagicMock()
        stopping.is_set.return_value = False
        with patch.object(runner, "log_for", return_value=MagicMock()), \
             patch.object(runner.subprocess, "Popen") as popen:
            with self.assertRaisesRegex(ValueError, "expired"):
                runner.supervise(config, "ssh", self.root, credentials, stopping)
        popen.assert_not_called()
        self.assertEqual((credentials / "token").read_bytes(), original)
        self.assertEqual(config.command("ssh")[-3:], ["--name", "forge-ssh", "127.0.0.1:22"])

    def test_shutdown_terminates_then_kills_a_stuck_child(self):
        process = MagicMock(pid=98765)
        process.poll.return_value = None
        process.wait.side_effect = [subprocess.TimeoutExpired("synthetic", 8), 0]
        with patch.object(runner.os, "killpg") as killpg:
            runner.stop_process(process)
        self.assertEqual([c.args[1] for c in killpg.call_args_list], [runner.signal.SIGTERM, runner.signal.SIGKILL])

    def test_shutdown_kills_descendants_of_an_exited_leader(self):
        process = MagicMock(pid=98765)
        process.poll.return_value = 0
        with patch.object(runner.os, "killpg") as killpg:
            runner.stop_process(process)
        self.assertEqual([c.args[1] for c in killpg.call_args_list], [runner.signal.SIGTERM, runner.signal.SIGKILL])

    def canary_args(self, phase="before"):
        return canary.parse_args([
            "--phase", phase, "--host", "forge", "--tunn-binary", "/opt/test/tunn",
            "--token-dir", str(self.root), "--dashboard-token-file", str(self.root / "dashboard.token"),
            "--ssh-user", "testuser", "--identity-file", str(self.root / "id_ed25519"),
            "--known-hosts", str(self.root / "known_hosts"), "--expected-hostname", "forge",
            "--expected-tools", "get_status,list_sessions", "--dashboard-marker", "AI dashboard",
            "--receipt", str(self.root / "receipt.json"),
        ])

    def canary_tokens(self, letter="a"):
        for suffix in ("ssh", "wt"):
            path = self.root / f"forge-{suffix}.token"
            path.write_text("tunn_ep_" + letter * 43 + "\n")
            path.chmod(0o600)
        path = self.root / "dashboard.token"
        path.write_text("synthetic-account-token")
        path.chmod(0o600)

    @staticmethod
    def fake_http():
        http = MagicMock()
        http.request.side_effect = [
            (401, {}, b""), (401, {}, b""), (401, {}, b""), (401, {}, b""),
            (200, {}, json.dumps({"id": 1, "result": {"supportedVersions": ["2026-07-28"]}}).encode()),
            (200, {}, json.dumps({"id": 2, "result": {"tools": [{"name": "list_sessions"}, {"name": "get_status"}]}}).encode()),
            (302, {}, b""), (200, {}, b"AI dashboard"),
        ]
        return http

    def test_canary_before_and_after_require_refreshed_tokens(self):
        self.canary_tokens()
        args = self.canary_args()
        output = io.StringIO()
        with patch.object(canary, "ssh_probe") as ssh, contextlib.redirect_stdout(output):
            canary.run(args, self.fake_http())
            ssh.assert_called_once()
        receipt = private_file(args.receipt).read_text()
        self.assertNotIn("tunn_ep_", receipt)
        self.assertNotIn("synthetic-account-token", receipt)
        args.phase = "after"
        with self.assertRaisesRegex(ValueError, "newly copied"):
            canary.run(args, self.fake_http())
        self.canary_tokens("b")
        with patch.object(canary, "ssh_probe"), contextlib.redirect_stdout(output):
            canary.run(args, self.fake_http())
        self.assertIn("after publisher restart", output.getvalue())
        self.assertNotIn("tunn_ep_", output.getvalue())

    def test_canary_fails_if_endpoint_is_public_or_tools_differ(self):
        self.canary_tokens()
        args = self.canary_args()
        public = MagicMock()
        public.request.return_value = (200, {}, b"unexpected")
        with self.assertRaisesRegex(ValueError, "missing/wrong"):
            canary.run(args, public)
        args.expected_tools = "dangerous_tool"
        with patch.object(canary, "ssh_probe"), contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaisesRegex(ValueError, "reviewed exact tool list"):
                canary.run(args, self.fake_http())
        self.assertFalse(args.receipt.exists())

    def test_hostmode_canary_requires_preserved_capabilities_and_same_policy(self):
        self.canary_tokens()
        args = self.canary_args()
        args.token_lifecycle = "preserve"
        with patch.object(canary, "ssh_probe"), contextlib.redirect_stdout(io.StringIO()):
            canary.run(args, self.fake_http())
            args.phase = "after"
            canary.run(args, self.fake_http())
        self.canary_tokens("b")
        with self.assertRaisesRegex(ValueError, "must preserve"):
            canary.run(args, self.fake_http())
        args.token_lifecycle = "rotate"
        with self.assertRaisesRegex(ValueError, "different token lifecycle"):
            canary.run(args, self.fake_http())

    def test_unavailable_relay_does_not_create_a_success_receipt(self):
        self.canary_tokens()
        args = self.canary_args()
        http = MagicMock()
        http.request.return_value = (503, {}, b"fixture relay unavailable")
        with patch.object(canary, "ssh_probe") as ssh:
            with self.assertRaises(ValueError):
                canary.run(args, http)
        ssh.assert_not_called()
        self.assertFalse(args.receipt.exists())

    def test_ssh_command_pins_host_identity_and_runs_only_fixed_command(self):
        command = canary.ssh_command(self.canary_args())
        self.assertIn("StrictHostKeyChecking=yes", command)
        self.assertIn("HostKeyAlias=forge-tunn", command)
        self.assertIn("BatchMode=yes", command)
        self.assertIn("IdentitiesOnly=yes", command)
        self.assertEqual(command[-1], "printf 'tunn-ai-hosts-ok\\n'; hostname")

    def test_ssh_probe_requires_its_own_listener_and_cleans_connector(self):
        args = self.canary_args()
        process = MagicMock()
        process.poll.return_value = None
        expected = b"tcp://127.0.0.1:2222 -> https://forge-ssh.tunn.to/_tunn/connect\n"
        selector = MagicMock()
        selector.__enter__.return_value = selector
        selector.select.return_value = [(MagicMock(), 1)]
        result = MagicMock(returncode=0, stdout=b"tunn-ai-hosts-ok\nforge\n")
        with patch.object(canary.subprocess, "Popen", return_value=process) as popen, \
             patch.object(canary.subprocess, "run", return_value=result) as ssh, \
             patch.object(canary.selectors, "DefaultSelector", return_value=selector), \
             patch.object(canary.os, "read", side_effect=[expected[:12], expected[12:]]), \
             patch.object(canary, "stop_process") as stop:
            canary.ssh_probe(args, self.root / "forge-ssh.token")
        self.assertEqual(popen.call_args.kwargs["env"]["TUNN_ENV"], "prod")
        self.assertIn("--token-file", popen.call_args.args[0])
        self.assertNotIn("--token", popen.call_args.args[0])
        ssh.assert_called_once()
        stop.assert_called_once_with(process)
        process.stdout.close.assert_called_once()

    def test_ssh_probe_rejects_a_different_listener_before_ssh(self):
        args = self.canary_args()
        process = MagicMock()
        selector = MagicMock()
        selector.__enter__.return_value = selector
        selector.select.return_value = [(MagicMock(), 1)]
        with patch.object(canary.subprocess, "Popen", return_value=process), \
             patch.object(canary.subprocess, "run") as ssh, \
             patch.object(canary.selectors, "DefaultSelector", return_value=selector), \
             patch.object(canary.os, "read", return_value=b"tcp://0.0.0.0:2222 -> wrong-endpoint\n"), \
             patch.object(canary, "stop_process") as stop:
            with self.assertRaisesRegex(ValueError, "expected loopback listener"):
                canary.ssh_probe(args, self.root / "forge-ssh.token")
        ssh.assert_not_called()
        stop.assert_called_once_with(process)

    def test_http_refuses_redirects_and_bounds_body(self):
        self.assertIsNone(runner.NoRedirect().redirect_request(None, None, 302, "redirect", {}, "https://external.test"))
        http = canary.HTTP()
        response = MagicMock()
        response.__enter__.return_value = response
        response.read.return_value = b"x" * (canary.MAX_BODY + 1)
        http.opener = MagicMock()
        http.opener.open.return_value = response
        with self.assertRaisesRegex(ValueError, "exceeds"):
            http.request("https://forge-wt.tunn.to/mcp")


if __name__ == "__main__":
    unittest.main()
