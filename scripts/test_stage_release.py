#!/usr/bin/env python3
"""Release preflight regressions; no builds or network required."""
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("stage_release", Path(__file__).with_name("stage-release.py"))
stage = importlib.util.module_from_spec(spec)
spec.loader.exec_module(stage)


class ReleasePreflight(unittest.TestCase):
    def test_nonstable_tags_never_create_a_feed(self):
        for tag in ("v1.2.3-preview.1", "v1.2.3-rc1", "draft", "../v1.2.3", "v1.2", "v1.2.3\n"):
            with self.subTest(tag=tag), tempfile.TemporaryDirectory() as temp:
                output = Path(temp) / "release"
                with self.assertRaises(ValueError), patch.object(stage, "run") as run:
                    stage.stage(tag, "a" * 40, output)
                run.assert_not_called()
                self.assertFalse(output.exists())

    def test_mismatched_tag_never_builds_or_writes(self):
        with tempfile.TemporaryDirectory() as temp, patch.object(stage, "run", return_value="b" * 40) as run:
            output = Path(temp) / "release"
            with self.assertRaises(ValueError):
                stage.stage("v1.2.3", "a" * 40, output)
            self.assertEqual(run.call_count, 1)
            self.assertFalse(output.exists())

    def test_immutable_destination_refuses_restage(self):
        with tempfile.TemporaryDirectory() as temp, patch.object(stage, "run", return_value="a" * 40) as run:
            output = Path(temp)
            (output / "sentinel").write_text("retained")
            with self.assertRaises(FileExistsError):
                stage.stage("v1.2.3", "a" * 40, output)
            self.assertEqual(run.call_count, 1)
            self.assertEqual((output / "sentinel").read_text(), "retained")


if __name__ == "__main__":
    unittest.main()
