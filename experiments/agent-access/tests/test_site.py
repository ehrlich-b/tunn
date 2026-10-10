import importlib.util
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
spec = importlib.util.spec_from_file_location("build", ROOT / "build.py")
build = importlib.util.module_from_spec(spec)
spec.loader.exec_module(build)


class LocalSiteTests(unittest.TestCase):
    def test_remote_references_and_actions_rejected(self):
        for html in ('<script src="https://example.invalid/a.js"></script>',
                     '<a href="mailto:someone@example.invalid">Send</a>',
                     '<form></form>', '<iframe src="local.html"></iframe>',
                     '<button onclick="fetch(1)">Signup</button>'):
            with self.subTest(html=html), self.assertRaises(ValueError):
                build.LocalPage().feed(html)

    def test_variants_label_unavailable_claims(self):
        for name in ("index.html", "team.html"):
            html = (ROOT / "site" / name).read_text()
            build.LocalPage().feed(html)
            self.assertIn("LOCAL PROTOTYPE", html)
            self.assertIn("disabled", html)
            self.assertIn("unavailable", html)
            self.assertNotIn("https://", html)
            self.assertIn("form-action 'none'", html)

    def test_output_cannot_overwrite_source(self):
        with self.assertRaises(ValueError):
            build.build(ROOT / "site")


if __name__ == "__main__":
    unittest.main()
