import copy
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import evaluate
from render_results import render
from test_evaluate import data_for_test


class ResultPageTests(unittest.TestCase):
    def test_synthetic_report_honestly_labels_evidence(self):
        report = evaluate.evaluate(evaluate.read_json(ROOT / "fixtures" / "synthetic.json"))
        html = render(report)
        self.assertIn("0 asserted actual rows", html)
        self.assertIn("16 simulated rows", html)
        self.assertEqual(html.count("<h2>NO_ACTUAL_EVIDENCE</h2>"), 2)
        for label in ("Activation", "Useful completion", "Written paid intent", "Collected payment",
                      "Voluntary useful return", "Dropouts", "Known partial minutes", "undefined (null)",
                      "Original declared roster", "Every submitted row"):
            self.assertIn(label, html)
        self.assertIn("synthetic-10", html)

    def test_no_dynamic_markup_in_observation_fields(self):
        data = data_for_test()
        data["observations"][10]["price_response"] = '<img src="https://outside.invalid/pixel" onerror="alert(1)">'
        html = render(evaluate.evaluate(data))
        self.assertNotIn('<img', html)
        self.assertIn('&lt;img', html)
        self.assertIn('&quot;', html)

    def test_dropouts_partial_support_and_unknown_values_survive_rendering(self):
        report = evaluate.evaluate(data_for_test())
        result = report["experiments"]["E2"]
        self.assertEqual(result["actual_denominator"], 6)
        self.assertEqual(result["metrics"]["dropped_out"]["count"], 1)
        self.assertIsNone(result["support_minutes"]["total"])
        html = render(report)
        self.assertIn("undefined (null)", html)
        self.assertIn("Known partial minutes", html)
        self.assertIn("synthetic-06 / e2-fixture-06", html)


if __name__ == "__main__":
    unittest.main()
