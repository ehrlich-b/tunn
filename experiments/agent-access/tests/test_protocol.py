import json
from pathlib import Path
import unittest
import hashlib
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import draft_copy
import evaluate


class FrozenProtocolTests(unittest.TestCase):
    def test_frozen_decisions(self):
        protocol = json.loads((ROOT / "protocol.json").read_text())
        self.assertEqual(protocol["protocol_id"], "tunn-access-e1-e2-v1")
        self.assertEqual(protocol["experiments"]["E1"], {
            "target_responses": 10, "minimum_recurring": 6,
            "minimum_per_recipe": 3, "minimum_occurrences_last_month": 2,
            "deadline_day": 14, "recruitment_minutes_ceiling": 50,
        })
        self.assertEqual(protocol["experiments"]["E2"], {
            "participants": 6, "participants_per_recipe": 3,
            "minimum_successes": 4, "maximum_active_seconds": 300,
            "maximum_baseline_ratio": 0.5,
            "owner_review_minutes_ceiling": 35, "deadline_day": 21,
        })
        self.assertTrue(protocol["offers"]["early_users_grandfathered"])
        self.assertEqual(protocol["offers"]["personal_launch_annual_usd"], 12)

    def test_protocol_content_pin_matches(self):
        self.assertEqual(hashlib.sha256((ROOT / "protocol.json").read_bytes()).hexdigest(), evaluate.FROZEN_PROTOCOL_SHA256)

    def test_exact_copy_packet_has_not_drifted(self):
        self.assertEqual((ROOT / "DRAFT-COPY.md").read_text(), draft_copy.copy_packet())


if __name__ == "__main__":
    unittest.main()
