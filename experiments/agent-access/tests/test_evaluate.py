import copy
import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("evaluate", ROOT / "evaluate.py")
ev = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ev)


def data_for_test():
    """Asserted-actual arithmetic test objects, never customer observations."""
    data = ev.read_json(ROOT / "fixtures" / "synthetic.json")
    for cohort in data["cohorts"].values():
        cohort["kind"] = "actual"
        cohort["invited"] = len(cohort["participants"])
    e2 = data["cohorts"]["E2"]
    e2["security_review_receipt"] = "unittest-only:review"
    e2["client_acceptance_receipt"] = "unittest-only:client"
    e2["baseline_reproductions"] = [{"candidate": name, "status": "supported", "receipt": "unittest-only:comparison"}
                                   for name in ("tunn", "pomerium", "cloudflare", "pangolin")]
    for row in data["observations"]:
        row["kind"] = "actual"
        row["record_complete"] = True
    return data


class EvaluationTests(unittest.TestCase):
    def decision(self, data, experiment="E2"):
        return ev.evaluate(data)["experiments"][experiment]

    def test_synthetic_never_passes(self):
        report = ev.evaluate(ev.read_json(ROOT / "fixtures" / "synthetic.json"))
        self.assertEqual(report["actual_observation_rows"], 0)
        for result in report["experiments"].values():
            self.assertEqual(result["decision"], "NO_ACTUAL_EVIDENCE")
            self.assertIsNone(result["actual_denominator"])
            self.assertIsNone(result["invitations"])

    def test_asserted_actual_frozen_gate_arithmetic(self):
        data = data_for_test()
        self.assertEqual(self.decision(data, "E1")["decision"], "PASS")
        result = self.decision(data)
        self.assertEqual(result["decision"], "PASS")
        self.assertEqual(result["qualifying_successes"], 4)
        self.assertEqual(result["by_recipe"]["browser"]["qualifying_successes"], 1)
        self.assertEqual(result["metrics"]["dropped_out"]["count"], 1)
        self.assertEqual(result["actual_denominator"], 6)
        self.assertIsNone(result["support_minutes"]["total"])
        self.assertEqual(result["support_minutes"]["known_partial"], 4)
        self.assertEqual(result["support_minutes"]["missing"], 1)

    def test_duplicate_observations_exclude_every_copy(self):
        data = data_for_test()
        data["observations"].append(copy.deepcopy(data["observations"][10]))
        result = self.decision(data)
        self.assertEqual(result["decision"], "INVALID")
        self.assertEqual(len(result["excluded"]), 2)
        self.assertEqual(result["actual_denominator"], 6)

    def test_duplicate_roster_and_task_cannot_pass(self):
        for field in ("participant_id", "task_id"):
            data = data_for_test()
            data["cohorts"]["E2"]["participants"][1][field] = data["cohorts"]["E2"]["participants"][0][field]
            self.assertNotEqual(self.decision(data)["decision"], "PASS")

    def test_incomplete_and_simulated_cannot_count(self):
        for field, value in (("record_complete", False), ("kind", "simulated"), ("active_seconds", None),
                             ("baseline_active_seconds", 0), ("required_assistance", None),
                             ("useful_task_receipt", None), ("denied_receipt", None), ("revoked_receipt", None)):
            data = data_for_test()
            data["observations"][10][field] = value
            result = self.decision(data)
            self.assertLess(result["qualifying_successes"], 4)
            self.assertNotEqual(result["decision"], "PASS")

    def test_missing_denominators_stay_undefined(self):
        data = data_for_test()
        data["cohorts"]["E2"]["participants"] = None
        result = self.decision(data)
        self.assertIsNone(result["actual_denominator"])
        self.assertIsNone(result["metrics"]["completed_useful_task"]["fraction"])
        self.assertNotEqual(result["decision"], "PASS")
        data = data_for_test()
        data["cohorts"]["E2"]["invited"] = None
        self.assertNotEqual(self.decision(data)["decision"], "PASS")

    def test_simulated_dropout_cannot_complete_actual_cohort(self):
        data = data_for_test()
        data["observations"][-1]["kind"] = "simulated"
        result = self.decision(data)
        self.assertEqual(result["qualifying_successes"], 4)
        self.assertEqual(result["decision"], "INCOMPLETE")

    def test_wrong_counterbalance_cannot_pass(self):
        data = data_for_test()
        data["observations"][13]["order"] = "tunn-first"
        self.assertEqual(self.decision(data)["decision"], "INCOMPLETE")

    def test_absent_dropout_is_preserved(self):
        data = data_for_test()
        data["observations"].pop()
        result = self.decision(data)
        self.assertEqual(result["actual_denominator"], 6)
        self.assertEqual(len(result["missing_participants"]), 1)
        self.assertNotEqual(result["decision"], "PASS")

    def test_frozen_kill_and_open_window(self):
        data = data_for_test()
        data["observations"][10]["next_task_choice"] = "baseline"
        self.assertEqual(self.decision(data)["decision"], "KILL")
        data["cohorts"]["E2"].update(closed=False, elapsed_day=1)
        self.assertEqual(self.decision(data)["decision"], "PENDING")
        data["cohorts"]["E2"]["elapsed_day"] = 21
        self.assertEqual(self.decision(data)["decision"], "KILL")

    def test_e1_recipe_failure_and_time_cap(self):
        data = data_for_test()
        data["observations"][5]["occurrences_last_month"] = 1
        self.assertEqual(self.decision(data, "E1")["decision"], "KILL")
        data = data_for_test()
        data["cohorts"]["E1"]["elapsed_day"] = 15
        self.assertEqual(self.decision(data, "E1")["decision"], "KILL")
        data = data_for_test()
        data["cohorts"]["E1"]["recruitment_minutes"] = 51
        self.assertEqual(self.decision(data, "E1")["decision"], "KILL")

    def test_missing_real_prerequisites_block_e2(self):
        for field in ("security_review_receipt", "client_acceptance_receipt", "baseline_reproductions"):
            data = data_for_test()
            data["cohorts"]["E2"][field] = None
            self.assertEqual(self.decision(data)["decision"], "INCOMPLETE")

    def test_unsafe_even_in_duplicate_incomplete_row_stops(self):
        data = data_for_test()
        row = copy.deepcopy(data["observations"][10])
        row.update(unsafe_grant=True, record_complete=False)
        data["observations"].append(row)
        self.assertEqual(self.decision(data)["decision"], "STOP_UNSAFE")

    def test_repeat_tasks_exclude_retries_reminders_and_same_day(self):
        data = data_for_test()
        row = data["observations"][10]
        def event(day, **changes):
            return {"date": day, "useful": True, "voluntary": True, "reminded": False,
                    "health_check": False, "retry": False, "receipt": "unittest-only:repeat", **changes}
        row["repeat_use"] = [event("2026-10-10"), event("2026-10-11"), event("2026-10-11"),
                             event("2026-10-12", reminded=True), event("2026-10-13", retry=True)]
        self.assertFalse(ev.repeated_use(row))
        row["repeat_use"].append(event("2026-10-14"))
        self.assertTrue(ev.repeated_use(row))

    def test_paid_intent_cannot_become_payment(self):
        data = data_for_test()
        data["observations"][10].update(written_paid_intent=True, written_paid_intent_receipt="unittest-only:intent")
        result = self.decision(data)
        self.assertEqual(result["metrics"]["written_paid_intent"]["count"], 1)
        self.assertIsNone(result["metrics"]["payment_collected"]["count"])

    def test_observations_cannot_override_protocol(self):
        data = data_for_test()
        data["thresholds"] = {"minimum_successes": 0}
        with self.assertRaises(ValueError):
            ev.evaluate(data)

    def test_offer_arithmetic_does_not_touch_entitlements(self):
        snapshot = {"customer": {"plan": "legacy", "annual_usd": 12, "capacity": 999}}
        original = copy.deepcopy(snapshot)
        self.assertEqual(ev.offer_arithmetic(3)["monthly_usd"], 18)
        self.assertEqual(ev.offer_arithmetic(3)["entitlement_changes"], [])
        self.assertEqual(snapshot, original)
        for invalid in (-1, True, 1.5, None):
            with self.assertRaises(ValueError):
                ev.offer_arithmetic(invalid)

    def test_nonfinite_numbers_booleans_and_duplicate_json_keys_rejected(self):
        data = data_for_test()
        for invalid in (float("nan"), -5, True):
            data["observations"][10]["active_seconds"] = invalid
            if isinstance(invalid, float):
                with self.assertRaises(ValueError):
                    ev.evaluate(data)
            else:
                self.assertNotEqual(self.decision(data)["decision"], "PASS")
        with self.assertRaises(ValueError):
            json.loads('{"kind":"simulated","kind":"actual"}', object_pairs_hook=ev.unique_keys)


if __name__ == "__main__":
    unittest.main()
