#!/usr/bin/env python3
"""Evaluate explicit local observations against a frozen protocol, offline."""
import argparse
from collections import Counter
from datetime import date
import hashlib
import json
import math
from pathlib import Path

ROOT = Path(__file__).resolve().parent
PROTOCOL_ID = "tunn-access-e1-e2-v1"
FROZEN_PROTOCOL_SHA256 = "3e85498ce6184e59bb1d47254002cec8a12fefc24f7ab883d427fd73d576951a"
RECIPES = ("mcp", "browser")


def number(value):
    return type(value) in (int, float) and math.isfinite(value) and value >= 0


def integer(value):
    return type(value) is int and value >= 0


def text(value):
    return isinstance(value, str) and bool(value.strip())


def unique_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"Duplicate JSON key: {key}")
        result[key] = value
    return result


def read_json(path):
    return json.loads(Path(path).read_text(), object_pairs_hook=unique_keys,
                      parse_constant=lambda value: (_ for _ in ()).throw(ValueError(f"Non-finite JSON number: {value}")))


def load_protocol():
    if hashlib.sha256((ROOT / "protocol.json").read_bytes()).hexdigest() != FROZEN_PROTOCOL_SHA256:
        raise ValueError("Frozen protocol changed; choose a new version before collecting new evidence")
    protocol = read_json(ROOT / "protocol.json")
    if protocol["protocol_id"] != PROTOCOL_ID:
        raise ValueError("Unsupported protocol")
    return protocol


def offer_arithmetic(maintainers):
    """A hypothetical quote only; no entitlement input, storage or write path."""
    if not integer(maintainers):
        raise ValueError("Maintainers must be a nonnegative integer")
    return {"status": "proposed; unavailable", "maintainers": maintainers,
            "monthly_usd": maintainers * 6, "annual_usd": maintainers * 6 * 12,
            "personal_launch_annual_usd": 12, "early_users_grandfathered": True,
            "entitlement_changes": []}


def valid_date(value):
    if not text(value):
        return False
    try:
        return date.fromisoformat(value).isoformat() == value
    except ValueError:
        return False


def row_errors(row, experiment):
    errors = []
    if row.get("kind") not in {"actual", "simulated"}:
        errors.append("missing actual/simulated classification")
    if row.get("record_complete") is not True:
        errors.append("incomplete observation record")
    if not text(row.get("source_receipt")):
        errors.append("missing local source receipt")
    if not valid_date(row.get("observed_on")):
        errors.append("missing or invalid observation date")
    if type(row.get("dropped_out")) is not bool:
        errors.append("missing dropout status")
    support = row.get("support_minutes")
    if support is not None and not number(support):
        errors.append("invalid support minutes")
    if experiment == "E1":
        for field in ("is_owner", "outside_caller_task"):
            if type(row.get(field)) is not bool:
                errors.append(f"missing {field}")
        if not integer(row.get("occurrences_last_month")):
            errors.append("missing occurrences in last month")
        if not valid_date(row.get("last_occurrence")):
            errors.append("missing last occurrence")
        elif valid_date(row.get("observed_on")):
            days = (date.fromisoformat(row["observed_on"]) - date.fromisoformat(row["last_occurrence"])).days
            if not 0 <= days <= 31:
                errors.append("last occurrence outside the measured month")
        if not text(row.get("workaround")):
            errors.append("missing baseline workaround")
    else:
        for field in ("activated", "completed_useful_task", "required_assistance", "unsafe_grant"):
            if type(row.get(field)) is not bool:
                errors.append(f"missing {field}")
        if row.get("order") not in {"tunn-first", "baseline-first"}:
            errors.append("missing comparison order")
        if row.get("next_task_choice") not in {"tunn", "baseline", "neither", None}:
            errors.append("invalid next-task choice")
        for field in ("baseline_name", "baseline_reason", "baseline_receipt"):
            if not text(row.get(field)):
                errors.append(f"missing {field}")
        for field in ("active_seconds", "baseline_active_seconds", "wall_seconds", "passive_wait_seconds"):
            value = row.get(field)
            if value is not None and not number(value):
                errors.append(f"invalid {field}")
        if number(row.get("wall_seconds")) and number(row.get("active_seconds")) and row["wall_seconds"] < row["active_seconds"]:
            errors.append("wall timing shorter than active timing")
        if row.get("completed_useful_task") is True:
            for field in ("active_seconds", "wall_seconds", "passive_wait_seconds"):
                if not number(row.get(field)):
                    errors.append(f"missing {field}")
            if not number(row.get("baseline_active_seconds")) or row["baseline_active_seconds"] <= 0:
                errors.append("missing positive baseline timing")
            for field in ("useful_task_receipt", "denied_receipt", "revoked_receipt"):
                if not text(row.get(field)):
                    errors.append(f"missing {field}")
            if row.get("next_task_choice") is None:
                errors.append("missing next-task choice")
    for field in ("written_paid_intent", "payment_collected"):
        if row.get(field) is not None and type(row[field]) is not bool:
            errors.append(f"invalid {field}")
        if row.get(field) is True and not text(row.get(field + "_receipt")):
            errors.append(f"missing {field} receipt")
    if row.get("payment_collected") is True and (not number(row.get("payment_usd")) or row["payment_usd"] <= 0):
        errors.append("missing positive collected payment")
    repeat = row.get("repeat_use")
    if repeat is not None:
        if not isinstance(repeat, list):
            errors.append("invalid repeat-use records")
        else:
            for event in repeat:
                if not isinstance(event, dict) or not valid_date(event.get("date")) or any(
                        type(event.get(key)) is not bool for key in ("useful", "voluntary", "reminded", "health_check", "retry")):
                    errors.append("incomplete repeat-use event")
                elif not text(event.get("receipt")):
                    errors.append("missing repeat-use receipt")
    return errors


def repeated_use(row):
    if row.get("repeat_use") is None:
        return None
    days = {event["date"] for event in row["repeat_use"]
            if event["date"] > row["observed_on"] and event["useful"] and event["voluntary"]
            and not (event["reminded"] or event["health_check"] or event["retry"])}
    return len(days) >= 2


def metric(rows, field, denominator):
    values = [repeated_use(row) if field == "repeat_on_two_later_days" else row.get(field) for row in rows]
    known = [value for value in values if type(value) is bool]
    count = sum(value is True for value in known)
    return {"count": count if known else None, "observed": len(known),
            "denominator": denominator,
            "missing": denominator - len(known) if denominator is not None else None,
            "fraction": count / denominator if denominator and len(known) == denominator else None}


def evaluate(data):
    if not isinstance(data, dict) or data.get("protocol_id") != PROTOCOL_ID:
        raise ValueError(f"Input must name frozen protocol {PROTOCOL_ID}")
    if not isinstance(data.get("observations"), list) or not isinstance(data.get("cohorts"), dict):
        raise ValueError("Input needs explicit cohorts and observations")
    if "thresholds" in data or "offers" in data:
        raise ValueError("Observations cannot override thresholds or offers")
    protocol = load_protocol()
    observations = data["observations"]
    if any(not isinstance(row, dict) or row.get("experiment") not in {"E1", "E2"} for row in observations):
        raise ValueError("Every observation must identify E1 or E2")
    reports = {}
    for experiment in ("E1", "E2"):
        rules = protocol["experiments"][experiment]
        cohort = data["cohorts"].get(experiment, {})
        if not isinstance(cohort, dict):
            raise ValueError(f"Invalid {experiment} cohort")
        roster = cohort.get("participants")
        integrity = []
        if roster is not None and (not isinstance(roster, list) or any(not isinstance(p, dict) for p in roster)):
            raise ValueError("Roster must be a list of participant/task identities or null")
        roster = roster if isinstance(roster, list) else None
        denominator = len(roster) if roster is not None else None
        roster = roster or []
        expected = rules["target_responses"] if experiment == "E1" else rules["participants"]
        if denominator != expected:
            integrity.append(f"need original {expected}-person roster; denominator remains {denominator}")
        if any(not text(p.get("participant_id")) or not text(p.get("task_id")) or p.get("recipe") not in RECIPES for p in roster):
            integrity.append("invalid roster identity or recipe")
        identities = Counter(p.get("participant_id") for p in roster)
        tasks = Counter(p.get("task_id") for p in roster)
        if any(n > 1 for n in identities.values()) or any(n > 1 for n in tasks.values()):
            integrity.append("duplicate roster participant or task identity")
        rows = [row for row in observations if row["experiment"] == experiment]
        ids = Counter(row.get("participant_id") for row in rows)
        task_ids = Counter(row.get("task_id") for row in rows)
        duplicate_ids = {key for key, count in ids.items() if count > 1}
        duplicate_tasks = {key for key, count in task_ids.items() if count > 1}
        if duplicate_ids or duplicate_tasks:
            integrity.append("duplicate observations: all copies excluded")
        actual = []
        simulated = []
        excluded = []
        row_details = []
        roster_map = {(p.get("participant_id"), p.get("task_id"), p.get("recipe")): p for p in roster}
        for index, row in enumerate(rows):
            errors = row_errors(row, experiment)
            key = (row.get("participant_id"), row.get("task_id"), row.get("recipe"))
            if key not in roster_map:
                errors.append("not in original roster")
            if row.get("participant_id") in duplicate_ids or row.get("task_id") in duplicate_tasks:
                errors.append("duplicate participant or task")
            if errors:
                excluded.append({"row": index, "participant_id": row.get("participant_id"), "reasons": errors})
            elif row["kind"] == "actual" and cohort.get("kind") == "actual":
                actual.append(row)
            else:
                simulated.append(row)
            row_details.append({"participant_id": row.get("participant_id"), "task_id": row.get("task_id"),
                                "recipe": row.get("recipe"), "kind": row.get("kind"),
                                "eligible_actual": row in actual, "errors": errors,
                                **{key: row.get(key) for key in ("dropped_out", "active_seconds", "baseline_active_seconds",
                                                               "required_assistance", "support_minutes", "price_response")}})
        absent = [p for p in roster if not any(row.get("participant_id") == p.get("participant_id") and
                                             row.get("task_id") == p.get("task_id") for row in rows)]
        actual_denominator = denominator if cohort.get("kind") == "actual" else None
        by_recipe = {recipe: {"roster": sum(p.get("recipe") == recipe for p in roster) if denominator is not None else None,
                              "eligible_actual": sum(row["recipe"] == recipe for row in actual)} for recipe in RECIPES}
        successes = []
        qualifying = []
        prerequisites = []
        day = cohort.get("elapsed_day")
        invited = cohort.get("invited")
        if not integer(day):
            prerequisites.append("unknown elapsed day")
        if not integer(invited) or denominator is None or invited < denominator:
            prerequisites.append("unknown or inconsistent invitation denominator")
        if type(cohort.get("closed")) is not bool:
            prerequisites.append("unknown collection-window status")
        if cohort.get("kind") != "actual":
            prerequisites.append("cohort is not actual")
        if simulated and cohort.get("kind") == "actual":
            prerequisites.append("simulated rows cannot stand in for actual cohort outcomes")
        ceiling_field = "recruitment_minutes" if experiment == "E1" else "owner_review_minutes"
        ceiling = rules["recruitment_minutes_ceiling"] if experiment == "E1" else rules["owner_review_minutes_ceiling"]
        minutes = cohort.get(ceiling_field)
        if not number(minutes):
            prerequisites.append(f"unknown {ceiling_field}")
        closed = cohort.get("closed") is True or (integer(day) and day >= rules["deadline_day"]) or (number(minutes) and minutes >= ceiling)
        if experiment == "E1":
            qualifying = [row for row in actual if row["is_owner"] and row["outside_caller_task"] and not row["dropped_out"]]
            successes = [row for row in qualifying if row["occurrences_last_month"] >= rules["minimum_occurrences_last_month"]]
            success_condition = len(qualifying) >= rules["target_responses"] and len(successes) >= rules["minimum_recurring"] and all(
                sum(row["recipe"] == recipe for row in successes) >= rules["minimum_per_recipe"] for recipe in RECIPES)
        else:
            if any(by_recipe[recipe]["roster"] != rules["participants_per_recipe"] for recipe in RECIPES):
                integrity.append("E2 requires three assigned participants per recipe")
            for recipe in RECIPES:
                orders = [row["order"] for row in actual if row["recipe"] == recipe]
                if not {"tunn-first", "baseline-first"}.issubset(orders):
                    prerequisites.append(f"missing counterbalanced {recipe} order")
                expected_first = 2 if recipe == "mcp" else 1
                if len(orders) == 3 and orders.count("tunn-first") != expected_first:
                    prerequisites.append(f"{recipe} order does not match frozen counterbalance")
            for field in ("security_review_receipt", "client_acceptance_receipt"):
                if not text(cohort.get(field)):
                    prerequisites.append(f"missing {field}")
            reproductions = cohort.get("baseline_reproductions")
            if not isinstance(reproductions, list):
                reproductions = []
            for candidate in ("tunn", "pomerium", "cloudflare", "pangolin"):
                entries = [entry for entry in reproductions if isinstance(entry, dict) and entry.get("candidate") == candidate]
                if len(entries) != 1 or entries[0].get("status") not in {"supported", "unsupported"} or not text(entries[0].get("receipt")) or (candidate == "tunn" and entries[0].get("status") != "supported"):
                    prerequisites.append(f"missing current {candidate} reproduction receipt")
            successes = [row for row in actual if row["completed_useful_task"] and not row["dropped_out"] and not row["unsafe_grant"]
                         and row["active_seconds"] <= rules["maximum_active_seconds"]
                         and row["active_seconds"] <= rules["maximum_baseline_ratio"] * row["baseline_active_seconds"]
                         and row["next_task_choice"] == "tunn"]
            success_condition = len(successes) >= rules["minimum_successes"]
        for recipe in RECIPES:
            by_recipe[recipe]["qualifying_successes"] = sum(row["recipe"] == recipe for row in successes)
        unsafe = any(row.get("kind") == "actual" and row.get("unsafe_grant") is True for row in rows)
        if unsafe:
            decision, reason = "STOP_UNSAFE", "An actual unsafe grant stops hosted testing immediately."
        elif cohort.get("kind") != "actual" or not rows:
            decision, reason = "NO_ACTUAL_EVIDENCE", "Synthetic or missing observations cannot establish demand."
        elif integrity:
            decision, reason = "INVALID", "; ".join(integrity)
        elif prerequisites or excluded or absent:
            decision = "KILL" if experiment == "E1" and closed else "INCOMPLETE"
            reason = "Missing/ineligible evidence cannot count; preserve the original denominator."
        elif success_condition and integer(day) and day <= rules["deadline_day"] and number(minutes) and minutes <= ceiling:
            decision, reason = "PASS", "Frozen local decision gate met by asserted actual observations; review receipts."
        elif closed:
            decision, reason = "KILL", "Frozen threshold or time ceiling missed; narrow or stop this hypothesis."
        else:
            decision, reason = "PENDING", "Collection remains open; do not extend the frozen deadline."
        supports = [row.get("support_minutes") for row in actual]
        support_known = [value for value in supports if number(value)]
        support_missing = actual_denominator - len(support_known) if actual_denominator is not None else None
        reports[experiment] = {
            "decision": decision, "reason": reason, "target_denominator": expected,
            "roster_denominator": denominator, "actual_denominator": actual_denominator,
            "invitations": invited if integer(invited) else None,
            "observation_rows": len(rows), "eligible_actual": len(actual), "eligible_simulated": len(simulated),
            "excluded": excluded, "missing_participants": absent, "integrity_errors": integrity,
            "required_evidence": prerequisites, "by_recipe": by_recipe,
            "qualifying_written_responses": len(qualifying), "qualifying_successes": len(successes),
            "metrics": {field: metric(actual, field, actual_denominator) for field in (
                "dropped_out", "activated", "completed_useful_task", "required_assistance",
                "written_paid_intent", "payment_collected", "repeat_on_two_later_days")},
            "support_minutes": {"total": sum(support_known) if support_missing == 0 and actual_denominator else None,
                                "known_partial": sum(support_known) if support_known else None,
                                "missing": support_missing},
            "price_responses": [{"participant_id": row["participant_id"], "response": row.get("price_response")}
                                for row in actual],
            "rows": row_details,
        }
    return {"protocol_id": PROTOCOL_ID, "protocol_sha256": hashlib.sha256((ROOT / "protocol.json").read_bytes()).hexdigest(),
            "input_sha256": hashlib.sha256(json.dumps(data, sort_keys=True, allow_nan=False).encode()).hexdigest(),
            "scope": "E1/E2 only; PASS is a small-cohort decision, not launch/security/payment approval",
            "actual_observation_rows": sum(row.get("kind") == "actual" for row in observations),
            "simulated_observation_rows": sum(row.get("kind") == "simulated" for row in observations),
            "experiments": reports, "example_offer_arithmetic": offer_arithmetic(3), "entitlement_changes": []}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.input.resolve() == args.out.resolve():
            raise ValueError("Output must not overwrite the observation input")
        report = evaluate(read_json(args.input))
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(report, indent=2, allow_nan=False) + "\n")
    except (ValueError, OSError, KeyError, TypeError) as exc:
        parser.exit(2, f"evaluate: {exc}\n")
    print("; ".join(f"{name}: {value['decision']} ({value['eligible_actual']} eligible actual)"
                    for name, value in report["experiments"].items()))


if __name__ == "__main__":
    main()
