from __future__ import annotations

import math
from collections import defaultdict
from typing import Any, Mapping, Sequence

from .domain import chunked, deterministic_order, fingerprint
from .errors import DomainError


def _desired_count(total: int, percentage: float) -> int:
    if total <= 0:
        return 0
    return min(total, max(1, math.ceil(total * percentage / 100.0)))


def _ordered_cohorts(snapshot: Mapping[str, Any], salt: str) -> dict[str, list[dict[str, Any]]]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for device in snapshot["eligible_devices"]:
        grouped[device["cohort_key"]].append(dict(device))
    return {
        key: deterministic_order(values, lambda item: item["device_id"], f"{salt}|{key}")
        for key, values in sorted(grouped.items())
    }


def _allocate_targets(
    cohorts: Mapping[str, Sequence[Mapping[str, Any]]],
    desired_total: int,
    previous: Mapping[str, int],
) -> dict[str, int]:
    total = sum(len(values) for values in cohorts.values())
    remaining = max(0, desired_total - sum(previous.values()))
    targets = dict(previous)
    if remaining == 0 or total == 0:
        return targets
    candidates: list[tuple[float, str]] = []
    for key, values in cohorts.items():
        ideal = desired_total * len(values) / total
        available = len(values) - previous.get(key, 0)
        base = min(available, max(0, math.floor(ideal) - previous.get(key, 0)))
        targets[key] = previous.get(key, 0) + base
        remaining -= base
        fraction = ideal - math.floor(ideal)
        candidates.append((fraction, key))
    candidates.sort(key=lambda item: (-item[0], item[1]))
    while remaining > 0:
        progressed = False
        for _, key in candidates:
            if targets.get(key, 0) < len(cohorts[key]):
                targets[key] = targets.get(key, 0) + 1
                remaining -= 1
                progressed = True
                if remaining == 0:
                    break
        if not progressed:
            break
    return targets


def _wave_assignments(
    cohorts: Mapping[str, Sequence[Mapping[str, Any]]],
    previous: Mapping[str, int],
    targets: Mapping[str, int],
) -> list[dict[str, Any]]:
    assignments: list[dict[str, Any]] = []
    for cohort_key, devices in sorted(cohorts.items()):
        start = previous.get(cohort_key, 0)
        end = targets.get(cohort_key, 0)
        for device in devices[start:end]:
            assignments.append(
                {
                    "device_id": device["device_id"],
                    "cohort_key": cohort_key,
                    "risk_level": device["risk_level"],
                    "hardware_model": device["hardware_model"],
                    "region": device["region"],
                    "eligibility_bucket": device["eligibility_bucket"],
                }
            )
    assignments.sort(key=lambda item: (item["cohort_key"], item["eligibility_bucket"], item["device_id"]))
    return assignments


def _batches(assignments: Sequence[dict[str, Any]], maximum_parallel: int) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for index, batch in enumerate(chunked(assignments, maximum_parallel), start=1):
        result.append(
            {
                "batch_id": f"batch-{index:03d}",
                "sequence": index,
                "device_ids": [item["device_id"] for item in batch],
                "cohort_keys": sorted({item["cohort_key"] for item in batch}),
                "critical_count": sum(item["risk_level"] == "critical" for item in batch),
            }
        )
    return result


def schedule_waves(
    snapshot: Mapping[str, Any],
    plan: Mapping[str, Any],
    dependency_graph: Mapping[str, Any],
) -> dict[str, Any]:
    total = snapshot["eligible_count"]
    if total <= 0:
        raise DomainError("no_eligible_devices", "cannot schedule a release without eligible devices")
    cohorts = _ordered_cohorts(snapshot, plan["plan_id"])
    previous_targets: dict[str, int] = {key: 0 for key in cohorts}
    waves: list[dict[str, Any]] = []
    assigned_devices: set[str] = set()
    policies = plan["rollout"]["waves"]
    for index, policy in enumerate(policies, start=1):
        desired = _desired_count(total, policy["target_percentage"])
        targets = _allocate_targets(cohorts, desired, previous_targets)
        assignments = _wave_assignments(cohorts, previous_targets, targets)
        duplicate = sorted(item["device_id"] for item in assignments if item["device_id"] in assigned_devices)
        if duplicate:
            raise DomainError("duplicate_wave_assignment", "device appears in multiple incremental waves", details={"devices": duplicate})
        assigned_devices.update(item["device_id"] for item in assignments)
        wave_id = f"wave-{index:03d}-{policy['name']}"
        wave = {
            "wave_id": wave_id,
            "sequence": index,
            "name": policy["name"],
            "target_percentage": policy["target_percentage"],
            "cumulative_target_count": desired,
            "incremental_count": len(assignments),
            "minimum_observation_minutes": policy["minimum_observation_minutes"],
            "maximum_parallel_devices": policy["maximum_parallel_devices"],
            "requires_checkpoint": policy["requires_checkpoint"],
            "depends_on_wave_id": waves[-1]["wave_id"] if waves else None,
            "capability_stages": dependency_graph["stages"],
            "assignments": assignments,
            "batches": _batches(assignments, policy["maximum_parallel_devices"]),
        }
        wave["wave_digest"] = fingerprint(wave)
        waves.append(wave)
        previous_targets = targets
    if len(assigned_devices) != total:
        missing = sorted(
            item["device_id"] for item in snapshot["eligible_devices"] if item["device_id"] not in assigned_devices
        )
        raise DomainError("incomplete_schedule", "final wave does not cover all eligible devices", details={"missing": missing})
    schedule = {
        "plan_id": plan["plan_id"],
        "snapshot_digest": snapshot["snapshot_digest"],
        "eligible_count": total,
        "cohort_counts": snapshot["cohort_counts"],
        "waves": waves,
        "dependency_graph_digest": dependency_graph["graph_digest"],
    }
    schedule["schedule_digest"] = fingerprint(schedule)
    return schedule


def verify_schedule(schedule: Mapping[str, Any]) -> dict[str, Any]:
    all_assignments = [item for wave in schedule["waves"] for item in wave["assignments"]]
    device_ids = [item["device_id"] for item in all_assignments]
    duplicates = sorted({device_id for device_id in device_ids if device_ids.count(device_id) > 1})
    wave_digest_failures: list[str] = []
    dependency_failures: list[str] = []
    previous_wave_id: str | None = None
    previous_target = 0
    for wave in schedule["waves"]:
        material = {key: value for key, value in wave.items() if key != "wave_digest"}
        if fingerprint(material) != wave["wave_digest"]:
            wave_digest_failures.append(wave["wave_id"])
        if wave["depends_on_wave_id"] != previous_wave_id:
            dependency_failures.append(wave["wave_id"])
        if wave["cumulative_target_count"] < previous_target:
            dependency_failures.append(wave["wave_id"])
        previous_target = wave["cumulative_target_count"]
        previous_wave_id = wave["wave_id"]
    material = {key: value for key, value in schedule.items() if key != "schedule_digest"}
    expected = fingerprint(material)
    return {
        "valid": not duplicates and not wave_digest_failures and not dependency_failures and expected == schedule["schedule_digest"],
        "duplicate_device_ids": duplicates,
        "wave_digest_failures": wave_digest_failures,
        "dependency_failures": sorted(set(dependency_failures)),
        "expected_schedule_digest": expected,
        "actual_schedule_digest": schedule["schedule_digest"],
        "assigned_count": len(device_ids),
    }


def schedule_summary(schedule: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "eligible_count": schedule["eligible_count"],
        "wave_count": len(schedule["waves"]),
        "batch_count": sum(len(wave["batches"]) for wave in schedule["waves"]),
        "wave_sizes": {wave["wave_id"]: wave["incremental_count"] for wave in schedule["waves"]},
        "schedule_digest": schedule["schedule_digest"],
    }

