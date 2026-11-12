from __future__ import annotations

from collections import Counter
from typing import Any, Mapping, Sequence

from .domain import (
    Version,
    deterministic_bucket,
    fingerprint,
    parse_time,
    require_bool,
    require_choice,
    require_identifier,
    require_list,
    require_mapping,
    require_string,
    unique_items,
)
from .errors import DomainError


DEVICE_STATES = ("active", "held", "retired")
RISK_LEVELS = ("low", "medium", "high", "critical")


def validate_device(value: Any, index: int) -> dict[str, Any]:
    path = f"devices[{index}]"
    source = require_mapping(value, path)
    attributes = require_mapping(source.get("attributes", {}), f"{path}.attributes")
    last_seen_at = parse_time(source.get("last_seen_at"), f"{path}.last_seen_at")
    return {
        "device_id": require_identifier(source.get("device_id"), f"{path}.device_id"),
        "identity_code": require_identifier(source.get("identity_code"), f"{path}.identity_code"),
        "current_version": require_string(source.get("current_version"), f"{path}.current_version"),
        "bootloader_version": require_string(source.get("bootloader_version"), f"{path}.bootloader_version"),
        "hardware_model": require_identifier(source.get("hardware_model"), f"{path}.hardware_model"),
        "region": require_identifier(source.get("region"), f"{path}.region"),
        "channel": require_identifier(source.get("channel"), f"{path}.channel"),
        "risk_level": require_choice(source.get("risk_level"), f"{path}.risk_level", RISK_LEVELS),
        "state": require_choice(source.get("state"), f"{path}.state", DEVICE_STATES),
        "battery_ready": require_bool(source.get("battery_ready"), f"{path}.battery_ready"),
        "storage_ready": require_bool(source.get("storage_ready"), f"{path}.storage_ready"),
        "network_ready": require_bool(source.get("network_ready"), f"{path}.network_ready"),
        "last_seen_at": last_seen_at.isoformat(),
        "attributes": {str(key): str(item) for key, item in sorted(attributes.items())},
    }


def eligibility_reasons(
    device: Mapping[str, Any],
    plan: Mapping[str, Any],
    snapshot_at: str,
    *,
    maximum_staleness_hours: int = 72,
) -> list[str]:
    reasons: list[str] = []
    if device["state"] != "active":
        reasons.append(f"device_state:{device['state']}")
    if device["identity_code"] != plan["identity"]["identity_code"]:
        reasons.append("identity_code_mismatch")
    if device["channel"] != plan["channel"]:
        reasons.append("channel_mismatch")
    if Version.parse(device["current_version"]).release_key() != Version.parse(plan["versioning"]["current"]).release_key():
        reasons.append("current_version_mismatch")
    if Version.parse(device["bootloader_version"]).release_key() < Version.parse(
        plan["versioning"]["minimum_bootloader"]
    ).release_key():
        reasons.append("bootloader_too_old")
    if not device["battery_ready"]:
        reasons.append("battery_not_ready")
    if not device["storage_ready"]:
        reasons.append("storage_not_ready")
    if not device["network_ready"]:
        reasons.append("network_not_ready")
    age_seconds = (parse_time(snapshot_at) - parse_time(device["last_seen_at"])).total_seconds()
    if age_seconds < 0:
        reasons.append("last_seen_in_future")
    if age_seconds > maximum_staleness_hours * 3600:
        reasons.append("device_stale")
    return reasons


def cohort_key(device: Mapping[str, Any], dimensions: Sequence[str]) -> str:
    supported = {
        "hardware_model": device["hardware_model"],
        "region": device["region"],
        "risk_level": device["risk_level"],
        "channel": device["channel"],
    }
    unknown = sorted(set(dimensions) - set(supported))
    if unknown:
        raise DomainError("unknown_cohort_dimension", "unknown cohort dimensions", details={"unknown": unknown})
    return "|".join(f"{dimension}={supported[dimension]}" for dimension in dimensions)


def build_eligibility_snapshot(
    devices_input: Any,
    plan: Mapping[str, Any],
    snapshot_at: str,
    *,
    dimensions: Sequence[str] = ("hardware_model", "region", "risk_level"),
    maximum_staleness_hours: int = 72,
) -> dict[str, Any]:
    parse_time(snapshot_at, "snapshot_at")
    devices = [
        validate_device(item, index)
        for index, item in enumerate(require_list(devices_input, "devices", minimum=1))
    ]
    devices = unique_items(devices, lambda item: item["device_id"], "devices")
    eligible: list[dict[str, Any]] = []
    held: list[dict[str, Any]] = []
    for device in devices:
        reasons = eligibility_reasons(
            device,
            plan,
            snapshot_at,
            maximum_staleness_hours=maximum_staleness_hours,
        )
        record = dict(device)
        record["cohort_key"] = cohort_key(device, dimensions)
        record["eligibility_bucket"] = deterministic_bucket(
            f"{plan['plan_id']}|{device['device_id']}|eligibility", 1_000_000
        )
        record["eligibility_reasons"] = reasons
        if reasons:
            held.append(record)
        else:
            eligible.append(record)
    eligible.sort(key=lambda item: (item["cohort_key"], item["eligibility_bucket"], item["device_id"]))
    held.sort(key=lambda item: item["device_id"])
    cohort_counts = Counter(item["cohort_key"] for item in eligible)
    hold_reasons = Counter(reason for item in held for reason in item["eligibility_reasons"])
    snapshot = {
        "snapshot_at": snapshot_at,
        "plan_id": plan["plan_id"],
        "identity_code": plan["identity"]["identity_code"],
        "dimensions": list(dimensions),
        "eligible_devices": eligible,
        "held_devices": held,
        "eligible_count": len(eligible),
        "held_count": len(held),
        "cohort_counts": dict(sorted(cohort_counts.items())),
        "hold_reason_counts": dict(sorted(hold_reasons.items())),
    }
    snapshot["snapshot_digest"] = fingerprint(snapshot)
    return snapshot


def verify_snapshot(snapshot: Mapping[str, Any]) -> dict[str, Any]:
    material = {key: value for key, value in snapshot.items() if key != "snapshot_digest"}
    expected = fingerprint(material)
    actual = snapshot.get("snapshot_digest")
    duplicate_ids = [
        device_id
        for device_id, count in Counter(
            item["device_id"] for item in list(snapshot["eligible_devices"]) + list(snapshot["held_devices"])
        ).items()
        if count > 1
    ]
    return {
        "valid": expected == actual and not duplicate_ids,
        "expected_digest": expected,
        "actual_digest": actual,
        "duplicate_device_ids": sorted(duplicate_ids),
        "eligible_count_matches": snapshot["eligible_count"] == len(snapshot["eligible_devices"]),
        "held_count_matches": snapshot["held_count"] == len(snapshot["held_devices"]),
    }


def split_large_cohorts(snapshot: Mapping[str, Any], maximum_size: int) -> dict[str, Any]:
    if maximum_size <= 0:
        raise DomainError("invalid_cohort_size", "maximum cohort size must be positive")
    grouped: dict[str, list[dict[str, Any]]] = {}
    for device in snapshot["eligible_devices"]:
        grouped.setdefault(device["cohort_key"], []).append(dict(device))
    eligible: list[dict[str, Any]] = []
    for key, devices in sorted(grouped.items()):
        for index, device in enumerate(devices):
            shard = index // maximum_size
            device["cohort_key"] = f"{key}|shard={shard + 1}"
            eligible.append(device)
    result = dict(snapshot)
    result["eligible_devices"] = eligible
    result["cohort_counts"] = dict(sorted(Counter(item["cohort_key"] for item in eligible).items()))
    result.pop("snapshot_digest", None)
    result["snapshot_digest"] = fingerprint(result)
    return result


def snapshot_summary(snapshot: Mapping[str, Any]) -> dict[str, Any]:
    critical = sum(1 for item in snapshot["eligible_devices"] if item["risk_level"] == "critical")
    return {
        "snapshot_at": snapshot["snapshot_at"],
        "eligible": snapshot["eligible_count"],
        "held": snapshot["held_count"],
        "cohorts": len(snapshot["cohort_counts"]),
        "critical_eligible": critical,
        "top_hold_reasons": sorted(
            snapshot["hold_reason_counts"].items(), key=lambda item: (-item[1], item[0])
        )[:5],
        "snapshot_digest": snapshot["snapshot_digest"],
    }

