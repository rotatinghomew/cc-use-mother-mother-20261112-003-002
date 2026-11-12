from __future__ import annotations

from collections import Counter
from typing import Any, Mapping

from .domain import fingerprint, parse_time
from .repository import Repository


def _issue(severity: str, code: str, message: str, **details: Any) -> dict[str, Any]:
    return {"severity": severity, "code": code, "message": message, "details": details}


def _repair(action: str, safe: bool, **parameters: Any) -> dict[str, Any]:
    return {"action": action, "safe": safe, "parameters": parameters}


def inspect_recovery(
    repository: Repository,
    release_id: str,
    now: str,
    *,
    stale_after_minutes: int = 60,
) -> dict[str, Any]:
    parse_time(now, "now")
    release = repository.get_release(release_id)
    issues: list[dict[str, Any]] = []
    repairs: list[dict[str, Any]] = []
    integrity = repository.integrity_check(release_id)
    if not integrity["valid"]:
        issues.append(_issue("critical", "integrity_failed", "repository integrity verification failed", integrity=integrity))
        repairs.append(_repair("restore_verified_backup", False, release_id=release_id))
    active_wave = None
    if release["active_wave_id"]:
        active_wave = next(
            (item for item in release["waves"] if item["wave_id"] == release["active_wave_id"]), None
        )
        if active_wave is None:
            issues.append(_issue("critical", "active_wave_missing", "release references a missing active wave"))
            repairs.append(_repair("pause_for_manual_reconciliation", True, reason="active_wave_missing"))
        elif active_wave["state"] not in {"running", "observing"} and release["state"] not in {"paused", "rolling_back"}:
            issues.append(
                _issue(
                    "critical",
                    "active_wave_state_mismatch",
                    "release and active wave states disagree",
                    release_state=release["state"],
                    wave_state=active_wave["state"],
                )
            )
            repairs.append(_repair("pause_for_manual_reconciliation", True, reason="active_wave_state_mismatch"))
    elif release["state"] in {"running", "observing"}:
        issues.append(_issue("critical", "active_wave_absent", "running release has no active wave"))
        repairs.append(_repair("pause_for_manual_reconciliation", True, reason="active_wave_absent"))
    stale_devices: list[str] = []
    now_value = parse_time(now)
    for device in release["devices"]:
        if device["state"] not in {"downloading", "installing", "rolling_back"}:
            continue
        if device["last_receipt_at"] is None:
            stale_devices.append(device["device_id"])
            continue
        age = (now_value - parse_time(device["last_receipt_at"])).total_seconds() / 60
        if age > stale_after_minutes:
            stale_devices.append(device["device_id"])
    if stale_devices:
        issues.append(
            _issue(
                "warning",
                "stale_device_operations",
                "device operations have not reported progress within the recovery threshold",
                device_ids=sorted(stale_devices),
            )
        )
        repairs.append(_repair("request_device_status", True, device_ids=sorted(stale_devices)))
    pending = repository.list_pending_receipts(release_id)
    if pending:
        issues.append(
            _issue(
                "warning",
                "pending_receipts",
                "receipts are waiting for prerequisite transitions",
                receipt_ids=[item["receipt_id"] for item in pending],
            )
        )
        repairs.append(_repair("drain_pending_receipts", True, release_id=release_id))
    checkpoints = repository.list_checkpoints(release_id)
    if not checkpoints and release["revision"] > 1:
        issues.append(_issue("warning", "checkpoint_missing", "mutated release has no durable checkpoint"))
        repairs.append(_repair("create_checkpoint", True, reason="recovery_checkpoint"))
    elif checkpoints:
        latest = checkpoints[-1]
        if latest["revision"] < release["revision"] - 2:
            issues.append(
                _issue(
                    "info",
                    "checkpoint_lag",
                    "latest checkpoint trails the current release revision",
                    latest_revision=latest["revision"],
                    current_revision=release["revision"],
                )
            )
            repairs.append(_repair("create_checkpoint", True, reason="checkpoint_lag"))
    if release["state"] == "completed" and release["rollback_deadline"]:
        if now_value > parse_time(release["rollback_deadline"]):
            issues.append(
                _issue(
                    "info",
                    "rollback_window_closed",
                    "release completion rollback window has closed",
                    rollback_deadline=release["rollback_deadline"],
                )
            )
    severity = "none"
    if any(item["severity"] == "critical" for item in issues):
        severity = "critical"
    elif any(item["severity"] == "warning" for item in issues):
        severity = "warning"
    elif issues:
        severity = "info"
    next_action = choose_recovery_action(release, issues, repairs)
    result = {
        "release_id": release_id,
        "inspected_at": now,
        "release_state": release["state"],
        "revision": release["revision"],
        "severity": severity,
        "issues": issues,
        "repairs": repairs,
        "next_action": next_action,
        "state_counts": dict(sorted(Counter(item["state"] for item in release["devices"]).items())),
        "integrity": integrity,
        "checkpoint_count": len(checkpoints),
    }
    result["recovery_digest"] = fingerprint(result)
    return result


def choose_recovery_action(
    release: Mapping[str, Any],
    issues: list[Mapping[str, Any]],
    repairs: list[Mapping[str, Any]],
) -> str:
    if any(item["code"] == "integrity_failed" for item in issues):
        return "restore_verified_backup"
    if any(item["severity"] == "critical" for item in issues):
        return "pause_for_manual_reconciliation"
    if any(item["code"] == "pending_receipts" for item in issues):
        return "drain_pending_receipts"
    if any(item["code"] == "stale_device_operations" for item in issues):
        return "request_device_status"
    if release["state"] == "paused":
        return "review_then_resume_or_rollback"
    if release["state"] == "rolling_back":
        return "continue_rollback"
    if release["state"] in {"ready", "running", "observing"}:
        return "continue_release"
    return "no_action"


def verify_checkpoint_recovery(repository: Repository, release_id: str, checkpoint_id: str) -> dict[str, Any]:
    checkpoint = repository.get_checkpoint(release_id, checkpoint_id)
    snapshot = checkpoint["snapshot"]
    expected = fingerprint(snapshot)
    current = repository.get_release(release_id)
    scheduled_ids = {item["device_id"] for item in current["devices"]}
    checkpoint_ids = {item["device_id"] for item in snapshot["devices"]}
    return {
        "valid": expected == checkpoint["snapshot_digest"] and checkpoint_ids <= scheduled_ids,
        "digest_valid": expected == checkpoint["snapshot_digest"],
        "unknown_checkpoint_devices": sorted(checkpoint_ids - scheduled_ids),
        "missing_current_devices": sorted(scheduled_ids - checkpoint_ids),
        "checkpoint_revision": checkpoint["revision"],
        "current_revision": current["revision"],
        "checkpoint_state": snapshot["state"],
        "current_state": current["state"],
        "safe_replay_boundary": checkpoint["revision"] <= current["revision"],
    }


def recovery_summary(result: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "severity": result["severity"],
        "issue_codes": [item["code"] for item in result["issues"]],
        "safe_repairs": [item["action"] for item in result["repairs"] if item["safe"]],
        "unsafe_repairs": [item["action"] for item in result["repairs"] if not item["safe"]],
        "next_action": result["next_action"],
        "recovery_digest": result["recovery_digest"],
    }

