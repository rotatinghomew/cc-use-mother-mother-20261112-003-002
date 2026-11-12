from __future__ import annotations

from collections import Counter
from typing import Any, Mapping

from .domain import fingerprint, parse_time
from .gates import operational_snapshot
from .receipts import receipt_summary
from .repository import Repository
from .state_machine import lifecycle_summary
from .telemetry import telemetry_summary


def _wave_report(repository: Repository, release: Mapping[str, Any], wave: Mapping[str, Any]) -> dict[str, Any]:
    state = next(item for item in release["waves"] if item["wave_id"] == wave["wave_id"])
    operational = operational_snapshot(repository, release["release_id"], wave["wave_id"])
    receipts = receipt_summary(repository, release["release_id"], wave["wave_id"])
    metrics = repository.list_metrics(release["release_id"], wave["wave_id"])
    return {
        "wave_id": wave["wave_id"],
        "sequence": wave["sequence"],
        "name": wave["name"],
        "state": state["state"],
        "started_at": state["started_at"],
        "observation_started_at": state["observation_started_at"],
        "completed_at": state["completed_at"],
        "decision": state["decision"],
        "decision_details": state["decision_details"],
        "checkpoint_id": state["checkpoint_id"],
        "scheduled_devices": wave["incremental_count"],
        "operational": operational,
        "receipts": receipts,
        "metric_ids": [item["metric_id"] for item in metrics],
        "wave_digest": wave["wave_digest"],
    }


def _failure_summary(release: Mapping[str, Any]) -> dict[str, Any]:
    failed = [item for item in release["devices"] if item["state"] in {"failed", "rollback_failed"}]
    by_code = Counter(item["failure_code"] or "unspecified" for item in failed)
    by_cohort = Counter(item["cohort_key"] for item in failed)
    return {
        "failed_device_count": len(failed),
        "failure_codes": dict(sorted(by_code.items())),
        "failed_by_cohort": dict(sorted(by_cohort.items())),
        "failed_device_ids": [item["device_id"] for item in failed],
    }


def _third_party_summary(plan: Mapping[str, Any]) -> list[dict[str, Any]]:
    return [
        {
            "application_id": item["application_id"],
            "consent": item["consent"],
            "declared_at": item["declared_at"],
            "expires_at": item["expires_at"],
            "allowed_capabilities": item["allowed_capabilities"],
            "signature_algorithm": item["signature_algorithm"],
            "signature_digest": item["signature_digest"],
        }
        for item in plan["third_party_declarations"]
    ]


def build_completion_report(
    repository: Repository,
    release_id: str,
    generated_at: str,
    report_id: str,
) -> dict[str, Any]:
    parse_time(generated_at, "generated_at")
    release = repository.get_release(release_id)
    integrity = repository.integrity_check(release_id)
    audit = repository.list_audit(release_id)
    waves = [_wave_report(repository, release, wave) for wave in release["schedule"]["waves"]]
    state_counts = Counter(item["state"] for item in release["devices"])
    terminal = release["state"] in {"completed", "rolled_back", "failed"}
    assessment = "passed"
    if release["state"] == "failed" or not integrity["valid"]:
        assessment = "failed"
    elif release["state"] == "rolled_back":
        assessment = "rolled_back"
    elif not terminal:
        assessment = "in_progress"
    report = {
        "report_id": report_id,
        "generated_at": generated_at,
        "release_id": release_id,
        "assessment": assessment,
        "release": lifecycle_summary(repository, release_id),
        "plan": {
            "plan_id": release["plan"]["plan_id"],
            "title": release["plan"]["title"],
            "identity_code": release["plan"]["identity"]["identity_code"],
            "current_version": release["plan"]["versioning"]["current"],
            "target_version": release["plan"]["versioning"]["target"],
            "approval": release["plan"]["approval"],
            "capabilities": release["plan"]["capabilities"],
            "dependencies": release["plan"]["dependencies"],
            "failure_budget": release["plan"]["failure_budget"],
            "health_thresholds": release["plan"]["health_thresholds"],
            "plan_fingerprint": release["plan"]["plan_fingerprint"],
        },
        "artifact": {
            "artifact_id": release["artifact"]["artifact_id"],
            "version": release["artifact"]["version"],
            "artifact_digest": release["artifact"]["artifact_digest"],
            "manifest_digest": release["artifact"]["manifest_digest"],
            "artifact_fingerprint": release["artifact"]["artifact_fingerprint"],
            "total_size": release["artifact"]["total_size"],
            "signing": release["artifact"]["signing"],
        },
        "eligibility": {
            "snapshot_at": release["snapshot"]["snapshot_at"],
            "eligible_count": release["snapshot"]["eligible_count"],
            "held_count": release["snapshot"]["held_count"],
            "cohort_counts": release["snapshot"]["cohort_counts"],
            "hold_reason_counts": release["snapshot"]["hold_reason_counts"],
            "snapshot_digest": release["snapshot"]["snapshot_digest"],
        },
        "schedule": {
            "wave_count": len(release["schedule"]["waves"]),
            "eligible_count": release["schedule"]["eligible_count"],
            "schedule_digest": release["schedule"]["schedule_digest"],
            "dependency_graph_digest": release["schedule"]["dependency_graph_digest"],
        },
        "waves": waves,
        "device_outcome_counts": dict(sorted(state_counts.items())),
        "failures": _failure_summary(release),
        "receipts": receipt_summary(repository, release_id),
        "telemetry": telemetry_summary(repository, release_id),
        "third_party_declarations": _third_party_summary(release["plan"]),
        "checkpoints": repository.list_checkpoints(release_id),
        "audit": {
            "event_count": len(audit),
            "head_hash": integrity["audit"]["head_hash"],
            "event_types": dict(sorted(Counter(item["event"]["event_type"] for item in audit).items())),
            "events": [item["event"] for item in audit],
        },
        "integrity": integrity,
    }
    report["report_digest"] = fingerprint(report)
    return report


def verify_completion_report(
    report: Mapping[str, Any],
    repository: Repository,
    release_id: str,
) -> dict[str, Any]:
    material = {key: value for key, value in report.items() if key != "report_digest"}
    expected = fingerprint(material)
    release = repository.get_release(release_id)
    current_integrity = repository.integrity_check(release_id)
    issues: list[str] = []
    if expected != report.get("report_digest"):
        issues.append("report_digest_mismatch")
    if report.get("release_id") != release_id:
        issues.append("release_id_mismatch")
    if report["plan"]["plan_fingerprint"] != release["plan"]["plan_fingerprint"]:
        issues.append("plan_fingerprint_mismatch")
    if report["artifact"]["artifact_fingerprint"] != release["artifact"]["artifact_fingerprint"]:
        issues.append("artifact_fingerprint_mismatch")
    if report["eligibility"]["snapshot_digest"] != release["snapshot"]["snapshot_digest"]:
        issues.append("snapshot_digest_mismatch")
    if report["schedule"]["schedule_digest"] != release["schedule"]["schedule_digest"]:
        issues.append("schedule_digest_mismatch")
    if report["audit"]["head_hash"] != current_integrity["audit"]["head_hash"]:
        issues.append("audit_head_mismatch")
    return {
        "valid": not issues and current_integrity["valid"],
        "issues": issues,
        "expected_report_digest": expected,
        "actual_report_digest": report.get("report_digest"),
        "repository_integrity": current_integrity,
    }


def report_summary(report: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "report_id": report["report_id"],
        "assessment": report["assessment"],
        "release_state": report["release"]["state"],
        "eligible_devices": report["eligibility"]["eligible_count"],
        "wave_count": report["schedule"]["wave_count"],
        "failed_devices": report["failures"]["failed_device_count"],
        "receipt_count": report["receipts"]["receipt_count"],
        "audit_event_count": report["audit"]["event_count"],
        "integrity_valid": report["integrity"]["valid"],
        "report_digest": report["report_digest"],
    }

