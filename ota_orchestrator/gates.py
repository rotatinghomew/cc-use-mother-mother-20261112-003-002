from __future__ import annotations

from collections import Counter
from typing import Any, Mapping

from .domain import bounded_ratio, fingerprint, round_metric
from .repository import Repository


SEVERITY_ORDER = {"info": 0, "warning": 1, "critical": 2}


def _finding(
    severity: str,
    code: str,
    message: str,
    observed: Any,
    threshold: Any,
    scope: str = "overall",
) -> dict[str, Any]:
    return {
        "severity": severity,
        "code": code,
        "message": message,
        "observed": observed,
        "threshold": threshold,
        "scope": scope,
    }


def operational_snapshot(repository: Repository, release_id: str, wave_id: str) -> dict[str, Any]:
    devices = repository.list_device_states(release_id, wave_id)
    counts = Counter(item["state"] for item in devices)
    attempted = sum(counts[state] for state in counts if state != "scheduled")
    succeeded = counts["installed"]
    failed = counts["failed"]
    rolled_back = counts["rolled_back"]
    rollback_failed = counts["rollback_failed"]
    consecutive_failures = 0
    maximum_consecutive_failures = 0
    for receipt in repository.list_receipts(release_id):
        if receipt["wave_id"] != wave_id or receipt["disposition"] != "applied":
            continue
        if receipt["kind"] == "install_failed":
            consecutive_failures += 1
            maximum_consecutive_failures = max(maximum_consecutive_failures, consecutive_failures)
        elif receipt["kind"] == "install_completed":
            consecutive_failures = 0
    cohort_failures: Counter[str] = Counter(
        item["cohort_key"] for item in devices if item["state"] in {"failed", "rollback_failed"}
    )
    critical_failures = sum(
        1
        for item in devices
        if item["risk_level"] == "critical" and item["state"] in {"failed", "rollback_failed"}
    )
    return {
        "device_count": len(devices),
        "state_counts": dict(sorted(counts.items())),
        "attempted": attempted,
        "succeeded": succeeded,
        "failed": failed,
        "rolled_back": rolled_back,
        "rollback_failed": rollback_failed,
        "success_rate": round_metric(bounded_ratio(succeeded, attempted)),
        "failure_rate": round_metric(bounded_ratio(failed + rollback_failed, attempted)),
        "rollback_rate": round_metric(bounded_ratio(rolled_back + rollback_failed, attempted)),
        "maximum_consecutive_failures": maximum_consecutive_failures,
        "critical_failures": critical_failures,
        "cohort_failures": dict(sorted(cohort_failures.items())),
    }


def evaluate_failure_budget(operational: Mapping[str, Any], budget: Mapping[str, Any]) -> dict[str, Any]:
    failures = operational["failed"] + operational["rollback_failed"]
    findings: list[dict[str, Any]] = []
    if failures > budget["maximum_failed_devices"]:
        findings.append(
            _finding(
                "critical",
                "failed_devices_budget_exhausted",
                "failed device count exceeds the release budget",
                failures,
                budget["maximum_failed_devices"],
            )
        )
    if operational["failure_rate"] > budget["maximum_failed_fraction"]:
        findings.append(
            _finding(
                "critical",
                "failed_fraction_budget_exhausted",
                "failed device fraction exceeds the release budget",
                operational["failure_rate"],
                budget["maximum_failed_fraction"],
            )
        )
    if operational["maximum_consecutive_failures"] > budget["maximum_consecutive_failures"]:
        findings.append(
            _finding(
                "critical",
                "consecutive_failure_budget_exhausted",
                "consecutive failures exceed the release budget",
                operational["maximum_consecutive_failures"],
                budget["maximum_consecutive_failures"],
            )
        )
    if operational["critical_failures"] > budget["critical_cohort_failures"]:
        findings.append(
            _finding(
                "critical",
                "critical_cohort_budget_exhausted",
                "critical cohort failures exceed the release budget",
                operational["critical_failures"],
                budget["critical_cohort_failures"],
            )
        )
    return {
        "exhausted": bool(findings),
        "remaining_failed_devices": budget["maximum_failed_devices"] - failures,
        "remaining_failed_fraction": round_metric(
            budget["maximum_failed_fraction"] - operational["failure_rate"]
        ),
        "findings": findings,
    }


def evaluate_gate(
    repository: Repository,
    release_id: str,
    wave_id: str,
    analysis: Mapping[str, Any],
) -> dict[str, Any]:
    release = repository.get_release(release_id)
    thresholds = release["plan"]["health_thresholds"]
    budget = release["plan"]["failure_budget"]
    operational = operational_snapshot(repository, release_id, wave_id)
    failure_budget = evaluate_failure_budget(operational, budget)
    findings: list[dict[str, Any]] = list(failure_budget["findings"])
    if analysis["current"]["sample_count"] < thresholds["minimum_sample_size"]:
        findings.append(
            _finding(
                "warning",
                "sample_size_insufficient",
                "health sample size is below the decision threshold",
                analysis["current"]["sample_count"],
                thresholds["minimum_sample_size"],
            )
        )
    if analysis["metric_coverage"] < thresholds["minimum_metric_coverage"]:
        findings.append(
            _finding(
                "warning",
                "metric_coverage_insufficient",
                "health metric coverage is below the decision threshold",
                analysis["metric_coverage"],
                thresholds["minimum_metric_coverage"],
            )
        )
    if operational["attempted"] and operational["success_rate"] < thresholds["minimum_success_rate"]:
        findings.append(
            _finding(
                "critical",
                "success_rate_below_threshold",
                "upgrade success rate is below the release threshold",
                operational["success_rate"],
                thresholds["minimum_success_rate"],
            )
        )
    if operational["failure_rate"] > thresholds["maximum_failure_rate"]:
        findings.append(
            _finding(
                "critical",
                "failure_rate_above_threshold",
                "upgrade failure rate exceeds the release threshold",
                operational["failure_rate"],
                thresholds["maximum_failure_rate"],
            )
        )
    if operational["rollback_rate"] > thresholds["maximum_rollback_rate"]:
        findings.append(
            _finding(
                "critical",
                "rollback_rate_above_threshold",
                "rollback rate exceeds the release threshold",
                operational["rollback_rate"],
                thresholds["maximum_rollback_rate"],
            )
        )
    overall = analysis["overall"]
    if overall["error_rate_delta"] > thresholds["maximum_error_rate_delta"]:
        findings.append(
            _finding(
                "critical",
                "error_rate_regression",
                "error rate regression exceeds the release threshold",
                overall["error_rate_delta"],
                thresholds["maximum_error_rate_delta"],
            )
        )
    if overall["latency_p95_delta_ms"] > thresholds["maximum_p95_latency_delta_ms"]:
        findings.append(
            _finding(
                "critical",
                "latency_regression",
                "p95 latency regression exceeds the release threshold",
                overall["latency_p95_delta_ms"],
                thresholds["maximum_p95_latency_delta_ms"],
            )
        )
    if overall["availability"] < thresholds["minimum_availability"]:
        findings.append(
            _finding(
                "critical",
                "availability_below_threshold",
                "availability is below the release threshold",
                overall["availability"],
                thresholds["minimum_availability"],
            )
        )
    if overall["privilege_denial_delta"] > thresholds["maximum_privilege_denial_delta"]:
        findings.append(
            _finding(
                "critical",
                "privilege_denial_regression",
                "privilege denial regression exceeds the release threshold",
                overall["privilege_denial_delta"],
                thresholds["maximum_privilege_denial_delta"],
            )
        )
    for cohort_key, cohort in analysis["by_cohort"].items():
        if cohort["sample_count"] == 0:
            findings.append(
                _finding(
                    "warning",
                    "cohort_metrics_missing",
                    "a scheduled cohort has no health metrics",
                    0,
                    1,
                    cohort_key,
                )
            )
        if cohort["error_rate_delta"] > thresholds["maximum_error_rate_delta"]:
            findings.append(
                _finding(
                    "critical",
                    "cohort_error_regression",
                    "cohort error rate regression exceeds the release threshold",
                    cohort["error_rate_delta"],
                    thresholds["maximum_error_rate_delta"],
                    cohort_key,
                )
            )
    critical = [item for item in findings if item["severity"] == "critical"]
    warnings = [item for item in findings if item["severity"] == "warning"]
    if critical:
        action = "rollback" if failure_budget["exhausted"] or len(critical) >= 2 else "pause"
    elif warnings:
        action = "pause"
    else:
        action = "continue"
    decision = {
        "release_id": release_id,
        "wave_id": wave_id,
        "action": action,
        "findings": sorted(findings, key=lambda item: (-SEVERITY_ORDER[item["severity"]], item["scope"], item["code"])),
        "operational": operational,
        "failure_budget": failure_budget,
        "analysis_digest": analysis["analysis_digest"],
        "thresholds": thresholds,
    }
    decision["decision_digest"] = fingerprint(decision)
    return decision


def decision_summary(decision: Mapping[str, Any]) -> dict[str, Any]:
    severities = Counter(item["severity"] for item in decision["findings"])
    return {
        "action": decision["action"],
        "finding_count": len(decision["findings"]),
        "severities": dict(sorted(severities.items())),
        "failure_budget_exhausted": decision["failure_budget"]["exhausted"],
        "decision_digest": decision["decision_digest"],
    }

