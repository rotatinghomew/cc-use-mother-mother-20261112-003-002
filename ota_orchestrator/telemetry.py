from __future__ import annotations

from collections import defaultdict
from typing import Any, Iterable, Mapping

from .domain import (
    bounded_ratio,
    fingerprint,
    mean,
    parse_time,
    percentile,
    require_identifier,
    require_int,
    require_mapping,
    require_number,
    require_string,
    round_metric,
)
from .errors import DomainError
from .repository import Repository


METRIC_FIELDS = (
    "request_count",
    "error_count",
    "privilege_denial_count",
    "availability_success_count",
    "latency_p50_ms",
    "latency_p95_ms",
    "latency_p99_ms",
)


def validate_metric(value: Any) -> dict[str, Any]:
    source = require_mapping(value, "metric")
    sample_count = require_int(source.get("sample_count"), "metric.sample_count", minimum=1)
    request_count = require_int(source.get("request_count"), "metric.request_count", minimum=0)
    error_count = require_int(source.get("error_count"), "metric.error_count", minimum=0)
    denial_count = require_int(
        source.get("privilege_denial_count"), "metric.privilege_denial_count", minimum=0
    )
    availability_success = require_int(
        source.get("availability_success_count"), "metric.availability_success_count", minimum=0
    )
    if error_count > request_count:
        raise DomainError("invalid_metric_counts", "error count cannot exceed request count")
    if denial_count > request_count:
        raise DomainError("invalid_metric_counts", "privilege denial count cannot exceed request count")
    if availability_success > sample_count:
        raise DomainError("invalid_metric_counts", "availability success count cannot exceed sample count")
    p50 = require_number(source.get("latency_p50_ms"), "metric.latency_p50_ms", minimum=0.0)
    p95 = require_number(source.get("latency_p95_ms"), "metric.latency_p95_ms", minimum=0.0)
    p99 = require_number(source.get("latency_p99_ms"), "metric.latency_p99_ms", minimum=0.0)
    if not p50 <= p95 <= p99:
        raise DomainError("invalid_latency_quantiles", "latency quantiles must be nondecreasing")
    wave_id = source.get("wave_id")
    if wave_id is not None:
        wave_id = require_identifier(wave_id, "metric.wave_id")
    return {
        "metric_id": require_identifier(source.get("metric_id"), "metric.metric_id"),
        "wave_id": wave_id,
        "cohort_key": require_string(source.get("cohort_key"), "metric.cohort_key", maximum=512),
        "observed_at": parse_time(source.get("observed_at"), "metric.observed_at").isoformat(),
        "sample_count": sample_count,
        "request_count": request_count,
        "error_count": error_count,
        "privilege_denial_count": denial_count,
        "availability_success_count": availability_success,
        "latency_p50_ms": p50,
        "latency_p95_ms": p95,
        "latency_p99_ms": p99,
    }


def ingest_metric(repository: Repository, release_id: str, value: Any) -> dict[str, Any]:
    metric = validate_metric(value)
    release = repository.get_release(release_id)
    if metric["wave_id"] is not None:
        wave_ids = {wave["wave_id"] for wave in release["schedule"]["waves"]}
        if metric["wave_id"] not in wave_ids:
            raise DomainError("unknown_metric_wave", "metric references an unknown wave")
    known_cohorts = set(release["snapshot"]["cohort_counts"])
    if metric["cohort_key"] not in known_cohorts:
        raise DomainError("unknown_metric_cohort", "metric references an unknown cohort")
    with repository.transaction():
        status = repository.insert_metric(release_id, metric)
        repository.append_audit(
            release_id,
            {
                "event_id": f"metric:{metric['metric_id']}",
                "event_type": "metric_ingested",
                "occurred_at": metric["observed_at"],
                "actor": "telemetry-collector",
                "details": {
                    "metric_id": metric["metric_id"],
                    "wave_id": metric["wave_id"],
                    "cohort_key": metric["cohort_key"],
                    "sample_count": metric["sample_count"],
                },
            },
        )
    return {"status": status, "metric": metric}


def _aggregate_metrics(values: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    metrics = list(values)
    sample_count = sum(item["sample_count"] for item in metrics)
    request_count = sum(item["request_count"] for item in metrics)
    error_count = sum(item["error_count"] for item in metrics)
    denial_count = sum(item["privilege_denial_count"] for item in metrics)
    availability_success = sum(item["availability_success_count"] for item in metrics)
    latency_weights = [max(1, item["request_count"]) for item in metrics]

    def weighted(field: str) -> float:
        denominator = sum(latency_weights)
        if denominator == 0:
            return 0.0
        return sum(item[field] * weight for item, weight in zip(metrics, latency_weights)) / denominator

    return {
        "metric_count": len(metrics),
        "sample_count": sample_count,
        "request_count": request_count,
        "error_count": error_count,
        "privilege_denial_count": denial_count,
        "availability_success_count": availability_success,
        "error_rate": round_metric(bounded_ratio(error_count, request_count)),
        "privilege_denial_rate": round_metric(bounded_ratio(denial_count, request_count)),
        "availability": round_metric(bounded_ratio(availability_success, sample_count)),
        "latency_p50_ms": round_metric(weighted("latency_p50_ms")),
        "latency_p95_ms": round_metric(weighted("latency_p95_ms")),
        "latency_p99_ms": round_metric(weighted("latency_p99_ms")),
        "first_observed_at": min((item["observed_at"] for item in metrics), default=None),
        "last_observed_at": max((item["observed_at"] for item in metrics), default=None),
    }


def aggregate_by_cohort(metrics: Iterable[Mapping[str, Any]]) -> dict[str, dict[str, Any]]:
    grouped: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
    for metric in metrics:
        grouped[metric["cohort_key"]].append(metric)
    return {key: _aggregate_metrics(values) for key, values in sorted(grouped.items())}


def freeze_baseline(repository: Repository, release_id: str) -> dict[str, Any]:
    metrics = repository.list_metrics(release_id, None)
    if not metrics:
        raise DomainError("baseline_missing", "baseline metrics are required before starting rollout")
    aggregate = _aggregate_metrics(metrics)
    by_cohort = aggregate_by_cohort(metrics)
    release = repository.get_release(release_id)
    missing_cohorts = sorted(set(release["snapshot"]["cohort_counts"]) - set(by_cohort))
    baseline = {
        "release_id": release_id,
        "metric_ids": [item["metric_id"] for item in metrics],
        "aggregate": aggregate,
        "by_cohort": by_cohort,
        "missing_cohorts": missing_cohorts,
    }
    baseline["baseline_digest"] = fingerprint(baseline)
    return baseline


def compare_wave(
    repository: Repository,
    release_id: str,
    wave_id: str,
    baseline: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    baseline = dict(baseline or freeze_baseline(repository, release_id))
    current_metrics = repository.list_metrics(release_id, wave_id)
    current = _aggregate_metrics(current_metrics)
    current_by_cohort = aggregate_by_cohort(current_metrics)
    release = repository.get_release(release_id)
    wave_devices = repository.list_device_states(release_id, wave_id)
    expected_cohorts = sorted({item["cohort_key"] for item in wave_devices})
    comparisons: dict[str, dict[str, Any]] = {}
    for cohort_key in sorted(set(expected_cohorts) | set(current_by_cohort)):
        base = baseline["by_cohort"].get(cohort_key, _aggregate_metrics([]))
        observed = current_by_cohort.get(cohort_key, _aggregate_metrics([]))
        comparisons[cohort_key] = compare_aggregate(base, observed)
    expected_devices = len(wave_devices)
    observed_samples = current["sample_count"]
    cohort_coverage = bounded_ratio(len(current_by_cohort), len(expected_cohorts))
    sample_coverage = bounded_ratio(observed_samples, expected_devices)
    result = {
        "release_id": release_id,
        "wave_id": wave_id,
        "baseline_digest": baseline["baseline_digest"],
        "baseline": baseline["aggregate"],
        "current": current,
        "overall": compare_aggregate(baseline["aggregate"], current),
        "by_cohort": comparisons,
        "expected_cohorts": expected_cohorts,
        "observed_cohorts": sorted(current_by_cohort),
        "missing_cohorts": sorted(set(expected_cohorts) - set(current_by_cohort)),
        "expected_device_count": expected_devices,
        "observed_sample_count": observed_samples,
        "sample_coverage": round_metric(sample_coverage),
        "cohort_coverage": round_metric(cohort_coverage),
        "metric_coverage": round_metric(min(sample_coverage, cohort_coverage)),
        "metric_ids": [item["metric_id"] for item in current_metrics],
        "release_state": release["state"],
    }
    result["analysis_digest"] = fingerprint(result)
    return result


def compare_aggregate(baseline: Mapping[str, Any], current: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "sample_count": current["sample_count"],
        "sample_delta": current["sample_count"] - baseline["sample_count"],
        "error_rate": current["error_rate"],
        "error_rate_delta": round_metric(current["error_rate"] - baseline["error_rate"]),
        "privilege_denial_rate": current["privilege_denial_rate"],
        "privilege_denial_delta": round_metric(
            current["privilege_denial_rate"] - baseline["privilege_denial_rate"]
        ),
        "availability": current["availability"],
        "availability_delta": round_metric(current["availability"] - baseline["availability"]),
        "latency_p50_ms": current["latency_p50_ms"],
        "latency_p50_delta_ms": round_metric(current["latency_p50_ms"] - baseline["latency_p50_ms"]),
        "latency_p95_ms": current["latency_p95_ms"],
        "latency_p95_delta_ms": round_metric(current["latency_p95_ms"] - baseline["latency_p95_ms"]),
        "latency_p99_ms": current["latency_p99_ms"],
        "latency_p99_delta_ms": round_metric(current["latency_p99_ms"] - baseline["latency_p99_ms"]),
    }


def metric_distribution(metrics: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    values = list(metrics)
    p95_values = [item["latency_p95_ms"] for item in values]
    error_rates = [bounded_ratio(item["error_count"], item["request_count"]) for item in values]
    return {
        "count": len(values),
        "p95_latency": {
            "minimum": min(p95_values, default=0.0),
            "mean": round_metric(mean(p95_values)),
            "median": round_metric(percentile(p95_values, 0.5)),
            "maximum": max(p95_values, default=0.0),
        },
        "error_rate": {
            "minimum": min(error_rates, default=0.0),
            "mean": round_metric(mean(error_rates)),
            "median": round_metric(percentile(error_rates, 0.5)),
            "maximum": max(error_rates, default=0.0),
        },
    }


def telemetry_summary(repository: Repository, release_id: str) -> dict[str, Any]:
    all_metrics = repository.list_metrics(release_id, "*")
    grouped: dict[str, int] = defaultdict(int)
    for metric in all_metrics:
        grouped[metric["wave_id"] or "baseline"] += 1
    return {
        "metric_count": len(all_metrics),
        "metrics_by_scope": dict(sorted(grouped.items())),
        "cohort_count": len({item["cohort_key"] for item in all_metrics}),
        "distribution": metric_distribution(all_metrics),
    }
