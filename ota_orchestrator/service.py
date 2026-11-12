from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping

from .contracts import (
    validate_artifact,
    validate_capability,
    validate_dependency,
    validate_identity,
    validate_plan,
    validate_third_party,
    validate_versioning,
)
from .dependency_graph import build_dependency_graph
from .domain import add_seconds, fingerprint, parse_time
from .eligibility import build_eligibility_snapshot
from .receipts import process_receipt
from .recovery import inspect_recovery
from .reporting import build_completion_report, verify_completion_report
from .repository import Repository
from .scheduler import schedule_waves, verify_schedule
from .state_machine import (
    begin_observation,
    create_release_record,
    evaluate_active_wave,
    finalize_rollback,
    mark_ready,
    request_rollback,
    start_wave,
)
from .telemetry import ingest_metric


class OtaOrchestrator:
    def __init__(self, database_path: str | Path) -> None:
        self.repository = Repository(database_path)

    def close(self) -> None:
        self.repository.close()

    def __enter__(self) -> "OtaOrchestrator":
        return self

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        self.close()

    def prepare_release(self, scenario: Mapping[str, Any]) -> dict[str, Any]:
        prepared = hydrate_scenario(scenario)
        plan = validate_plan(prepared["plan"])
        artifact = validate_artifact(prepared["artifact"], plan)
        snapshot = build_eligibility_snapshot(
            prepared["devices"],
            plan,
            prepared["snapshot_at"],
            dimensions=tuple(prepared.get("cohort_dimensions", ("hardware_model", "region", "risk_level"))),
            maximum_staleness_hours=int(prepared.get("maximum_staleness_hours", 72)),
        )
        dependency_graph = build_dependency_graph(plan)
        schedule = schedule_waves(snapshot, plan, dependency_graph)
        schedule_verification = verify_schedule(schedule)
        if not schedule_verification["valid"]:
            raise ValueError(f"invalid generated schedule: {schedule_verification}")
        release_id = scenario.get("release_id") or f"release-{plan['plan_id']}"
        created_at = prepared["created_at"]
        record = create_release_record(
            release_id,
            plan,
            artifact,
            snapshot,
            dependency_graph,
            schedule,
            created_at,
        )
        self.repository.create_release(record)
        with self.repository.transaction():
            self.repository.append_audit(
                release_id,
                {
                    "event_id": f"release:{release_id}:created",
                    "event_type": "release_created",
                    "occurred_at": created_at,
                    "actor": "ota-orchestrator",
                    "details": {
                        "plan_id": plan["plan_id"],
                        "plan_fingerprint": plan["plan_fingerprint"],
                        "artifact_fingerprint": artifact["artifact_fingerprint"],
                        "snapshot_digest": snapshot["snapshot_digest"],
                        "schedule_digest": schedule["schedule_digest"],
                    },
                },
            )
        for metric in prepared.get("baseline_metrics", []):
            ingest_metric(self.repository, release_id, metric)
        return self.repository.get_release(release_id)

    def run_fixture(self, scenario: Mapping[str, Any]) -> dict[str, Any]:
        prepared = hydrate_scenario(scenario)
        release = self.prepare_release(prepared)
        release_id = release["release_id"]
        clock = prepared["created_at"]
        clock = add_seconds(clock, 60)
        mark_ready(self.repository, release_id, clock)
        receipt_index = 0
        metric_templates = prepared.get("wave_metric_templates", {})
        failure_devices = set(prepared.get("failure_devices", []))
        rollback_requested = False
        for wave in release["schedule"]["waves"]:
            clock = add_seconds(clock, 60)
            start_wave(self.repository, release_id, wave["wave_id"], clock)
            for assignment in wave["assignments"]:
                device_id = assignment["device_id"]
                for kind in ("download_started", "install_started"):
                    receipt_index += 1
                    clock = add_seconds(clock, 1)
                    process_receipt(
                        self.repository,
                        make_receipt(release, wave["wave_id"], device_id, kind, receipt_index, clock),
                    )
                receipt_index += 1
                clock = add_seconds(clock, 1)
                terminal = "install_failed" if device_id in failure_devices else "install_completed"
                process_receipt(
                    self.repository,
                    make_receipt(release, wave["wave_id"], device_id, terminal, receipt_index, clock),
                )
            clock = add_seconds(clock, 30)
            begin_observation(self.repository, release_id, wave["wave_id"], clock)
            templates = metric_templates.get(wave["wave_id"], prepared.get("default_wave_metrics", []))
            for metric_index, template in enumerate(templates):
                metric = dict(template)
                metric.setdefault("metric_id", f"metric-{wave['wave_id']}-{metric_index + 1:03d}")
                metric["wave_id"] = wave["wave_id"]
                metric.setdefault("observed_at", add_seconds(clock, 30 + metric_index))
                ingest_metric(self.repository, release_id, metric)
            clock = add_seconds(clock, wave["minimum_observation_minutes"] * 60 + 1)
            result = evaluate_active_wave(self.repository, release_id, clock)
            action = result["decision"]["action"]
            if action == "rollback":
                rollback_requested = True
                break
            if action == "pause":
                break
        current = self.repository.get_release(release_id)
        if rollback_requested or current["state"] == "rolling_back":
            receipt_index, clock = self._simulate_rollback(release_id, receipt_index, clock)
            finalize_rollback(self.repository, release_id, add_seconds(clock, 1))
        generated_at = prepared.get("report_generated_at", add_seconds(clock, 10))
        report_id = prepared.get("report_id", f"report-{release_id}")
        report = build_completion_report(self.repository, release_id, generated_at, report_id)
        verification = verify_completion_report(report, self.repository, release_id)
        recovery = inspect_recovery(self.repository, release_id, generated_at)
        return {
            "release": self.repository.get_release(release_id),
            "report": report,
            "report_verification": verification,
            "recovery": recovery,
        }

    def _simulate_rollback(self, release_id: str, receipt_index: int, clock: str) -> tuple[int, str]:
        release = self.repository.get_release(release_id)
        if release["state"] != "rolling_back":
            request_rollback(self.repository, release_id, add_seconds(clock, 1), "fixture_rollback")
        release = self.repository.get_release(release_id)
        for device in release["devices"]:
            if device["state"] not in {"installed", "failed"}:
                continue
            wave_id = device["wave_id"]
            receipt_index += 1
            clock = add_seconds(clock, 1)
            process_receipt(
                self.repository,
                make_receipt(release, wave_id, device["device_id"], "rollback_started", receipt_index, clock),
            )
            receipt_index += 1
            clock = add_seconds(clock, 1)
            process_receipt(
                self.repository,
                make_receipt(release, wave_id, device["device_id"], "rollback_completed", receipt_index, clock),
            )
        return receipt_index, clock


def make_receipt(
    release: Mapping[str, Any],
    wave_id: str,
    device_id: str,
    kind: str,
    sequence: int,
    occurred_at: str,
) -> dict[str, Any]:
    payload: dict[str, Any] = {}
    if kind == "install_completed":
        payload["installed_version"] = release["plan"]["versioning"]["target"]
    elif kind == "install_failed":
        payload["failure_code"] = "synthetic_install_failure"
    elif kind == "rollback_completed":
        payload["rollback_version"] = release["plan"]["versioning"]["current"]
    elif kind == "rollback_failed":
        payload["failure_code"] = "synthetic_rollback_failure"
    receipt_id = f"receipt-{sequence:06d}-{device_id}-{kind}"
    return {
        "receipt_id": receipt_id,
        "release_id": release["release_id"],
        "device_id": device_id,
        "wave_id": wave_id,
        "kind": kind,
        "sequence": sequence,
        "occurred_at": occurred_at,
        "received_at": add_seconds(occurred_at, 1),
        "payload": payload,
        "signature_digest": fingerprint(
            {"receipt_id": receipt_id, "device_id": device_id, "kind": kind, "payload": payload}
        ),
    }


def hydrate_scenario(value: Mapping[str, Any]) -> dict[str, Any]:
    result = json.loads(json.dumps(value, ensure_ascii=False))
    plan = result["plan"]
    artifact = result["artifact"]
    if artifact.get("artifact_digest") in {None, "$AUTO"}:
        artifact["artifact_digest"] = fingerprint({"files": artifact["files"], "kind": "artifact"})
    if artifact.get("manifest_digest") in {None, "$AUTO"}:
        artifact["manifest_digest"] = fingerprint({"files": artifact["files"], "kind": "manifest"})
    plan["versioning"]["artifact_digest"] = artifact["artifact_digest"]
    plan["versioning"]["manifest_digest"] = artifact["manifest_digest"]
    plan.setdefault("approval", {})
    if plan["approval"].get("scope_digest") in {None, "$AUTO"}:
        preview = {
            "identity": validate_identity(plan["identity"]),
            "versioning": validate_versioning(plan["versioning"]),
            "capabilities": [
                validate_capability(item, index)
                for index, item in enumerate(plan["capabilities"])
            ],
            "third_party_declarations": [
                validate_third_party(item, index)
                for index, item in enumerate(plan["third_party_declarations"])
            ],
            "dependencies": [
                validate_dependency(item, index)
                for index, item in enumerate(plan.get("dependencies", []))
            ],
        }
        plan["approval"]["scope_digest"] = fingerprint(preview)
    result.setdefault("created_at", result.get("snapshot_at"))
    return result


def load_json(path: str | Path) -> dict[str, Any]:
    with Path(path).open("r", encoding="utf-8") as handle:
        return json.load(handle)


def save_json(path: str | Path, value: Mapping[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("w", encoding="utf-8") as handle:
        json.dump(value, handle, ensure_ascii=False, sort_keys=True, indent=2)
        handle.write("\n")
