from __future__ import annotations

import copy
import json
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

from ota_orchestrator.domain import add_seconds, fingerprint
from ota_orchestrator.service import OtaOrchestrator, hydrate_scenario, load_json, make_receipt


PROJECT_ROOT = Path(__file__).resolve().parents[1]
FIXTURE_PATH = PROJECT_ROOT / "fixtures" / "acceptance.json"


def fixture() -> dict[str, Any]:
    return load_json(FIXTURE_PATH)


def cloned_fixture() -> dict[str, Any]:
    return copy.deepcopy(fixture())


def hydrated_fixture() -> dict[str, Any]:
    return hydrate_scenario(cloned_fixture())


@contextmanager
def temporary_application() -> Iterator[tuple[OtaOrchestrator, Path]]:
    with tempfile.TemporaryDirectory(prefix="ota-tests-") as directory:
        database = Path(directory) / "state.sqlite3"
        application = OtaOrchestrator(database)
        try:
            yield application, database
        finally:
            application.close()


def prepare_application(
    value: dict[str, Any] | None = None,
) -> tuple[tempfile.TemporaryDirectory[str], OtaOrchestrator, dict[str, Any]]:
    directory = tempfile.TemporaryDirectory(prefix="ota-tests-")
    database = Path(directory.name) / "state.sqlite3"
    application = OtaOrchestrator(database)
    release = application.prepare_release(value or cloned_fixture())
    return directory, application, release


def close_prepared(directory: tempfile.TemporaryDirectory[str], application: OtaOrchestrator) -> None:
    application.close()
    directory.cleanup()


def successful_metric(
    metric_id: str,
    cohort_key: str,
    wave_id: str | None,
    observed_at: str,
    *,
    sample_count: int = 20,
    error_count: int = 5,
    request_count: int = 1000,
    availability_success_count: int | None = None,
    latency_p95_ms: float = 110.0,
    privilege_denial_count: int = 1,
) -> dict[str, Any]:
    if availability_success_count is None:
        availability_success_count = sample_count
    return {
        "metric_id": metric_id,
        "wave_id": wave_id,
        "cohort_key": cohort_key,
        "observed_at": observed_at,
        "sample_count": sample_count,
        "request_count": request_count,
        "error_count": error_count,
        "privilege_denial_count": privilege_denial_count,
        "availability_success_count": availability_success_count,
        "latency_p50_ms": latency_p95_ms - 40,
        "latency_p95_ms": latency_p95_ms,
        "latency_p99_ms": latency_p95_ms + 40,
    }


def receipt(
    release: dict[str, Any],
    wave_id: str,
    device_id: str,
    kind: str,
    sequence: int,
    occurred_at: str,
) -> dict[str, Any]:
    return make_receipt(release, wave_id, device_id, kind, sequence, occurred_at)


def complete_device(
    application: OtaOrchestrator,
    release: dict[str, Any],
    wave_id: str,
    device_id: str,
    start_sequence: int,
    clock: str,
    *,
    fail: bool = False,
) -> tuple[int, str, list[dict[str, Any]]]:
    from ota_orchestrator.receipts import process_receipt

    results: list[dict[str, Any]] = []
    sequence = start_sequence
    for kind in ("download_started", "install_started"):
        sequence += 1
        clock = add_seconds(clock, 1)
        results.append(
            process_receipt(application.repository, receipt(release, wave_id, device_id, kind, sequence, clock))
        )
    sequence += 1
    clock = add_seconds(clock, 1)
    results.append(
        process_receipt(
            application.repository,
            receipt(release, wave_id, device_id, "install_failed" if fail else "install_completed", sequence, clock),
        )
    )
    return sequence, clock, results


def complete_wave_devices(
    application: OtaOrchestrator,
    release: dict[str, Any],
    wave_id: str,
    clock: str,
    *,
    failed_ids: set[str] | None = None,
) -> tuple[int, str]:
    failed_ids = failed_ids or set()
    wave = next(item for item in release["schedule"]["waves"] if item["wave_id"] == wave_id)
    sequence = 0
    for assignment in wave["assignments"]:
        sequence, clock, _ = complete_device(
            application,
            release,
            wave_id,
            assignment["device_id"],
            sequence,
            clock,
            fail=assignment["device_id"] in failed_ids,
        )
    return sequence, clock


def minimal_plan_scope(value: dict[str, Any]) -> dict[str, Any]:
    plan = value["plan"]
    return {
        "identity": plan["identity"],
        "versioning": plan["versioning"],
        "capabilities": plan["capabilities"],
        "third_party_declarations": plan["third_party_declarations"],
        "dependencies": plan.get("dependencies", []),
    }


def refresh_approval(value: dict[str, Any]) -> None:
    hydrated = hydrate_scenario(value)
    value.clear()
    value.update(hydrated)


def dump_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2)


def tamper_digest(value: str) -> str:
    replacement = "0" if value[0] != "0" else "1"
    return replacement + value[1:]


def signed_digest(label: str) -> str:
    return fingerprint({"test-signature": label})

