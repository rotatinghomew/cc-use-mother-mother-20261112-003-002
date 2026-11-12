from __future__ import annotations

from collections import Counter
from typing import Any, Mapping

from .domain import add_seconds, fingerprint, parse_time
from .errors import DomainError, StateError
from .gates import evaluate_gate
from .repository import Repository
from .telemetry import compare_wave, freeze_baseline


RELEASE_STATES = (
    "planned",
    "ready",
    "running",
    "observing",
    "paused",
    "rolling_back",
    "completed",
    "rolled_back",
    "failed",
)
TERMINAL_STATES = {"completed", "rolled_back", "failed"}


def create_release_record(
    release_id: str,
    plan: Mapping[str, Any],
    artifact: Mapping[str, Any],
    snapshot: Mapping[str, Any],
    dependency_graph: Mapping[str, Any],
    schedule: Mapping[str, Any],
    created_at: str,
) -> dict[str, Any]:
    parse_time(created_at, "created_at")
    record = {
        "release_id": release_id,
        "state": "planned",
        "revision": 1,
        "created_at": created_at,
        "updated_at": created_at,
        "plan": dict(plan),
        "artifact": dict(artifact),
        "snapshot": dict(snapshot),
        "dependency_graph": dict(dependency_graph),
        "schedule": dict(schedule),
        "active_wave_id": None,
        "paused_reason": None,
        "rollback_deadline": None,
        "terminal_at": None,
    }
    record["record_digest"] = _record_digest(record)
    return record


def _record_digest(record: Mapping[str, Any]) -> str:
    return fingerprint(
        {
            key: record.get(key)
            for key in (
                "release_id",
                "state",
                "revision",
                "created_at",
                "updated_at",
                "plan",
                "artifact",
                "snapshot",
                "dependency_graph",
                "schedule",
                "active_wave_id",
                "paused_reason",
                "rollback_deadline",
                "terminal_at",
            )
        }
    )


def _audit_event(
    event_id: str,
    event_type: str,
    occurred_at: str,
    actor: str,
    details: Mapping[str, Any],
) -> dict[str, Any]:
    return {
        "event_id": event_id,
        "event_type": event_type,
        "occurred_at": occurred_at,
        "actor": actor,
        "details": dict(details),
    }


def _mutate_release(
    repository: Repository,
    release: dict[str, Any],
    occurred_at: str,
    *,
    target_state: str | None = None,
    active_wave_id: str | None | object = ...,
    paused_reason: str | None | object = ...,
    rollback_deadline: str | None | object = ...,
    terminal_at: str | None | object = ...,
) -> tuple[int, dict[str, Any]]:
    expected_revision = release["revision"]
    release["revision"] += 1
    release["updated_at"] = occurred_at
    if target_state is not None:
        release["state"] = target_state
    if active_wave_id is not ...:
        release["active_wave_id"] = active_wave_id
    if paused_reason is not ...:
        release["paused_reason"] = paused_reason
    if rollback_deadline is not ...:
        release["rollback_deadline"] = rollback_deadline
    if terminal_at is not ...:
        release["terminal_at"] = terminal_at
    release["record_digest"] = _record_digest(release)
    return expected_revision, release


def mark_ready(repository: Repository, release_id: str, occurred_at: str, actor: str = "release-controller") -> dict[str, Any]:
    release = repository.get_release(release_id)
    if release["state"] == "ready":
        return release
    if release["state"] != "planned":
        raise StateError("invalid_ready_transition", "only a planned release can become ready")
    baseline = freeze_baseline(repository, release_id)
    expected_revision, release = _mutate_release(repository, release, occurred_at, target_state="ready")
    with repository.transaction():
        repository.update_release(release, expected_revision)
        repository.append_audit(
            release_id,
            _audit_event(
                f"release:{release_id}:ready",
                "release_ready",
                occurred_at,
                actor,
                {"baseline_digest": baseline["baseline_digest"], "eligible_count": release["snapshot"]["eligible_count"]},
            ),
        )
    create_checkpoint(repository, release_id, occurred_at, "release_ready", actor)
    return repository.get_release(release_id)


def _wave_by_id(release: Mapping[str, Any], wave_id: str) -> Mapping[str, Any]:
    for wave in release["schedule"]["waves"]:
        if wave["wave_id"] == wave_id:
            return wave
    raise StateError("wave_not_found", "wave is not part of this release", details={"wave_id": wave_id})


def _wave_state(release: Mapping[str, Any], wave_id: str) -> Mapping[str, Any]:
    for wave in release["waves"]:
        if wave["wave_id"] == wave_id:
            return wave
    raise StateError("wave_not_found", "wave state is not part of this release", details={"wave_id": wave_id})


def _prior_wave(release: Mapping[str, Any], wave: Mapping[str, Any]) -> Mapping[str, Any] | None:
    if wave["depends_on_wave_id"] is None:
        return None
    return _wave_state(release, wave["depends_on_wave_id"])


def start_wave(
    repository: Repository,
    release_id: str,
    wave_id: str,
    occurred_at: str,
    actor: str = "release-controller",
) -> dict[str, Any]:
    release = repository.get_release(release_id)
    if release["state"] not in {"ready", "running"}:
        raise StateError("release_not_startable", "release is not in a state that can start a wave")
    if release["active_wave_id"] is not None:
        raise StateError("active_wave_exists", "another wave is already active")
    wave = _wave_by_id(release, wave_id)
    wave_state = _wave_state(release, wave_id)
    if wave_state["state"] != "pending":
        raise StateError("wave_not_pending", "only a pending wave can be started")
    prior = _prior_wave(release, wave)
    if prior and prior["state"] != "completed":
        raise StateError("wave_dependency_not_met", "prior wave must be completed before starting this wave")
    expected_revision, release = _mutate_release(
        repository,
        release,
        occurred_at,
        target_state="running",
        active_wave_id=wave_id,
        paused_reason=None,
    )
    with repository.transaction():
        repository.update_wave(release_id, wave_id, state="running", started_at=occurred_at)
        repository.update_release(release, expected_revision)
        repository.append_audit(
            release_id,
            _audit_event(
                f"wave:{wave_id}:started",
                "wave_started",
                occurred_at,
                actor,
                {
                    "wave_id": wave_id,
                    "device_count": wave["incremental_count"],
                    "wave_digest": wave["wave_digest"],
                },
            ),
        )
    return repository.get_release(release_id)


def begin_observation(
    repository: Repository,
    release_id: str,
    wave_id: str,
    occurred_at: str,
    actor: str = "release-controller",
) -> dict[str, Any]:
    release = repository.get_release(release_id)
    if release["state"] != "running" or release["active_wave_id"] != wave_id:
        raise StateError("wave_not_running", "requested wave is not the active running wave")
    devices = repository.list_device_states(release_id, wave_id)
    incomplete = [item["device_id"] for item in devices if item["state"] not in {"installed", "failed"}]
    if incomplete:
        raise StateError(
            "wave_devices_incomplete",
            "all device installation attempts must finish before observation",
            details={"incomplete": incomplete},
        )
    expected_revision, release = _mutate_release(repository, release, occurred_at, target_state="observing")
    with repository.transaction():
        repository.update_wave(release_id, wave_id, state="observing", observation_started_at=occurred_at)
        repository.update_release(release, expected_revision)
        repository.append_audit(
            release_id,
            _audit_event(
                f"wave:{wave_id}:observation",
                "wave_observation_started",
                occurred_at,
                actor,
                {"wave_id": wave_id, "device_states": dict(Counter(item["state"] for item in devices))},
            ),
        )
    return repository.get_release(release_id)


def evaluate_active_wave(
    repository: Repository,
    release_id: str,
    occurred_at: str,
    actor: str = "health-gate",
) -> dict[str, Any]:
    release = repository.get_release(release_id)
    if release["state"] != "observing" or not release["active_wave_id"]:
        raise StateError("release_not_observing", "release does not have an active observation window")
    wave_id = release["active_wave_id"]
    wave = _wave_by_id(release, wave_id)
    wave_state = _wave_state(release, wave_id)
    elapsed_minutes = (parse_time(occurred_at) - parse_time(wave_state["observation_started_at"])).total_seconds() / 60
    if elapsed_minutes < wave["minimum_observation_minutes"]:
        raise StateError(
            "observation_window_open",
            "minimum observation window has not elapsed",
            details={"elapsed_minutes": elapsed_minutes, "required_minutes": wave["minimum_observation_minutes"]},
        )
    analysis = compare_wave(repository, release_id, wave_id)
    decision = evaluate_gate(repository, release_id, wave_id, analysis)
    checkpoint = None
    with repository.transaction():
        repository.update_wave(
            release_id,
            wave_id,
            decision=decision["action"],
            decision_json=decision,
        )
        repository.append_audit(
            release_id,
            _audit_event(
                f"wave:{wave_id}:decision:{decision['decision_digest'][:16]}",
                "wave_decision_recorded",
                occurred_at,
                actor,
                {"wave_id": wave_id, "action": decision["action"], "decision_digest": decision["decision_digest"]},
            ),
        )
    if decision["action"] == "continue":
        checkpoint = complete_wave(repository, release_id, wave_id, occurred_at, actor)
    elif decision["action"] == "pause":
        pause_release(repository, release_id, occurred_at, "health_gate_pause", actor)
    else:
        request_rollback(repository, release_id, occurred_at, "health_gate_rollback", actor)
    return {
        "analysis": analysis,
        "decision": decision,
        "checkpoint": checkpoint,
        "release": repository.get_release(release_id),
    }


def complete_wave(
    repository: Repository,
    release_id: str,
    wave_id: str,
    occurred_at: str,
    actor: str = "release-controller",
) -> dict[str, Any]:
    release = repository.get_release(release_id)
    if release["active_wave_id"] != wave_id or release["state"] not in {"observing", "running"}:
        raise StateError("wave_not_active", "only the active wave can be completed")
    wave = _wave_by_id(release, wave_id)
    devices = repository.list_device_states(release_id, wave_id)
    unfinished = [item["device_id"] for item in devices if item["state"] not in {"installed", "failed"}]
    if unfinished:
        raise StateError("wave_devices_incomplete", "wave cannot complete with unfinished devices", details={"unfinished": unfinished})
    next_state = "ready"
    terminal_at: str | None = None
    rollback_deadline: str | None = None
    final_wave = wave["sequence"] == len(release["schedule"]["waves"])
    if final_wave:
        next_state = "completed"
        terminal_at = occurred_at
        rollback_deadline = add_seconds(occurred_at, release["plan"]["rollback_window_minutes"] * 60)
    expected_revision, release = _mutate_release(
        repository,
        release,
        occurred_at,
        target_state=next_state,
        active_wave_id=None,
        rollback_deadline=rollback_deadline if final_wave else release.get("rollback_deadline"),
        terminal_at=terminal_at if final_wave else release.get("terminal_at"),
    )
    with repository.transaction():
        repository.update_wave(release_id, wave_id, state="completed", completed_at=occurred_at)
        repository.update_release(release, expected_revision)
        repository.append_audit(
            release_id,
            _audit_event(
                f"wave:{wave_id}:completed",
                "wave_completed",
                occurred_at,
                actor,
                {"wave_id": wave_id, "final_wave": final_wave, "state_counts": dict(Counter(item["state"] for item in devices))},
            ),
        )
    checkpoint = create_checkpoint(repository, release_id, occurred_at, f"wave_completed:{wave_id}", actor)
    with repository.transaction():
        repository.update_wave(release_id, wave_id, checkpoint_id=checkpoint["checkpoint_id"])
    if final_wave:
        with repository.transaction():
            repository.append_audit(
                release_id,
                _audit_event(
                    f"release:{release_id}:completed",
                    "release_completed",
                    occurred_at,
                    actor,
                    {"rollback_deadline": rollback_deadline, "checkpoint_id": checkpoint["checkpoint_id"]},
                ),
            )
    return checkpoint


def pause_release(
    repository: Repository,
    release_id: str,
    occurred_at: str,
    reason: str,
    actor: str = "release-controller",
) -> dict[str, Any]:
    release = repository.get_release(release_id)
    if release["state"] == "paused" and release["paused_reason"] == reason:
        return release
    if release["state"] not in {"running", "observing", "ready"}:
        raise StateError("release_not_pausable", "release cannot be paused from its current state")
    expected_revision, release = _mutate_release(
        repository,
        release,
        occurred_at,
        target_state="paused",
        paused_reason=reason,
    )
    with repository.transaction():
        repository.update_release(release, expected_revision)
        repository.append_audit(
            release_id,
            _audit_event(
                f"release:{release_id}:paused:{release['revision']}",
                "release_paused",
                occurred_at,
                actor,
                {"reason": reason, "active_wave_id": release["active_wave_id"]},
            ),
        )
    create_checkpoint(repository, release_id, occurred_at, f"pause:{reason}", actor)
    return repository.get_release(release_id)


def resume_release(
    repository: Repository,
    release_id: str,
    occurred_at: str,
    actor: str = "release-controller",
) -> dict[str, Any]:
    release = repository.get_release(release_id)
    if release["state"] != "paused":
        raise StateError("release_not_paused", "only a paused release can resume")
    target = "observing" if release["active_wave_id"] and _wave_state(release, release["active_wave_id"])["state"] == "observing" else "running"
    if release["active_wave_id"] is None:
        target = "ready"
    expected_revision, release = _mutate_release(
        repository,
        release,
        occurred_at,
        target_state=target,
        paused_reason=None,
    )
    with repository.transaction():
        repository.update_release(release, expected_revision)
        repository.append_audit(
            release_id,
            _audit_event(
                f"release:{release_id}:resumed:{release['revision']}",
                "release_resumed",
                occurred_at,
                actor,
                {"target_state": target, "active_wave_id": release["active_wave_id"]},
            ),
        )
    return repository.get_release(release_id)


def request_rollback(
    repository: Repository,
    release_id: str,
    occurred_at: str,
    reason: str,
    actor: str = "release-controller",
) -> dict[str, Any]:
    release = repository.get_release(release_id)
    if release["state"] == "rolling_back":
        return release
    if release["state"] == "completed":
        deadline = release.get("rollback_deadline")
        if deadline is None or parse_time(occurred_at) > parse_time(deadline):
            raise StateError("rollback_window_closed", "completed release is outside its rollback window")
    elif release["state"] not in {"running", "observing", "paused", "ready"}:
        raise StateError("release_not_rollbackable", "release cannot enter rollback from its current state")
    installed = [
        item for item in release["devices"] if item["state"] in {"installed", "failed", "rolling_back", "rollback_failed"}
    ]
    if not installed:
        raise StateError("rollback_has_no_targets", "release has no devices eligible for rollback")
    expected_revision, release = _mutate_release(
        repository,
        release,
        occurred_at,
        target_state="rolling_back",
        paused_reason=reason,
    )
    with repository.transaction():
        repository.update_release(release, expected_revision)
        repository.append_audit(
            release_id,
            _audit_event(
                f"release:{release_id}:rollback:{release['revision']}",
                "rollback_requested",
                occurred_at,
                actor,
                {"reason": reason, "target_device_ids": [item["device_id"] for item in installed]},
            ),
        )
    create_checkpoint(repository, release_id, occurred_at, f"rollback_requested:{reason}", actor)
    return repository.get_release(release_id)


def finalize_rollback(
    repository: Repository,
    release_id: str,
    occurred_at: str,
    actor: str = "release-controller",
) -> dict[str, Any]:
    release = repository.get_release(release_id)
    if release["state"] != "rolling_back":
        raise StateError("release_not_rolling_back", "release is not rolling back")
    rollback_targets = [
        item for item in release["devices"] if item["state"] in {"installed", "failed", "rolling_back", "rolled_back", "rollback_failed"}
    ]
    unfinished = [item["device_id"] for item in rollback_targets if item["state"] in {"installed", "failed", "rolling_back"}]
    if unfinished:
        raise StateError("rollback_incomplete", "rollback still has unfinished devices", details={"unfinished": unfinished})
    target_state = "failed" if any(item["state"] == "rollback_failed" for item in rollback_targets) else "rolled_back"
    expected_revision, release = _mutate_release(
        repository,
        release,
        occurred_at,
        target_state=target_state,
        active_wave_id=None,
        terminal_at=occurred_at,
    )
    with repository.transaction():
        repository.update_release(release, expected_revision)
        repository.append_audit(
            release_id,
            _audit_event(
                f"release:{release_id}:rollback-finalized",
                "rollback_finalized",
                occurred_at,
                actor,
                {"target_state": target_state, "target_count": len(rollback_targets)},
            ),
        )
    create_checkpoint(repository, release_id, occurred_at, f"rollback_finalized:{target_state}", actor)
    return repository.get_release(release_id)


def create_checkpoint(
    repository: Repository,
    release_id: str,
    occurred_at: str,
    reason: str,
    actor: str = "release-controller",
) -> dict[str, Any]:
    release = repository.get_release(release_id)
    snapshot = {
        "release_id": release_id,
        "state": release["state"],
        "revision": release["revision"],
        "active_wave_id": release["active_wave_id"],
        "paused_reason": release["paused_reason"],
        "rollback_deadline": release["rollback_deadline"],
        "terminal_at": release["terminal_at"],
        "waves": release["waves"],
        "devices": release["devices"],
        "pending_receipts": repository.list_pending_receipts(release_id),
        "audit_head": repository.verify_audit_chain(release_id)["head_hash"],
    }
    checkpoint_id = f"checkpoint-{release['revision']:06d}-{fingerprint(snapshot)[:12]}"
    checkpoint = {
        "checkpoint_id": checkpoint_id,
        "created_at": occurred_at,
        "revision": release["revision"],
        "reason": reason,
        "snapshot": snapshot,
        "snapshot_digest": fingerprint(snapshot),
    }
    existing = {item["checkpoint_id"] for item in repository.list_checkpoints(release_id)}
    if checkpoint_id not in existing:
        with repository.transaction():
            repository.create_checkpoint(release_id, checkpoint)
            repository.append_audit(
                release_id,
                _audit_event(
                    f"checkpoint:{checkpoint_id}",
                    "checkpoint_created",
                    occurred_at,
                    actor,
                    {"checkpoint_id": checkpoint_id, "reason": reason, "snapshot_digest": checkpoint["snapshot_digest"]},
                ),
            )
            if release["active_wave_id"]:
                repository.update_wave(release_id, release["active_wave_id"], checkpoint_id=checkpoint_id)
    return checkpoint


def checkpoint_status(repository: Repository, release_id: str, checkpoint_id: str) -> dict[str, Any]:
    checkpoint = repository.get_checkpoint(release_id, checkpoint_id)
    expected = fingerprint(checkpoint["snapshot"])
    current = repository.get_release(release_id)
    return {
        "checkpoint_id": checkpoint_id,
        "valid": expected == checkpoint["snapshot_digest"],
        "expected_digest": expected,
        "actual_digest": checkpoint["snapshot_digest"],
        "checkpoint_revision": checkpoint["revision"],
        "current_revision": current["revision"],
        "is_current": checkpoint["revision"] == current["revision"],
        "state_at_checkpoint": checkpoint["snapshot"]["state"],
        "current_state": current["state"],
    }


def lifecycle_summary(repository: Repository, release_id: str) -> dict[str, Any]:
    release = repository.get_release(release_id)
    counts = Counter(item["state"] for item in release["devices"])
    return {
        "release_id": release_id,
        "state": release["state"],
        "revision": release["revision"],
        "active_wave_id": release["active_wave_id"],
        "paused_reason": release["paused_reason"],
        "rollback_deadline": release["rollback_deadline"],
        "terminal_at": release["terminal_at"],
        "wave_states": {item["wave_id"]: item["state"] for item in release["waves"]},
        "device_states": dict(sorted(counts.items())),
        "checkpoint_count": len(repository.list_checkpoints(release_id)),
        "audit_event_count": repository.verify_audit_chain(release_id)["event_count"],
    }
