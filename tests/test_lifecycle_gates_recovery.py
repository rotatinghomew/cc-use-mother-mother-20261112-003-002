from __future__ import annotations

import unittest

from ota_orchestrator.domain import add_seconds
from ota_orchestrator.errors import StateError
from ota_orchestrator.gates import decision_summary, evaluate_failure_budget, evaluate_gate, operational_snapshot
from ota_orchestrator.receipts import process_receipt
from ota_orchestrator.recovery import inspect_recovery, recovery_summary, verify_checkpoint_recovery
from ota_orchestrator.state_machine import (
    begin_observation,
    checkpoint_status,
    complete_wave,
    create_checkpoint,
    evaluate_active_wave,
    finalize_rollback,
    lifecycle_summary,
    mark_ready,
    pause_release,
    request_rollback,
    resume_release,
    start_wave,
)
from ota_orchestrator.telemetry import compare_wave, freeze_baseline, ingest_metric

from support import (
    cloned_fixture,
    close_prepared,
    complete_device,
    complete_wave_devices,
    prepare_application,
    receipt,
    successful_metric,
)


class LifecycleGateRecoveryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory, self.application, self.release = prepare_application()
        self.repository = self.application.repository
        self.release_id = self.release["release_id"]
        self.first_wave = self.release["schedule"]["waves"][0]
        self.clock = "2026-11-12T01:10:00Z"

    def tearDown(self) -> None:
        close_prepared(self.directory, self.application)

    def mark_ready(self) -> dict:
        self.clock = add_seconds(self.clock, 1)
        return mark_ready(self.repository, self.release_id, self.clock)

    def start_first_wave(self) -> dict:
        self.mark_ready()
        self.clock = add_seconds(self.clock, 1)
        return start_wave(self.repository, self.release_id, self.first_wave["wave_id"], self.clock)

    def finish_first_wave_devices(self, failed_ids: set[str] | None = None) -> dict:
        running = self.start_first_wave()
        _, self.clock = complete_wave_devices(
            self.application,
            running,
            self.first_wave["wave_id"],
            self.clock,
            failed_ids=failed_ids,
        )
        return self.repository.get_release(self.release_id)

    def ingest_wave_health(self, wave_id: str, observed_at: str, *, degraded: bool = False) -> None:
        release = self.repository.get_release(self.release_id)
        devices = self.repository.list_device_states(self.release_id, wave_id)
        cohorts = sorted({item["cohort_key"] for item in devices})
        for index, cohort in enumerate(cohorts):
            metric = successful_metric(
                f"health-{wave_id}-{index}",
                cohort,
                wave_id,
                add_seconds(observed_at, index + 1),
                sample_count=4,
                request_count=400,
                error_count=80 if degraded else 2,
                availability_success_count=2 if degraded else 4,
                latency_p95_ms=220 if degraded else 112,
                privilege_denial_count=40 if degraded else 1,
            )
            ingest_metric(self.repository, self.release_id, metric)

    def test_mark_ready_requires_frozen_baseline(self) -> None:
        self.repository.connection.execute(
            "DELETE FROM metric_samples WHERE release_id=? AND wave_id IS NULL",
            (self.release_id,),
        )
        with self.assertRaises(Exception) as captured:
            mark_ready(self.repository, self.release_id, self.clock)
        self.assertIn("baseline", str(captured.exception).lower())

    def test_mark_ready_is_idempotent(self) -> None:
        first = self.mark_ready()
        second = mark_ready(self.repository, self.release_id, add_seconds(self.clock, 1))
        self.assertEqual(first["revision"], second["revision"])
        self.assertEqual(second["state"], "ready")

    def test_first_wave_start_sets_active_wave(self) -> None:
        release = self.start_first_wave()
        self.assertEqual(release["state"], "running")
        self.assertEqual(release["active_wave_id"], self.first_wave["wave_id"])
        state = next(item for item in release["waves"] if item["wave_id"] == self.first_wave["wave_id"])
        self.assertEqual(state["state"], "running")
        self.assertEqual(state["started_at"], self.clock)

    def test_wave_cannot_start_when_release_is_planned(self) -> None:
        with self.assertRaises(StateError) as captured:
            start_wave(self.repository, self.release_id, self.first_wave["wave_id"], self.clock)
        self.assertEqual(captured.exception.code, "release_not_startable")

    def test_second_wave_cannot_skip_dependency(self) -> None:
        self.mark_ready()
        second = self.release["schedule"]["waves"][1]
        with self.assertRaises(StateError) as captured:
            start_wave(self.repository, self.release_id, second["wave_id"], self.clock)
        self.assertEqual(captured.exception.code, "wave_dependency_not_met")

    def test_only_one_wave_can_be_active(self) -> None:
        self.start_first_wave()
        second = self.release["schedule"]["waves"][1]
        with self.assertRaises(StateError) as captured:
            start_wave(self.repository, self.release_id, second["wave_id"], add_seconds(self.clock, 1))
        self.assertEqual(captured.exception.code, "active_wave_exists")

    def test_observation_requires_all_install_attempts_to_finish(self) -> None:
        self.start_first_wave()
        with self.assertRaises(StateError) as captured:
            begin_observation(self.repository, self.release_id, self.first_wave["wave_id"], add_seconds(self.clock, 1))
        self.assertEqual(captured.exception.code, "wave_devices_incomplete")
        self.assertEqual(len(captured.exception.details["incomplete"]), self.first_wave["incremental_count"])

    def test_observation_starts_after_device_terminal_receipts(self) -> None:
        self.finish_first_wave_devices()
        self.clock = add_seconds(self.clock, 1)
        release = begin_observation(self.repository, self.release_id, self.first_wave["wave_id"], self.clock)
        self.assertEqual(release["state"], "observing")
        state = next(item for item in release["waves"] if item["wave_id"] == self.first_wave["wave_id"])
        self.assertEqual(state["state"], "observing")

    def test_gate_cannot_run_before_minimum_observation_window(self) -> None:
        self.finish_first_wave_devices()
        self.clock = add_seconds(self.clock, 1)
        begin_observation(self.repository, self.release_id, self.first_wave["wave_id"], self.clock)
        self.ingest_wave_health(self.first_wave["wave_id"], self.clock)
        with self.assertRaises(StateError) as captured:
            evaluate_active_wave(self.repository, self.release_id, add_seconds(self.clock, 30))
        self.assertEqual(captured.exception.code, "observation_window_open")

    def test_healthy_wave_decision_continues_and_creates_checkpoint(self) -> None:
        self.finish_first_wave_devices()
        self.clock = add_seconds(self.clock, 1)
        begin_observation(self.repository, self.release_id, self.first_wave["wave_id"], self.clock)
        self.ingest_wave_health(self.first_wave["wave_id"], self.clock)
        result = evaluate_active_wave(self.repository, self.release_id, add_seconds(self.clock, 61))
        self.assertEqual(result["decision"]["action"], "continue")
        self.assertIsNotNone(result["checkpoint"])
        self.assertEqual(result["release"]["state"], "ready")
        wave_state = next(item for item in result["release"]["waves"] if item["wave_id"] == self.first_wave["wave_id"])
        self.assertEqual(wave_state["state"], "completed")

    def test_degraded_wave_exhausts_budget_and_requests_rollback(self) -> None:
        failed_id = self.first_wave["assignments"][0]["device_id"]
        self.finish_first_wave_devices({failed_id})
        self.clock = add_seconds(self.clock, 1)
        begin_observation(self.repository, self.release_id, self.first_wave["wave_id"], self.clock)
        self.ingest_wave_health(self.first_wave["wave_id"], self.clock, degraded=True)
        result = evaluate_active_wave(self.repository, self.release_id, add_seconds(self.clock, 61))
        self.assertEqual(result["decision"]["action"], "rollback")
        self.assertTrue(result["decision"]["failure_budget"]["exhausted"])
        self.assertEqual(result["release"]["state"], "rolling_back")

    def test_warning_only_gate_pauses_release(self) -> None:
        self.finish_first_wave_devices()
        self.clock = add_seconds(self.clock, 1)
        begin_observation(self.repository, self.release_id, self.first_wave["wave_id"], self.clock)
        device = self.repository.list_device_states(self.release_id, self.first_wave["wave_id"])[0]
        ingest_metric(
            self.repository,
            self.release_id,
            successful_metric(
                "health-warning-only",
                device["cohort_key"],
                self.first_wave["wave_id"],
                add_seconds(self.clock, 1),
                sample_count=1,
            ),
        )
        result = evaluate_active_wave(self.repository, self.release_id, add_seconds(self.clock, 61))
        self.assertEqual(result["decision"]["action"], "pause")
        self.assertEqual(result["release"]["state"], "paused")

    def test_pause_and_resume_preserve_active_observation(self) -> None:
        self.finish_first_wave_devices()
        self.clock = add_seconds(self.clock, 1)
        begin_observation(self.repository, self.release_id, self.first_wave["wave_id"], self.clock)
        paused = pause_release(self.repository, self.release_id, add_seconds(self.clock, 1), "operator_review")
        self.assertEqual(paused["state"], "paused")
        self.assertEqual(paused["paused_reason"], "operator_review")
        resumed = resume_release(self.repository, self.release_id, add_seconds(self.clock, 2))
        self.assertEqual(resumed["state"], "observing")
        self.assertIsNone(resumed["paused_reason"])
        self.assertEqual(resumed["active_wave_id"], self.first_wave["wave_id"])

    def test_pause_is_idempotent_for_same_reason(self) -> None:
        self.start_first_wave()
        first = pause_release(self.repository, self.release_id, add_seconds(self.clock, 1), "operator_review")
        second = pause_release(self.repository, self.release_id, add_seconds(self.clock, 2), "operator_review")
        self.assertEqual(first["revision"], second["revision"])
        self.assertEqual(second["state"], "paused")

    def test_resume_requires_paused_release(self) -> None:
        self.mark_ready()
        with self.assertRaises(StateError) as captured:
            resume_release(self.repository, self.release_id, add_seconds(self.clock, 1))
        self.assertEqual(captured.exception.code, "release_not_paused")

    def test_request_rollback_requires_targets(self) -> None:
        self.mark_ready()
        with self.assertRaises(StateError) as captured:
            request_rollback(self.repository, self.release_id, add_seconds(self.clock, 1), "operator")
        self.assertEqual(captured.exception.code, "rollback_has_no_targets")

    def test_rollback_finalization_requires_all_targets_terminal(self) -> None:
        running = self.start_first_wave()
        assignment = self.first_wave["assignments"][0]
        _, self.clock, _ = complete_device(
            self.application,
            running,
            self.first_wave["wave_id"],
            assignment["device_id"],
            0,
            self.clock,
        )
        request_rollback(self.repository, self.release_id, add_seconds(self.clock, 1), "operator")
        with self.assertRaises(StateError) as captured:
            finalize_rollback(self.repository, self.release_id, add_seconds(self.clock, 2))
        self.assertEqual(captured.exception.code, "rollback_incomplete")

    def test_rollback_finalizes_after_successful_device_receipts(self) -> None:
        running = self.start_first_wave()
        assignment = self.first_wave["assignments"][0]
        sequence, self.clock, _ = complete_device(
            self.application,
            running,
            self.first_wave["wave_id"],
            assignment["device_id"],
            0,
            self.clock,
        )
        request_rollback(self.repository, self.release_id, add_seconds(self.clock, 1), "operator")
        process_receipt(
            self.repository,
            receipt(
                running,
                self.first_wave["wave_id"],
                assignment["device_id"],
                "rollback_started",
                sequence + 1,
                add_seconds(self.clock, 2),
            ),
        )
        process_receipt(
            self.repository,
            receipt(
                running,
                self.first_wave["wave_id"],
                assignment["device_id"],
                "rollback_completed",
                sequence + 2,
                add_seconds(self.clock, 3),
            ),
        )
        release = finalize_rollback(self.repository, self.release_id, add_seconds(self.clock, 4))
        self.assertEqual(release["state"], "rolled_back")
        self.assertIsNotNone(release["terminal_at"])

    def test_failed_rollback_finalizes_release_as_failed(self) -> None:
        running = self.start_first_wave()
        assignment = self.first_wave["assignments"][0]
        sequence, self.clock, _ = complete_device(
            self.application,
            running,
            self.first_wave["wave_id"],
            assignment["device_id"],
            0,
            self.clock,
        )
        request_rollback(self.repository, self.release_id, add_seconds(self.clock, 1), "operator")
        process_receipt(
            self.repository,
            receipt(running, self.first_wave["wave_id"], assignment["device_id"], "rollback_started", sequence + 1, add_seconds(self.clock, 2)),
        )
        process_receipt(
            self.repository,
            receipt(running, self.first_wave["wave_id"], assignment["device_id"], "rollback_failed", sequence + 2, add_seconds(self.clock, 3)),
        )
        release = finalize_rollback(self.repository, self.release_id, add_seconds(self.clock, 4))
        self.assertEqual(release["state"], "failed")

    def test_checkpoint_is_hash_verified(self) -> None:
        self.start_first_wave()
        checkpoint = create_checkpoint(self.repository, self.release_id, add_seconds(self.clock, 1), "manual")
        status = checkpoint_status(self.repository, self.release_id, checkpoint["checkpoint_id"])
        self.assertTrue(status["valid"])
        self.assertTrue(status["is_current"])
        self.assertEqual(status["state_at_checkpoint"], "running")

    def test_checkpoint_recovery_validation_matches_scheduled_devices(self) -> None:
        self.start_first_wave()
        checkpoint = create_checkpoint(self.repository, self.release_id, add_seconds(self.clock, 1), "manual")
        verification = verify_checkpoint_recovery(self.repository, self.release_id, checkpoint["checkpoint_id"])
        self.assertTrue(verification["valid"])
        self.assertEqual(verification["unknown_checkpoint_devices"], [])
        self.assertEqual(verification["missing_current_devices"], [])

    def test_lifecycle_summary_reports_state_and_counts(self) -> None:
        self.start_first_wave()
        summary = lifecycle_summary(self.repository, self.release_id)
        self.assertEqual(summary["state"], "running")
        self.assertEqual(summary["active_wave_id"], self.first_wave["wave_id"])
        self.assertEqual(summary["device_states"]["scheduled"], 12)
        self.assertGreater(summary["audit_event_count"], 12)

    def test_freeze_baseline_covers_all_fixture_cohorts(self) -> None:
        baseline = freeze_baseline(self.repository, self.release_id)
        self.assertEqual(baseline["missing_cohorts"], [])
        self.assertEqual(len(baseline["by_cohort"]), 12)
        self.assertEqual(len(baseline["baseline_digest"]), 64)

    def test_compare_wave_reports_missing_cohorts(self) -> None:
        self.finish_first_wave_devices()
        device = self.repository.list_device_states(self.release_id, self.first_wave["wave_id"])[0]
        ingest_metric(
            self.repository,
            self.release_id,
            successful_metric("partial-health", device["cohort_key"], self.first_wave["wave_id"], self.clock),
        )
        analysis = compare_wave(self.repository, self.release_id, self.first_wave["wave_id"])
        self.assertGreaterEqual(len(analysis["missing_cohorts"]), 1)
        self.assertLess(analysis["metric_coverage"], 1.0)

    def test_operational_snapshot_calculates_failure_rates(self) -> None:
        failed_id = self.first_wave["assignments"][0]["device_id"]
        self.finish_first_wave_devices({failed_id})
        snapshot = operational_snapshot(self.repository, self.release_id, self.first_wave["wave_id"])
        self.assertEqual(snapshot["attempted"], 3)
        self.assertEqual(snapshot["failed"], 1)
        self.assertAlmostEqual(snapshot["failure_rate"], 1 / 3, places=5)
        self.assertAlmostEqual(snapshot["success_rate"], 2 / 3, places=5)

    def test_failure_budget_reports_remaining_capacity(self) -> None:
        operational = {
            "failed": 1,
            "rollback_failed": 0,
            "failure_rate": 0.1,
            "maximum_consecutive_failures": 1,
            "critical_failures": 0,
        }
        budget = self.release["plan"]["failure_budget"]
        result = evaluate_failure_budget(operational, budget)
        self.assertFalse(result["exhausted"])
        self.assertEqual(result["remaining_failed_devices"], 1)
        self.assertAlmostEqual(result["remaining_failed_fraction"], 0.1)

    def test_decision_summary_counts_severity(self) -> None:
        self.finish_first_wave_devices()
        self.ingest_wave_health(self.first_wave["wave_id"], self.clock)
        analysis = compare_wave(self.repository, self.release_id, self.first_wave["wave_id"])
        decision = evaluate_gate(self.repository, self.release_id, self.first_wave["wave_id"], analysis)
        summary = decision_summary(decision)
        self.assertEqual(summary["action"], "continue")
        self.assertFalse(summary["failure_budget_exhausted"])
        self.assertEqual(len(summary["decision_digest"]), 64)

    def test_recovery_detects_stale_install_operation(self) -> None:
        running = self.start_first_wave()
        assignment = self.first_wave["assignments"][0]
        process_receipt(
            self.repository,
            receipt(running, self.first_wave["wave_id"], assignment["device_id"], "install_started", 1, self.clock),
        )
        recovery = inspect_recovery(self.repository, self.release_id, add_seconds(self.clock, 7200), stale_after_minutes=30)
        self.assertEqual(recovery["severity"], "warning")
        self.assertIn("stale_device_operations", [item["code"] for item in recovery["issues"]])
        self.assertEqual(recovery["next_action"], "request_device_status")

    def test_recovery_detects_pending_receipts(self) -> None:
        running = self.start_first_wave()
        assignment = self.first_wave["assignments"][0]
        pending = receipt(running, self.first_wave["wave_id"], assignment["device_id"], "install_completed", 3, add_seconds(self.clock, 3))
        process_receipt(self.repository, pending)
        recovery = inspect_recovery(self.repository, self.release_id, add_seconds(self.clock, 10))
        self.assertIn("pending_receipts", [item["code"] for item in recovery["issues"]])
        self.assertEqual(recovery["next_action"], "drain_pending_receipts")

    def test_recovery_detects_integrity_tampering(self) -> None:
        self.repository.connection.execute(
            "UPDATE audit_events SET event_hash=? WHERE release_id=? AND event_sequence=(SELECT MIN(event_sequence) FROM audit_events WHERE release_id=?)",
            ("e" * 64, self.release_id, self.release_id),
        )
        recovery = inspect_recovery(self.repository, self.release_id, self.clock)
        self.assertEqual(recovery["severity"], "critical")
        self.assertEqual(recovery["next_action"], "restore_verified_backup")
        summary = recovery_summary(recovery)
        self.assertIn("restore_verified_backup", summary["unsafe_repairs"])

    def test_recovery_recommends_continue_for_clean_ready_release(self) -> None:
        self.mark_ready()
        recovery = inspect_recovery(self.repository, self.release_id, add_seconds(self.clock, 1))
        self.assertEqual(recovery["severity"], "none")
        self.assertEqual(recovery["next_action"], "continue_release")


if __name__ == "__main__":
    unittest.main()

