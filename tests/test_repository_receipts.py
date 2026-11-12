from __future__ import annotations

import sqlite3
import unittest
from pathlib import Path

from ota_orchestrator.domain import add_seconds, fingerprint
from ota_orchestrator.errors import ConflictError, DomainError, ReceiptError
from ota_orchestrator.receipts import drain_pending_receipts, process_receipt, receipt_summary, validate_receipt
from ota_orchestrator.repository import Repository
from ota_orchestrator.telemetry import ingest_metric, telemetry_summary, validate_metric

from support import (
    cloned_fixture,
    close_prepared,
    complete_device,
    prepare_application,
    receipt,
    successful_metric,
    tamper_digest,
    temporary_application,
)


class RepositoryAndReceiptTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory, self.application, self.release = prepare_application()
        self.repository = self.application.repository
        self.release_id = self.release["release_id"]
        self.wave = self.release["schedule"]["waves"][0]
        self.device_id = self.wave["assignments"][0]["device_id"]
        self.clock = "2026-11-12T01:10:00Z"

    def tearDown(self) -> None:
        close_prepared(self.directory, self.application)

    def test_release_is_persisted_with_wave_and_device_rows(self) -> None:
        loaded = self.repository.get_release(self.release_id)
        self.assertEqual(loaded["state"], "planned")
        self.assertEqual(len(loaded["waves"]), 3)
        self.assertEqual(len(loaded["devices"]), 12)
        self.assertEqual({item["state"] for item in loaded["devices"]}, {"scheduled"})

    def test_release_creation_rejects_duplicate_release_id(self) -> None:
        with self.assertRaises(ConflictError) as captured:
            self.repository.create_release(self.release)
        self.assertEqual(captured.exception.code, "release_exists")

    def test_optimistic_revision_conflict_is_detected(self) -> None:
        first = self.repository.get_release(self.release_id)
        second = self.repository.get_release(self.release_id)
        first["state"] = "ready"
        first["revision"] += 1
        first["updated_at"] = add_seconds(first["updated_at"], 1)
        with self.repository.transaction():
            self.repository.update_release(first, 1)
        second["state"] = "paused"
        second["revision"] += 1
        second["updated_at"] = add_seconds(second["updated_at"], 2)
        with self.assertRaises(ConflictError) as captured:
            with self.repository.transaction():
                self.repository.update_release(second, 1)
        self.assertEqual(captured.exception.code, "revision_conflict")

    def test_transaction_rolls_back_partial_updates(self) -> None:
        original = self.repository.get_device_state(self.release_id, self.device_id)
        with self.assertRaises(RuntimeError):
            with self.repository.transaction():
                self.repository.update_device(self.release_id, self.device_id, state="installing")
                raise RuntimeError("force rollback")
        current = self.repository.get_device_state(self.release_id, self.device_id)
        self.assertEqual(current["state"], original["state"])

    def test_audit_chain_is_append_only_and_verifiable(self) -> None:
        initial = self.repository.verify_audit_chain(self.release_id)
        self.assertTrue(initial["valid"])
        self.assertEqual(initial["event_count"], 13)
        with self.repository.transaction():
            result = self.repository.append_audit(
                self.release_id,
                {
                    "event_id": "test-audit-event",
                    "event_type": "test_event",
                    "occurred_at": self.clock,
                    "actor": "test-suite",
                    "details": {"purpose": "chain verification"},
                },
            )
        self.assertEqual(result["status"], "inserted")
        verified = self.repository.verify_audit_chain(self.release_id)
        self.assertTrue(verified["valid"])
        self.assertEqual(verified["event_count"], initial["event_count"] + 1)
        self.assertNotEqual(verified["head_hash"], initial["head_hash"])

    def test_duplicate_audit_event_is_idempotent(self) -> None:
        event = {
            "event_id": "audit-idempotent",
            "event_type": "test_event",
            "occurred_at": self.clock,
            "actor": "test-suite",
            "details": {"value": 1},
        }
        with self.repository.transaction():
            first = self.repository.append_audit(self.release_id, event)
        with self.repository.transaction():
            second = self.repository.append_audit(self.release_id, event)
        self.assertEqual(first["status"], "inserted")
        self.assertEqual(second["status"], "duplicate")
        self.assertEqual(first["event_hash"], second["event_hash"])

    def test_conflicting_audit_event_id_is_rejected(self) -> None:
        event = {
            "event_id": "audit-conflict",
            "event_type": "test_event",
            "occurred_at": self.clock,
            "actor": "test-suite",
            "details": {"value": 1},
        }
        with self.repository.transaction():
            self.repository.append_audit(self.release_id, event)
        changed = dict(event)
        changed["details"] = {"value": 2}
        with self.assertRaises(ConflictError) as captured:
            with self.repository.transaction():
                self.repository.append_audit(self.release_id, changed)
        self.assertEqual(captured.exception.code, "audit_event_conflict")

    def test_audit_chain_detects_database_tampering(self) -> None:
        self.repository.connection.execute(
            "UPDATE audit_events SET event_hash=? WHERE release_id=? AND event_sequence=(SELECT MIN(event_sequence) FROM audit_events WHERE release_id=?)",
            ("f" * 64, self.release_id, self.release_id),
        )
        verification = self.repository.verify_audit_chain(self.release_id)
        self.assertFalse(verification["valid"])
        self.assertGreaterEqual(len(verification["failures"]), 1)

    def test_repository_integrity_includes_sqlite_and_audit_checks(self) -> None:
        integrity = self.repository.integrity_check(self.release_id)
        self.assertTrue(integrity["valid"])
        self.assertEqual(integrity["sqlite_integrity"], "ok")
        self.assertEqual(integrity["orphan_receipts"], 0)
        self.assertTrue(integrity["release_digest_valid"])

    def test_database_backup_can_be_opened_and_read(self) -> None:
        backup = Path(self.directory.name) / "backup.sqlite3"
        self.repository.backup(backup)
        self.assertTrue(backup.exists())
        connection = sqlite3.connect(backup)
        try:
            count = connection.execute("SELECT COUNT(*) FROM releases").fetchone()[0]
        finally:
            connection.close()
        self.assertEqual(count, 1)

    def test_download_receipt_changes_scheduled_device_to_downloading(self) -> None:
        value = receipt(self.release, self.wave["wave_id"], self.device_id, "download_started", 1, self.clock)
        result = process_receipt(self.repository, value)
        self.assertEqual(result["status"], "applied")
        self.assertEqual(result["device_state"]["state"], "downloading")

    def test_identical_receipt_is_idempotent(self) -> None:
        value = receipt(self.release, self.wave["wave_id"], self.device_id, "download_started", 1, self.clock)
        first = process_receipt(self.repository, value)
        second = process_receipt(self.repository, value)
        self.assertEqual(first["status"], "applied")
        self.assertEqual(second["status"], "duplicate")
        self.assertEqual(len(self.repository.list_receipts(self.release_id, self.device_id)), 1)

    def test_receipt_id_reuse_with_changed_payload_is_conflict(self) -> None:
        value = receipt(self.release, self.wave["wave_id"], self.device_id, "download_started", 1, self.clock)
        process_receipt(self.repository, value)
        changed = dict(value)
        changed["payload"] = {"changed": True}
        with self.assertRaises(ConflictError) as captured:
            process_receipt(self.repository, changed)
        self.assertEqual(captured.exception.code, "receipt_id_conflict")

    def test_receipt_for_wrong_wave_is_rejected(self) -> None:
        wrong_wave = self.release["schedule"]["waves"][1]["wave_id"]
        value = receipt(self.release, wrong_wave, self.device_id, "download_started", 1, self.clock)
        with self.assertRaises(ReceiptError) as captured:
            process_receipt(self.repository, value)
        self.assertEqual(captured.exception.code, "receipt_wave_mismatch")

    def test_completion_before_start_is_queued_then_drained(self) -> None:
        completion = receipt(self.release, self.wave["wave_id"], self.device_id, "install_completed", 3, add_seconds(self.clock, 3))
        result = process_receipt(self.repository, completion)
        self.assertEqual(result["status"], "pending")
        self.assertEqual(len(self.repository.list_pending_receipts(self.release_id)), 1)
        process_receipt(
            self.repository,
            receipt(self.release, self.wave["wave_id"], self.device_id, "download_started", 1, self.clock),
        )
        started = process_receipt(
            self.repository,
            receipt(self.release, self.wave["wave_id"], self.device_id, "install_started", 2, add_seconds(self.clock, 1)),
        )
        self.assertIn(completion["receipt_id"], started["drained"])
        device = self.repository.get_device_state(self.release_id, self.device_id)
        self.assertEqual(device["state"], "installed")
        self.assertEqual(len(self.repository.list_pending_receipts(self.release_id)), 0)

    def test_late_start_after_completion_is_recorded_without_regression(self) -> None:
        sequence, clock, _ = complete_device(
            self.application, self.release, self.wave["wave_id"], self.device_id, 0, self.clock
        )
        late = receipt(
            self.release,
            self.wave["wave_id"],
            self.device_id,
            "install_started",
            sequence + 1,
            self.clock,
        )
        result = process_receipt(self.repository, late)
        self.assertEqual(result["status"], "late")
        self.assertEqual(self.repository.get_device_state(self.release_id, self.device_id)["state"], "installed")

    def test_conflicting_terminal_receipt_is_preserved_as_conflict(self) -> None:
        sequence, clock, _ = complete_device(
            self.application, self.release, self.wave["wave_id"], self.device_id, 0, self.clock
        )
        conflict = receipt(
            self.release,
            self.wave["wave_id"],
            self.device_id,
            "install_failed",
            sequence + 1,
            add_seconds(clock, 1),
        )
        result = process_receipt(self.repository, conflict)
        self.assertEqual(result["status"], "conflict")
        self.assertIsNotNone(result["conflict_with"])
        summary = receipt_summary(self.repository, self.release_id)
        self.assertEqual(summary["dispositions"]["conflict"], 1)
        self.assertIn(conflict["receipt_id"], summary["conflict_ids"])

    def test_install_completion_requires_target_version(self) -> None:
        process_receipt(
            self.repository,
            receipt(self.release, self.wave["wave_id"], self.device_id, "install_started", 1, self.clock),
        )
        completion = receipt(
            self.release,
            self.wave["wave_id"],
            self.device_id,
            "install_completed",
            2,
            add_seconds(self.clock, 1),
        )
        completion["payload"]["installed_version"] = "9.9.9"
        with self.assertRaises(ReceiptError) as captured:
            process_receipt(self.repository, completion)
        self.assertEqual(captured.exception.code, "installed_version_mismatch")

    def test_install_failure_records_failure_code(self) -> None:
        sequence, clock, results = complete_device(
            self.application,
            self.release,
            self.wave["wave_id"],
            self.device_id,
            0,
            self.clock,
            fail=True,
        )
        self.assertEqual(sequence, 3)
        self.assertEqual(results[-1]["status"], "applied")
        device = self.repository.get_device_state(self.release_id, self.device_id)
        self.assertEqual(device["state"], "failed")
        self.assertEqual(device["failure_code"], "synthetic_install_failure")

    def test_rollback_completion_requires_original_version(self) -> None:
        sequence, clock, _ = complete_device(
            self.application, self.release, self.wave["wave_id"], self.device_id, 0, self.clock
        )
        process_receipt(
            self.repository,
            receipt(self.release, self.wave["wave_id"], self.device_id, "rollback_started", sequence + 1, add_seconds(clock, 1)),
        )
        rollback = receipt(
            self.release,
            self.wave["wave_id"],
            self.device_id,
            "rollback_completed",
            sequence + 2,
            add_seconds(clock, 2),
        )
        rollback["payload"]["rollback_version"] = "2.2.0"
        with self.assertRaises(ReceiptError) as captured:
            process_receipt(self.repository, rollback)
        self.assertEqual(captured.exception.code, "rollback_version_mismatch")

    def test_receipt_validation_rejects_receive_time_before_occurrence(self) -> None:
        value = receipt(self.release, self.wave["wave_id"], self.device_id, "download_started", 1, self.clock)
        value["received_at"] = "2026-11-12T01:09:00Z"
        with self.assertRaises(ReceiptError) as captured:
            validate_receipt(value)
        self.assertEqual(captured.exception.code, "receipt_received_before_occurrence")

    def test_receipt_validation_rejects_invalid_signature_digest(self) -> None:
        value = receipt(self.release, self.wave["wave_id"], self.device_id, "download_started", 1, self.clock)
        value["signature_digest"] = "short"
        with self.assertRaises(DomainError) as captured:
            validate_receipt(value)
        self.assertEqual(captured.exception.code, "invalid_string_length")

    def test_pending_drain_is_noop_when_prerequisite_missing(self) -> None:
        completion = receipt(self.release, self.wave["wave_id"], self.device_id, "install_completed", 3, add_seconds(self.clock, 3))
        process_receipt(self.repository, completion)
        applied = drain_pending_receipts(self.repository, self.release_id, self.device_id)
        self.assertEqual(applied, [])
        self.assertEqual(len(self.repository.list_pending_receipts(self.release_id)), 1)

    def test_metric_ingestion_is_idempotent(self) -> None:
        cohort = self.release["snapshot"]["eligible_devices"][0]["cohort_key"]
        metric = successful_metric("metric-idempotent", cohort, self.wave["wave_id"], self.clock)
        first = ingest_metric(self.repository, self.release_id, metric)
        second = ingest_metric(self.repository, self.release_id, metric)
        self.assertEqual(first["status"], "inserted")
        self.assertEqual(second["status"], "duplicate")

    def test_metric_id_reuse_with_changed_content_is_conflict(self) -> None:
        cohort = self.release["snapshot"]["eligible_devices"][0]["cohort_key"]
        metric = successful_metric("metric-conflict", cohort, self.wave["wave_id"], self.clock)
        ingest_metric(self.repository, self.release_id, metric)
        changed = dict(metric)
        changed["error_count"] = 99
        with self.assertRaises(ConflictError) as captured:
            ingest_metric(self.repository, self.release_id, changed)
        self.assertEqual(captured.exception.code, "metric_conflict")

    def test_metric_for_unknown_wave_is_rejected(self) -> None:
        cohort = self.release["snapshot"]["eligible_devices"][0]["cohort_key"]
        metric = successful_metric("metric-unknown-wave", cohort, "wave-missing", self.clock)
        with self.assertRaises(DomainError) as captured:
            ingest_metric(self.repository, self.release_id, metric)
        self.assertEqual(captured.exception.code, "unknown_metric_wave")

    def test_metric_for_unknown_cohort_is_rejected(self) -> None:
        metric = successful_metric("metric-unknown-cohort", "cohort-missing", self.wave["wave_id"], self.clock)
        with self.assertRaises(DomainError) as captured:
            ingest_metric(self.repository, self.release_id, metric)
        self.assertEqual(captured.exception.code, "unknown_metric_cohort")

    def test_metric_validation_checks_quantile_order(self) -> None:
        cohort = self.release["snapshot"]["eligible_devices"][0]["cohort_key"]
        metric = successful_metric("metric-quantiles", cohort, self.wave["wave_id"], self.clock)
        metric["latency_p50_ms"] = 200
        metric["latency_p95_ms"] = 100
        with self.assertRaises(DomainError) as captured:
            validate_metric(metric)
        self.assertEqual(captured.exception.code, "invalid_latency_quantiles")

    def test_metric_validation_checks_count_consistency(self) -> None:
        cohort = self.release["snapshot"]["eligible_devices"][0]["cohort_key"]
        metric = successful_metric("metric-counts", cohort, self.wave["wave_id"], self.clock)
        metric["error_count"] = metric["request_count"] + 1
        with self.assertRaises(DomainError) as captured:
            validate_metric(metric)
        self.assertEqual(captured.exception.code, "invalid_metric_counts")

    def test_telemetry_summary_includes_baseline_and_wave_metrics(self) -> None:
        cohort = self.release["snapshot"]["eligible_devices"][0]["cohort_key"]
        ingest_metric(
            self.repository,
            self.release_id,
            successful_metric("metric-wave-summary", cohort, self.wave["wave_id"], self.clock),
        )
        summary = telemetry_summary(self.repository, self.release_id)
        self.assertGreater(summary["metric_count"], 12)
        self.assertEqual(summary["metrics_by_scope"][self.wave["wave_id"]], 1)
        self.assertEqual(summary["metrics_by_scope"]["baseline"], 12)

    def test_export_release_contains_all_auditable_surfaces(self) -> None:
        exported = self.repository.export_release(self.release_id)
        self.assertIn("release", exported)
        self.assertIn("receipts", exported)
        self.assertIn("pending_receipts", exported)
        self.assertIn("metrics", exported)
        self.assertIn("checkpoints", exported)
        self.assertIn("audit", exported)
        self.assertTrue(exported["integrity"]["valid"])


class RepositoryLifecycleTests(unittest.TestCase):
    def test_repository_context_manager_closes_connection(self) -> None:
        with temporary_application() as (application, database):
            application.prepare_release(cloned_fixture())
            connection = application.repository.connection
        with self.assertRaises(sqlite3.ProgrammingError):
            connection.execute("SELECT 1")


if __name__ == "__main__":
    unittest.main()

