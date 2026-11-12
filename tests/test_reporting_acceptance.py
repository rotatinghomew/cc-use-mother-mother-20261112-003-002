from __future__ import annotations

import copy
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from ota_orchestrator.domain import fingerprint
from ota_orchestrator.recovery import inspect_recovery
from ota_orchestrator.reporting import build_completion_report, report_summary, verify_completion_report
from ota_orchestrator.repository import Repository
from ota_orchestrator.service import OtaOrchestrator

from support import FIXTURE_PATH, cloned_fixture, tamper_digest


class ReportingAcceptanceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory(prefix="ota-report-tests-")
        self.database = Path(self.directory.name) / "acceptance.sqlite3"
        self.application = OtaOrchestrator(self.database)

    def tearDown(self) -> None:
        self.application.close()
        self.directory.cleanup()

    def run_acceptance(self, value: dict | None = None) -> dict:
        return self.application.run_fixture(value or cloned_fixture())

    def test_full_acceptance_completes_all_waves(self) -> None:
        result = self.run_acceptance()
        self.assertEqual(result["release"]["state"], "completed")
        self.assertEqual(result["report"]["assessment"], "passed")
        self.assertTrue(result["report_verification"]["valid"])
        self.assertTrue(result["report"]["integrity"]["valid"])
        self.assertEqual(result["report"]["device_outcome_counts"], {"installed": 12})
        self.assertEqual(len(result["report"]["waves"]), 3)

    def test_acceptance_report_contains_plan_and_artifact_proof(self) -> None:
        report = self.run_acceptance()["report"]
        self.assertEqual(report["plan"]["identity_code"], "agent-cn-ota-002")
        self.assertEqual(report["plan"]["current_version"], "2.3.0")
        self.assertEqual(report["plan"]["target_version"], "2.4.0")
        self.assertEqual(report["artifact"]["version"], "2.4.0")
        self.assertEqual(len(report["plan"]["plan_fingerprint"]), 64)
        self.assertEqual(len(report["artifact"]["artifact_fingerprint"]), 64)
        self.assertEqual(len(report["artifact"]["signing"]["signature_digest"]), 64)

    def test_acceptance_report_exposes_eligibility_holds(self) -> None:
        report = self.run_acceptance()["report"]
        self.assertEqual(report["eligibility"]["eligible_count"], 12)
        self.assertEqual(report["eligibility"]["held_count"], 1)
        self.assertEqual(report["eligibility"]["hold_reason_counts"]["battery_not_ready"], 1)
        self.assertEqual(report["eligibility"]["hold_reason_counts"]["bootloader_too_old"], 1)

    def test_acceptance_report_exposes_third_party_consent(self) -> None:
        report = self.run_acceptance()["report"]
        declarations = report["third_party_declarations"]
        self.assertEqual(len(declarations), 1)
        self.assertTrue(declarations[0]["consent"])
        self.assertIn("cap-delegated-navigation", declarations[0]["allowed_capabilities"])
        self.assertEqual(declarations[0]["signature_algorithm"], "ed25519")

    def test_acceptance_report_wave_decisions_are_continue(self) -> None:
        report = self.run_acceptance()["report"]
        self.assertEqual([wave["decision"] for wave in report["waves"]], ["continue", "continue", "continue"])
        self.assertTrue(all(wave["state"] == "completed" for wave in report["waves"]))
        self.assertTrue(all(wave["checkpoint_id"] for wave in report["waves"]))

    def test_acceptance_report_contains_receipt_and_metric_evidence(self) -> None:
        report = self.run_acceptance()["report"]
        self.assertEqual(report["receipts"]["receipt_count"], 36)
        self.assertEqual(report["receipts"]["pending_count"], 0)
        self.assertEqual(report["receipts"]["conflict_ids"], [])
        self.assertEqual(report["receipts"]["late_ids"], [])
        self.assertGreater(report["telemetry"]["metric_count"], 20)
        self.assertEqual(report["telemetry"]["metrics_by_scope"]["baseline"], 12)

    def test_acceptance_report_contains_audit_hash_head(self) -> None:
        report = self.run_acceptance()["report"]
        self.assertGreater(report["audit"]["event_count"], 90)
        self.assertEqual(len(report["audit"]["head_hash"]), 64)
        self.assertIn("receipt_recorded", report["audit"]["event_types"])
        self.assertIn("checkpoint_created", report["audit"]["event_types"])
        self.assertIn("release_completed", report["audit"]["event_types"])

    def test_report_summary_is_compact_and_decision_ready(self) -> None:
        report = self.run_acceptance()["report"]
        summary = report_summary(report)
        self.assertEqual(summary["assessment"], "passed")
        self.assertEqual(summary["release_state"], "completed")
        self.assertEqual(summary["eligible_devices"], 12)
        self.assertEqual(summary["wave_count"], 3)
        self.assertEqual(summary["failed_devices"], 0)
        self.assertTrue(summary["integrity_valid"])

    def test_report_verification_detects_plan_tampering(self) -> None:
        result = self.run_acceptance()
        report = copy.deepcopy(result["report"])
        report["plan"]["target_version"] = "9.9.9"
        verification = verify_completion_report(report, self.application.repository, result["release"]["release_id"])
        self.assertFalse(verification["valid"])
        self.assertNotEqual(verification["expected_report_digest"], verification["actual_report_digest"])

    def test_report_verification_detects_artifact_fingerprint_tampering(self) -> None:
        result = self.run_acceptance()
        report = copy.deepcopy(result["report"])
        report["artifact"]["artifact_fingerprint"] = tamper_digest(report["artifact"]["artifact_fingerprint"])
        report["report_digest"] = fingerprint({key: value for key, value in report.items() if key != "report_digest"})
        verification = verify_completion_report(report, self.application.repository, result["release"]["release_id"])
        self.assertFalse(verification["valid"])
        self.assertIn("artifact_fingerprint_mismatch", verification["issues"])

    def test_report_verification_detects_snapshot_digest_tampering(self) -> None:
        result = self.run_acceptance()
        report = copy.deepcopy(result["report"])
        report["eligibility"]["snapshot_digest"] = tamper_digest(report["eligibility"]["snapshot_digest"])
        report["report_digest"] = fingerprint({key: value for key, value in report.items() if key != "report_digest"})
        verification = verify_completion_report(report, self.application.repository, result["release"]["release_id"])
        self.assertFalse(verification["valid"])
        self.assertIn("snapshot_digest_mismatch", verification["issues"])

    def test_report_verification_detects_schedule_digest_tampering(self) -> None:
        result = self.run_acceptance()
        report = copy.deepcopy(result["report"])
        report["schedule"]["schedule_digest"] = tamper_digest(report["schedule"]["schedule_digest"])
        report["report_digest"] = fingerprint({key: value for key, value in report.items() if key != "report_digest"})
        verification = verify_completion_report(report, self.application.repository, result["release"]["release_id"])
        self.assertFalse(verification["valid"])
        self.assertIn("schedule_digest_mismatch", verification["issues"])

    def test_report_verification_detects_audit_head_tampering(self) -> None:
        result = self.run_acceptance()
        report = copy.deepcopy(result["report"])
        report["audit"]["head_hash"] = tamper_digest(report["audit"]["head_hash"])
        report["report_digest"] = fingerprint({key: value for key, value in report.items() if key != "report_digest"})
        verification = verify_completion_report(report, self.application.repository, result["release"]["release_id"])
        self.assertFalse(verification["valid"])
        self.assertIn("audit_head_mismatch", verification["issues"])

    def test_report_can_be_rebuilt_from_persisted_database(self) -> None:
        result = self.run_acceptance()
        release_id = result["release"]["release_id"]
        self.application.close()
        self.application = OtaOrchestrator(self.database)
        rebuilt = build_completion_report(
            self.application.repository,
            release_id,
            result["report"]["generated_at"],
            result["report"]["report_id"],
        )
        self.assertEqual(rebuilt["report_digest"], result["report"]["report_digest"])
        self.assertTrue(verify_completion_report(rebuilt, self.application.repository, release_id)["valid"])

    def test_recovery_after_process_reopen_is_clean(self) -> None:
        result = self.run_acceptance()
        release_id = result["release"]["release_id"]
        self.application.close()
        self.application = OtaOrchestrator(self.database)
        recovery = inspect_recovery(self.application.repository, release_id, result["report"]["generated_at"])
        self.assertIn(recovery["severity"], {"none", "info"})
        self.assertIn(recovery["next_action"], {"no_action", "continue_release"})
        self.assertTrue(recovery["integrity"]["valid"])

    def test_failure_fixture_triggers_rollback_report(self) -> None:
        value = cloned_fixture()
        value["failure_devices"] = ["device-001", "device-002"]
        result = self.run_acceptance(value)
        self.assertIn(result["release"]["state"], {"rolled_back", "failed"})
        self.assertIn(result["report"]["assessment"], {"rolled_back", "failed"})
        self.assertTrue(result["report_verification"]["valid"])
        self.assertGreaterEqual(result["report"]["failures"]["failed_device_count"], 0)

    def test_repository_export_after_acceptance_is_integrity_valid(self) -> None:
        result = self.run_acceptance()
        exported = self.application.repository.export_release(result["release"]["release_id"])
        self.assertTrue(exported["integrity"]["valid"])
        self.assertEqual(exported["release"]["state"], "completed")
        self.assertEqual(len(exported["checkpoints"]), 4)
        self.assertEqual(len(exported["receipts"]), 36)


class CommandLineAcceptanceTests(unittest.TestCase):
    def run_cli(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, "-m", "ota_orchestrator", *arguments],
            cwd=FIXTURE_PATH.parents[1],
            text=True,
            encoding="utf-8",
            capture_output=True,
            timeout=30,
        )

    def test_run_fixture_cli_writes_report_and_database(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ota-cli-") as directory:
            database = Path(directory) / "state.sqlite3"
            output = Path(directory) / "result.json"
            result = self.run_cli(
                "run-fixture",
                str(FIXTURE_PATH),
                "--database",
                str(database),
                "--output",
                str(output),
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue(database.exists())
            self.assertTrue(output.exists())
            value = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(value["release"]["state"], "completed")
            self.assertTrue(value["report_verification"]["valid"])

    def test_inspect_cli_returns_persisted_release(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ota-cli-") as directory:
            database = Path(directory) / "state.sqlite3"
            output = Path(directory) / "result.json"
            first = self.run_cli(
                "run-fixture",
                str(FIXTURE_PATH),
                "--database",
                str(database),
                "--output",
                str(output),
            )
            self.assertEqual(first.returncode, 0, first.stderr)
            inspected = self.run_cli(
                "inspect",
                "--database",
                str(database),
                "--release",
                "release-ota-fixture-002",
            )
            self.assertEqual(inspected.returncode, 0, inspected.stderr)
            value = json.loads(inspected.stdout)
            self.assertEqual(value["release"]["state"], "completed")
            self.assertTrue(value["integrity"]["valid"])

    def test_recover_cli_returns_recovery_digest(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ota-cli-") as directory:
            database = Path(directory) / "state.sqlite3"
            output = Path(directory) / "result.json"
            first = self.run_cli(
                "run-fixture",
                str(FIXTURE_PATH),
                "--database",
                str(database),
                "--output",
                str(output),
            )
            self.assertEqual(first.returncode, 0, first.stderr)
            recovered = self.run_cli(
                "recover",
                "--database",
                str(database),
                "--release",
                "release-ota-fixture-002",
                "--now",
                "2026-11-12T04:00:00Z",
            )
            self.assertEqual(recovered.returncode, 0, recovered.stderr)
            value = json.loads(recovered.stdout)
            self.assertEqual(len(value["recovery_digest"]), 64)
            self.assertTrue(value["integrity"]["valid"])

    def test_report_cli_writes_verifiable_report(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ota-cli-") as directory:
            database = Path(directory) / "state.sqlite3"
            run_output = Path(directory) / "run.json"
            report_output = Path(directory) / "report.json"
            first = self.run_cli(
                "run-fixture",
                str(FIXTURE_PATH),
                "--database",
                str(database),
                "--output",
                str(run_output),
            )
            self.assertEqual(first.returncode, 0, first.stderr)
            report = self.run_cli(
                "report",
                "--database",
                str(database),
                "--release",
                "release-ota-fixture-002",
                "--generated-at",
                "2026-11-12T04:00:00Z",
                "--report-id",
                "report-cli",
                "--output",
                str(report_output),
            )
            self.assertEqual(report.returncode, 0, report.stderr)
            verified = self.run_cli(
                "verify-report",
                str(report_output),
                "--database",
                str(database),
                "--release",
                "release-ota-fixture-002",
            )
            self.assertEqual(verified.returncode, 0, verified.stderr)
            value = json.loads(verified.stdout)
            self.assertTrue(value["valid"])

    def test_cli_reports_domain_errors_as_json(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ota-cli-") as directory:
            database = Path(directory) / "state.sqlite3"
            inspected = self.run_cli(
                "inspect",
                "--database",
                str(database),
                "--release",
                "missing-release",
            )
            self.assertEqual(inspected.returncode, 2)
            error = json.loads(inspected.stderr)
            self.assertEqual(error["error"]["code"], "release_not_found")


if __name__ == "__main__":
    unittest.main()
