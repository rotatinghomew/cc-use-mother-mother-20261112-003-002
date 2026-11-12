from __future__ import annotations

import copy
import unittest

from ota_orchestrator.contracts import validate_artifact, validate_plan
from ota_orchestrator.dependency_graph import DependencyGraph, build_dependency_graph
from ota_orchestrator.eligibility import (
    build_eligibility_snapshot,
    snapshot_summary,
    split_large_cohorts,
    verify_snapshot,
)
from ota_orchestrator.errors import DomainError
from ota_orchestrator.scheduler import schedule_summary, schedule_waves, verify_schedule

from support import hydrated_fixture


class EligibilityAndSchedulerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.value = hydrated_fixture()
        self.plan = validate_plan(self.value["plan"])
        self.artifact = validate_artifact(self.value["artifact"], self.plan)

    def snapshot(self) -> dict:
        return build_eligibility_snapshot(
            self.value["devices"],
            self.plan,
            self.value["snapshot_at"],
            dimensions=tuple(self.value["cohort_dimensions"]),
        )

    def test_snapshot_separates_eligible_and_held_devices(self) -> None:
        snapshot = self.snapshot()
        self.assertEqual(snapshot["eligible_count"], 12)
        self.assertEqual(snapshot["held_count"], 1)
        held = snapshot["held_devices"][0]
        self.assertEqual(held["device_id"], "device-held")
        self.assertIn("bootloader_too_old", held["eligibility_reasons"])
        self.assertIn("battery_not_ready", held["eligibility_reasons"])

    def test_snapshot_is_deterministic_under_input_reordering(self) -> None:
        first = self.snapshot()
        self.value["devices"].reverse()
        second = self.snapshot()
        self.assertEqual(first["snapshot_digest"], second["snapshot_digest"])
        self.assertEqual(
            [item["device_id"] for item in first["eligible_devices"]],
            [item["device_id"] for item in second["eligible_devices"]],
        )

    def test_snapshot_verification_detects_tampering(self) -> None:
        snapshot = self.snapshot()
        self.assertTrue(verify_snapshot(snapshot)["valid"])
        snapshot["eligible_devices"][0]["region"] = "changed"
        verification = verify_snapshot(snapshot)
        self.assertFalse(verification["valid"])
        self.assertNotEqual(verification["expected_digest"], verification["actual_digest"])

    def test_wrong_identity_is_held(self) -> None:
        self.value["devices"][0]["identity_code"] = "agent-wrong"
        snapshot = self.snapshot()
        held = next(item for item in snapshot["held_devices"] if item["device_id"] == "device-001")
        self.assertIn("identity_code_mismatch", held["eligibility_reasons"])

    def test_stale_device_is_held(self) -> None:
        self.value["devices"][0]["last_seen_at"] = "2026-10-01T00:00:00Z"
        snapshot = self.snapshot()
        held = next(item for item in snapshot["held_devices"] if item["device_id"] == "device-001")
        self.assertIn("device_stale", held["eligibility_reasons"])

    def test_future_last_seen_is_held(self) -> None:
        self.value["devices"][0]["last_seen_at"] = "2026-11-13T00:00:00Z"
        snapshot = self.snapshot()
        held = next(item for item in snapshot["held_devices"] if item["device_id"] == "device-001")
        self.assertIn("last_seen_in_future", held["eligibility_reasons"])

    def test_channel_mismatch_is_held(self) -> None:
        self.value["devices"][0]["channel"] = "beta"
        snapshot = self.snapshot()
        held = next(item for item in snapshot["held_devices"] if item["device_id"] == "device-001")
        self.assertIn("channel_mismatch", held["eligibility_reasons"])

    def test_snapshot_summary_reports_critical_devices(self) -> None:
        summary = snapshot_summary(self.snapshot())
        self.assertEqual(summary["eligible"], 12)
        self.assertEqual(summary["held"], 1)
        self.assertEqual(summary["critical_eligible"], 0)
        self.assertGreater(summary["cohorts"], 5)

    def test_large_cohort_split_preserves_device_count(self) -> None:
        snapshot = self.snapshot()
        split = split_large_cohorts(snapshot, 1)
        self.assertEqual(split["eligible_count"], snapshot["eligible_count"])
        self.assertEqual(len(split["eligible_devices"]), len(snapshot["eligible_devices"]))
        self.assertTrue(all("|shard=" in item["cohort_key"] for item in split["eligible_devices"]))
        self.assertTrue(verify_snapshot(split)["valid"])

    def test_dependency_graph_builds_topological_stages(self) -> None:
        graph = DependencyGraph(self.plan["capabilities"], self.plan["dependencies"])
        layers = graph.topological_layers()
        self.assertIn("cap-local-search", layers[0])
        self.assertIn("cap-device-action", layers[0])
        self.assertIn("cap-delegated-navigation", layers[-1])
        self.assertEqual(
            graph.transitive_requirements("cap-delegated-navigation"),
            ["cap-local-search"],
        )

    def test_dependency_cycle_is_rejected(self) -> None:
        dependencies = list(self.plan["dependencies"])
        dependencies.append(
            {
                "predecessor": "cap-delegated-navigation",
                "successor": "cap-local-search",
                "type": "requires",
                "reason": "synthetic cycle",
            }
        )
        with self.assertRaises(DomainError) as captured:
            DependencyGraph(self.plan["capabilities"], dependencies)
        self.assertEqual(captured.exception.code, "dependency_cycle")

    def test_missing_transitive_requirement_is_reported(self) -> None:
        graph = DependencyGraph(self.plan["capabilities"], self.plan["dependencies"])
        validation = graph.validate_enabled_set(["cap-delegated-navigation"])
        self.assertFalse(validation["valid"])
        self.assertEqual(
            validation["missing_requirements"]["cap-delegated-navigation"],
            ["cap-local-search"],
        )

    def test_conflicting_capability_set_is_reported(self) -> None:
        dependencies = list(self.plan["dependencies"])
        dependencies.append(
            {
                "predecessor": "cap-local-search",
                "successor": "cap-device-action",
                "type": "conflicts",
                "reason": "synthetic conflict",
            }
        )
        graph = DependencyGraph(self.plan["capabilities"], dependencies)
        validation = graph.validate_enabled_set(["cap-local-search", "cap-device-action"])
        self.assertFalse(validation["valid"])
        self.assertEqual(validation["conflicts"], [["cap-device-action", "cap-local-search"]])

    def test_schedule_covers_each_eligible_device_once(self) -> None:
        snapshot = self.snapshot()
        graph = build_dependency_graph(self.plan)
        schedule = schedule_waves(snapshot, self.plan, graph)
        verification = verify_schedule(schedule)
        self.assertTrue(verification["valid"])
        self.assertEqual(verification["assigned_count"], 12)
        assigned = [item["device_id"] for wave in schedule["waves"] for item in wave["assignments"]]
        self.assertEqual(len(assigned), len(set(assigned)))
        self.assertEqual(len(assigned), snapshot["eligible_count"])

    def test_schedule_is_deterministic(self) -> None:
        snapshot = self.snapshot()
        graph = build_dependency_graph(self.plan)
        first = schedule_waves(snapshot, self.plan, graph)
        second = schedule_waves(copy.deepcopy(snapshot), copy.deepcopy(self.plan), copy.deepcopy(graph))
        self.assertEqual(first["schedule_digest"], second["schedule_digest"])
        self.assertEqual(first, second)

    def test_wave_targets_are_incremental_and_cumulative(self) -> None:
        schedule = schedule_waves(self.snapshot(), self.plan, build_dependency_graph(self.plan))
        self.assertEqual([wave["cumulative_target_count"] for wave in schedule["waves"]], [3, 6, 12])
        self.assertEqual([wave["incremental_count"] for wave in schedule["waves"]], [3, 3, 6])

    def test_parallel_capacity_splits_batches(self) -> None:
        schedule = schedule_waves(self.snapshot(), self.plan, build_dependency_graph(self.plan))
        for wave in schedule["waves"]:
            for batch in wave["batches"]:
                self.assertLessEqual(len(batch["device_ids"]), wave["maximum_parallel_devices"])
        self.assertEqual(len(schedule["waves"][0]["batches"]), 2)

    def test_wave_dependencies_form_a_linear_release_chain(self) -> None:
        schedule = schedule_waves(self.snapshot(), self.plan, build_dependency_graph(self.plan))
        self.assertIsNone(schedule["waves"][0]["depends_on_wave_id"])
        self.assertEqual(schedule["waves"][1]["depends_on_wave_id"], schedule["waves"][0]["wave_id"])
        self.assertEqual(schedule["waves"][2]["depends_on_wave_id"], schedule["waves"][1]["wave_id"])

    def test_schedule_verification_detects_wave_tampering(self) -> None:
        schedule = schedule_waves(self.snapshot(), self.plan, build_dependency_graph(self.plan))
        schedule["waves"][0]["assignments"][0]["region"] = "tampered"
        verification = verify_schedule(schedule)
        self.assertFalse(verification["valid"])
        self.assertIn(schedule["waves"][0]["wave_id"], verification["wave_digest_failures"])

    def test_schedule_summary_reports_operational_shape(self) -> None:
        schedule = schedule_waves(self.snapshot(), self.plan, build_dependency_graph(self.plan))
        summary = schedule_summary(schedule)
        self.assertEqual(summary["eligible_count"], 12)
        self.assertEqual(summary["wave_count"], 3)
        self.assertGreaterEqual(summary["batch_count"], 5)
        self.assertEqual(sum(summary["wave_sizes"].values()), 12)

    def test_scheduler_rejects_empty_eligible_snapshot(self) -> None:
        snapshot = self.snapshot()
        snapshot["eligible_devices"] = []
        snapshot["eligible_count"] = 0
        with self.assertRaises(DomainError) as captured:
            schedule_waves(snapshot, self.plan, build_dependency_graph(self.plan))
        self.assertEqual(captured.exception.code, "no_eligible_devices")


if __name__ == "__main__":
    unittest.main()

