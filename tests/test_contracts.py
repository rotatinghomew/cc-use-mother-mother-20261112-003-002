from __future__ import annotations

import unittest

from ota_orchestrator.contracts import (
    approval_scope_digest,
    describe_contract,
    plan_scope_payload,
    validate_artifact,
    validate_plan,
)
from ota_orchestrator.domain import fingerprint
from ota_orchestrator.errors import DomainError, ValidationError
from ota_orchestrator.service import hydrate_scenario

from support import cloned_fixture, hydrated_fixture, refresh_approval, tamper_digest


class PlanContractTests(unittest.TestCase):
    def test_valid_plan_normalizes_all_governance_fields(self) -> None:
        value = hydrated_fixture()
        plan = validate_plan(value["plan"])
        self.assertEqual(plan["plan_id"], "plan-ota-fixture-002")
        self.assertEqual(plan["identity"]["identity_code"], "agent-cn-ota-002")
        self.assertEqual(plan["versioning"]["current"], "2.3.0")
        self.assertEqual(plan["versioning"]["target"], "2.4.0")
        self.assertEqual(len(plan["capabilities"]), 3)
        self.assertEqual(len(plan["third_party_declarations"]), 1)
        self.assertEqual(len(plan["rollout"]["waves"]), 3)
        self.assertEqual(plan["rollout"]["waves"][-1]["target_percentage"], 100.0)
        self.assertEqual(plan["failure_budget"]["maximum_failed_devices"], 2)
        self.assertEqual(plan["health_thresholds"]["minimum_metric_coverage"], 0.8)
        self.assertEqual(len(plan["plan_fingerprint"]), 64)

    def test_validation_collects_multiple_independent_errors(self) -> None:
        value = hydrated_fixture()
        value["plan"]["identity"]["identity_code"] = "x"
        value["plan"]["versioning"]["target"] = "bad"
        value["plan"]["channel"] = "unknown"
        with self.assertRaises(ValidationError) as captured:
            validate_plan(value["plan"])
        codes = {item.code for item in captured.exception.violations}
        self.assertIn("invalid_string_length", codes)
        self.assertIn("invalid_version", codes)
        self.assertIn("invalid_choice", codes)

    def test_target_version_must_move_forward(self) -> None:
        value = hydrated_fixture()
        value["plan"]["versioning"]["target"] = "2.2.9"
        with self.assertRaises(ValidationError) as captured:
            validate_plan(value["plan"])
        self.assertIn("version_not_forward", {item.code for item in captured.exception.violations})

    def test_identity_expiry_must_follow_issuance(self) -> None:
        value = hydrated_fixture()
        value["plan"]["identity"]["expires_at"] = "2025-01-01T00:00:00Z"
        with self.assertRaises(ValidationError) as captured:
            validate_plan(value["plan"])
        codes = {item.code for item in captured.exception.violations}
        self.assertIn("invalid_identity_window", codes)

    def test_third_party_consent_is_mandatory(self) -> None:
        value = hydrated_fixture()
        value["plan"]["third_party_declarations"][0]["consent"] = False
        with self.assertRaises(ValidationError) as captured:
            validate_plan(value["plan"])
        codes = {item.code for item in captured.exception.violations}
        self.assertIn("third_party_consent_required", codes)

    def test_third_party_declaration_must_reference_known_capabilities(self) -> None:
        value = hydrated_fixture()
        value["plan"]["third_party_declarations"][0]["allowed_capabilities"].append("cap-unknown")
        refresh_approval(value)
        with self.assertRaises(DomainError) as captured:
            validate_plan(value["plan"])
        self.assertEqual(captured.exception.code, "unknown_declared_capability")

    def test_duplicate_capability_ids_are_rejected(self) -> None:
        value = hydrated_fixture()
        value["plan"]["capabilities"].append(dict(value["plan"]["capabilities"][0]))
        refresh_approval(value)
        with self.assertRaises(DomainError) as captured:
            validate_plan(value["plan"])
        self.assertEqual(captured.exception.code, "duplicate_item")

    def test_wave_percentages_must_increase(self) -> None:
        value = hydrated_fixture()
        value["plan"]["rollout"]["waves"][1]["target_percentage"] = 20.0
        refresh_approval(value)
        with self.assertRaises(DomainError) as captured:
            validate_plan(value["plan"])
        self.assertEqual(captured.exception.code, "invalid_wave_percentages")

    def test_final_wave_must_reach_full_fleet(self) -> None:
        value = hydrated_fixture()
        value["plan"]["rollout"]["waves"][-1]["target_percentage"] = 95.0
        refresh_approval(value)
        with self.assertRaises(DomainError) as captured:
            validate_plan(value["plan"])
        self.assertEqual(captured.exception.code, "invalid_wave_percentages")

    def test_approval_scope_detects_capability_tampering(self) -> None:
        value = hydrated_fixture()
        original = value["plan"]["approval"]["scope_digest"]
        value["plan"]["capabilities"][0]["description"] = "changed after approval"
        self.assertEqual(value["plan"]["approval"]["scope_digest"], original)
        with self.assertRaises(DomainError) as captured:
            validate_plan(value["plan"])
        self.assertEqual(captured.exception.code, "approval_scope_mismatch")

    def test_approval_scope_helper_matches_validated_plan(self) -> None:
        plan = validate_plan(hydrated_fixture()["plan"])
        self.assertEqual(approval_scope_digest(plan), fingerprint(plan_scope_payload(plan)))

    def test_artifact_digests_must_match_plan(self) -> None:
        value = hydrated_fixture()
        plan = validate_plan(value["plan"])
        value["artifact"]["artifact_digest"] = tamper_digest(value["artifact"]["artifact_digest"])
        with self.assertRaises(DomainError) as captured:
            validate_artifact(value["artifact"], plan)
        self.assertEqual(captured.exception.code, "artifact_digest_mismatch")

    def test_artifact_version_must_match_target(self) -> None:
        value = hydrated_fixture()
        plan = validate_plan(value["plan"])
        value["artifact"]["version"] = "2.5.0"
        with self.assertRaises(DomainError) as captured:
            validate_artifact(value["artifact"], plan)
        self.assertEqual(captured.exception.code, "artifact_version_mismatch")

    def test_duplicate_artifact_file_paths_are_rejected(self) -> None:
        value = hydrated_fixture()
        value["artifact"]["files"].append(dict(value["artifact"]["files"][0]))
        plan = validate_plan(value["plan"])
        with self.assertRaises(DomainError) as captured:
            validate_artifact(value["artifact"], plan)
        self.assertEqual(captured.exception.code, "duplicate_item")

    def test_artifact_summary_is_traceable(self) -> None:
        value = hydrated_fixture()
        plan = validate_plan(value["plan"])
        artifact = validate_artifact(value["artifact"], plan)
        summary = describe_contract(plan, artifact)
        self.assertEqual(summary["identity_code"], "agent-cn-ota-002")
        self.assertEqual(summary["version_transition"], "2.3.0->2.4.0")
        self.assertEqual(summary["capability_count"], 3)
        self.assertGreater(summary["artifact_bytes"], 2_000_000)
        self.assertIn('"plan_id":"plan-ota-fixture-002"', summary["canonical_contract"])

    def test_hydration_generates_stable_digests(self) -> None:
        first = hydrate_scenario(cloned_fixture())
        second = hydrate_scenario(cloned_fixture())
        self.assertEqual(first["artifact"]["artifact_digest"], second["artifact"]["artifact_digest"])
        self.assertEqual(first["artifact"]["manifest_digest"], second["artifact"]["manifest_digest"])
        self.assertEqual(first["plan"]["approval"]["scope_digest"], second["plan"]["approval"]["scope_digest"])

    def test_invalid_signature_algorithm_is_rejected(self) -> None:
        value = hydrated_fixture()
        value["plan"]["third_party_declarations"][0]["signature_algorithm"] = "md5"
        with self.assertRaises(ValidationError) as captured:
            validate_plan(value["plan"])
        self.assertIn("invalid_choice", {item.code for item in captured.exception.violations})

    def test_failure_budget_fraction_is_bounded(self) -> None:
        value = hydrated_fixture()
        value["plan"]["failure_budget"]["maximum_failed_fraction"] = 1.2
        with self.assertRaises(ValidationError) as captured:
            validate_plan(value["plan"])
        self.assertIn("number_too_large", {item.code for item in captured.exception.violations})

    def test_health_thresholds_require_valid_availability(self) -> None:
        value = hydrated_fixture()
        value["plan"]["health_thresholds"]["minimum_availability"] = -0.1
        with self.assertRaises(ValidationError) as captured:
            validate_plan(value["plan"])
        self.assertIn("number_too_small", {item.code for item in captured.exception.violations})

    def test_unknown_dependency_capability_is_rejected(self) -> None:
        value = hydrated_fixture()
        value["plan"]["dependencies"][0]["predecessor"] = "cap-missing"
        refresh_approval(value)
        with self.assertRaises(DomainError) as captured:
            validate_plan(value["plan"])
        self.assertEqual(captured.exception.code, "unknown_dependency_capability")


if __name__ == "__main__":
    unittest.main()
