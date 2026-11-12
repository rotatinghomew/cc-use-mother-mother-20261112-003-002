from __future__ import annotations

from typing import Any, Mapping

from .domain import (
    Version,
    fingerprint,
    parse_time,
    require_bool,
    require_choice,
    require_digest,
    require_identifier,
    require_int,
    require_list,
    require_mapping,
    require_number,
    require_string,
    stable_json,
    unique_items,
)
from .errors import DomainError, ValidationError, Violation


RISK_LEVELS = ("low", "medium", "high", "critical")
CHANNELS = ("internal", "beta", "stable", "regulated")
TOOL_MODES = ("read", "write", "execute", "delegate")
SIGNATURE_ALGORITHMS = ("sha256-rsa", "sha256-ecdsa", "ed25519")
DEPENDENCY_TYPES = ("requires", "after", "conflicts")


def _capture(violations: list[Violation], callback: Any, fallback: Any = None) -> Any:
    try:
        return callback()
    except DomainError as exc:
        violations.append(Violation(exc.code, exc.message, exc.path, exc.details))
        return fallback


def validate_identity(value: Any, path: str = "plan.identity") -> dict[str, Any]:
    source = require_mapping(value, path)
    identity_code = require_identifier(source.get("identity_code"), f"{path}.identity_code")
    issuer = require_identifier(source.get("issuer"), f"{path}.issuer")
    model_family = require_identifier(source.get("model_family"), f"{path}.model_family")
    issued_at = parse_time(source.get("issued_at"), f"{path}.issued_at")
    expires_at = parse_time(source.get("expires_at"), f"{path}.expires_at")
    if expires_at <= issued_at:
        raise DomainError("invalid_identity_window", "identity expiry must follow issuance", path=path)
    return {
        "identity_code": identity_code,
        "issuer": issuer,
        "model_family": model_family,
        "issued_at": issued_at.isoformat(),
        "expires_at": expires_at.isoformat(),
        "certificate_digest": require_digest(source.get("certificate_digest"), f"{path}.certificate_digest"),
    }


def validate_versioning(value: Any, path: str = "plan.versioning") -> dict[str, Any]:
    source = require_mapping(value, path)
    current = Version.parse(source.get("current"), f"{path}.current")
    target = Version.parse(source.get("target"), f"{path}.target")
    minimum_bootloader = Version.parse(source.get("minimum_bootloader"), f"{path}.minimum_bootloader")
    if target.release_key() <= current.release_key():
        raise DomainError("version_not_forward", "target version must be newer than current version", path=path)
    return {
        "current": source["current"],
        "target": source["target"],
        "minimum_bootloader": source["minimum_bootloader"],
        "artifact_digest": require_digest(source.get("artifact_digest"), f"{path}.artifact_digest"),
        "manifest_digest": require_digest(source.get("manifest_digest"), f"{path}.manifest_digest"),
    }


def validate_approval(value: Any, path: str = "plan.approval") -> dict[str, Any]:
    source = require_mapping(value, path)
    approved_at = parse_time(source.get("approved_at"), f"{path}.approved_at")
    return {
        "approval_id": require_identifier(source.get("approval_id"), f"{path}.approval_id"),
        "reviewer": require_identifier(source.get("reviewer"), f"{path}.reviewer"),
        "approved_at": approved_at.isoformat(),
        "scope_digest": require_digest(source.get("scope_digest"), f"{path}.scope_digest"),
        "decision": require_choice(source.get("decision"), f"{path}.decision", ("approved", "conditionally_approved")),
        "conditions": [
            require_string(item, f"{path}.conditions[{index}]", maximum=512)
            for index, item in enumerate(require_list(source.get("conditions", []), f"{path}.conditions"))
        ],
    }


def validate_capability(value: Any, index: int) -> dict[str, Any]:
    path = f"plan.capabilities[{index}]"
    source = require_mapping(value, path)
    controls = [
        require_identifier(item, f"{path}.controls[{control_index}]")
        for control_index, item in enumerate(require_list(source.get("controls"), f"{path}.controls", minimum=1))
    ]
    return {
        "capability_id": require_identifier(source.get("capability_id"), f"{path}.capability_id"),
        "description": require_string(source.get("description"), f"{path}.description", maximum=1024),
        "risk_level": require_choice(source.get("risk_level"), f"{path}.risk_level", RISK_LEVELS),
        "tool_modes": [
            require_choice(item, f"{path}.tool_modes[{mode_index}]", TOOL_MODES)
            for mode_index, item in enumerate(require_list(source.get("tool_modes"), f"{path}.tool_modes", minimum=1))
        ],
        "controls": sorted(set(controls)),
        "user_confirmation_required": require_bool(
            source.get("user_confirmation_required"), f"{path}.user_confirmation_required"
        ),
    }


def validate_third_party(value: Any, index: int) -> dict[str, Any]:
    path = f"plan.third_party_declarations[{index}]"
    source = require_mapping(value, path)
    consent = require_bool(source.get("consent"), f"{path}.consent")
    if not consent:
        raise DomainError("third_party_consent_required", "third-party declaration must explicitly consent", path=path)
    declared_at = parse_time(source.get("declared_at"), f"{path}.declared_at")
    expires_at = parse_time(source.get("expires_at"), f"{path}.expires_at")
    if expires_at <= declared_at:
        raise DomainError("invalid_declaration_window", "third-party declaration expiry must follow declaration", path=path)
    return {
        "application_id": require_identifier(source.get("application_id"), f"{path}.application_id"),
        "consent": consent,
        "declared_at": declared_at.isoformat(),
        "expires_at": expires_at.isoformat(),
        "signature_algorithm": require_choice(
            source.get("signature_algorithm"), f"{path}.signature_algorithm", SIGNATURE_ALGORITHMS
        ),
        "signature_digest": require_digest(source.get("signature_digest"), f"{path}.signature_digest"),
        "allowed_capabilities": sorted(
            require_identifier(item, f"{path}.allowed_capabilities[{capability_index}]")
            for capability_index, item in enumerate(
                require_list(source.get("allowed_capabilities"), f"{path}.allowed_capabilities", minimum=1)
            )
        ),
    }


def validate_wave_policy(value: Any, index: int) -> dict[str, Any]:
    path = f"plan.rollout.waves[{index}]"
    source = require_mapping(value, path)
    target_percentage = require_number(
        source.get("target_percentage"), f"{path}.target_percentage", minimum=0.01, maximum=100.0
    )
    return {
        "name": require_identifier(source.get("name"), f"{path}.name"),
        "target_percentage": target_percentage,
        "minimum_observation_minutes": require_int(
            source.get("minimum_observation_minutes"), f"{path}.minimum_observation_minutes", minimum=1, maximum=10080
        ),
        "maximum_parallel_devices": require_int(
            source.get("maximum_parallel_devices"), f"{path}.maximum_parallel_devices", minimum=1, maximum=100000
        ),
        "requires_checkpoint": require_bool(source.get("requires_checkpoint"), f"{path}.requires_checkpoint"),
    }


def validate_dependency(value: Any, index: int) -> dict[str, Any]:
    path = f"plan.dependencies[{index}]"
    source = require_mapping(value, path)
    predecessor = require_identifier(source.get("predecessor"), f"{path}.predecessor")
    successor = require_identifier(source.get("successor"), f"{path}.successor")
    if predecessor == successor:
        raise DomainError("self_dependency", "dependency cannot reference the same capability twice", path=path)
    return {
        "predecessor": predecessor,
        "successor": successor,
        "type": require_choice(source.get("type"), f"{path}.type", DEPENDENCY_TYPES),
        "reason": require_string(source.get("reason"), f"{path}.reason", maximum=512),
    }


def validate_thresholds(value: Any, path: str = "plan.health_thresholds") -> dict[str, Any]:
    source = require_mapping(value, path)
    return {
        "minimum_sample_size": require_int(source.get("minimum_sample_size"), f"{path}.minimum_sample_size", minimum=1),
        "minimum_success_rate": require_number(
            source.get("minimum_success_rate"), f"{path}.minimum_success_rate", minimum=0.0, maximum=1.0
        ),
        "maximum_failure_rate": require_number(
            source.get("maximum_failure_rate"), f"{path}.maximum_failure_rate", minimum=0.0, maximum=1.0
        ),
        "maximum_rollback_rate": require_number(
            source.get("maximum_rollback_rate"), f"{path}.maximum_rollback_rate", minimum=0.0, maximum=1.0
        ),
        "maximum_error_rate_delta": require_number(
            source.get("maximum_error_rate_delta"), f"{path}.maximum_error_rate_delta", minimum=0.0, maximum=1.0
        ),
        "maximum_p95_latency_delta_ms": require_number(
            source.get("maximum_p95_latency_delta_ms"), f"{path}.maximum_p95_latency_delta_ms", minimum=0.0
        ),
        "minimum_availability": require_number(
            source.get("minimum_availability"), f"{path}.minimum_availability", minimum=0.0, maximum=1.0
        ),
        "maximum_privilege_denial_delta": require_number(
            source.get("maximum_privilege_denial_delta"), f"{path}.maximum_privilege_denial_delta", minimum=0.0, maximum=1.0
        ),
        "minimum_metric_coverage": require_number(
            source.get("minimum_metric_coverage"), f"{path}.minimum_metric_coverage", minimum=0.0, maximum=1.0
        ),
    }


def validate_failure_budget(value: Any, path: str = "plan.failure_budget") -> dict[str, Any]:
    source = require_mapping(value, path)
    return {
        "maximum_failed_devices": require_int(
            source.get("maximum_failed_devices"), f"{path}.maximum_failed_devices", minimum=0
        ),
        "maximum_failed_fraction": require_number(
            source.get("maximum_failed_fraction"), f"{path}.maximum_failed_fraction", minimum=0.0, maximum=1.0
        ),
        "maximum_consecutive_failures": require_int(
            source.get("maximum_consecutive_failures"), f"{path}.maximum_consecutive_failures", minimum=1
        ),
        "critical_cohort_failures": require_int(
            source.get("critical_cohort_failures"), f"{path}.critical_cohort_failures", minimum=0
        ),
    }


def validate_plan(value: Any) -> dict[str, Any]:
    source = require_mapping(value, "plan")
    violations: list[Violation] = []
    plan_id = _capture(violations, lambda: require_identifier(source.get("plan_id"), "plan.plan_id"), "invalid")
    title = _capture(violations, lambda: require_string(source.get("title"), "plan.title", maximum=256), "invalid")
    channel = _capture(violations, lambda: require_choice(source.get("channel"), "plan.channel", CHANNELS), "invalid")
    identity = _capture(violations, lambda: validate_identity(source.get("identity")), {})
    versioning = _capture(violations, lambda: validate_versioning(source.get("versioning")), {})
    approval = _capture(violations, lambda: validate_approval(source.get("approval")), {})
    capabilities_input = _capture(violations, lambda: require_list(source.get("capabilities"), "plan.capabilities", minimum=1), [])
    capabilities = [
        _capture(violations, lambda item=item, index=index: validate_capability(item, index), {})
        for index, item in enumerate(capabilities_input)
    ]
    declarations_input = _capture(
        violations,
        lambda: require_list(source.get("third_party_declarations"), "plan.third_party_declarations", minimum=1),
        [],
    )
    declarations = [
        _capture(violations, lambda item=item, index=index: validate_third_party(item, index), {})
        for index, item in enumerate(declarations_input)
    ]
    rollout_source = _capture(violations, lambda: require_mapping(source.get("rollout"), "plan.rollout"), {})
    waves_input = _capture(
        violations,
        lambda: require_list(rollout_source.get("waves"), "plan.rollout.waves", minimum=1),
        [],
    )
    waves = [
        _capture(violations, lambda item=item, index=index: validate_wave_policy(item, index), {})
        for index, item in enumerate(waves_input)
    ]
    dependencies_input = _capture(
        violations, lambda: require_list(source.get("dependencies", []), "plan.dependencies"), []
    )
    dependencies = [
        _capture(violations, lambda item=item, index=index: validate_dependency(item, index), {})
        for index, item in enumerate(dependencies_input)
    ]
    thresholds = _capture(violations, lambda: validate_thresholds(source.get("health_thresholds")), {})
    budget = _capture(violations, lambda: validate_failure_budget(source.get("failure_budget")), {})
    rollback_window_minutes = _capture(
        violations,
        lambda: require_int(source.get("rollback_window_minutes"), "plan.rollback_window_minutes", minimum=1, maximum=43200),
        0,
    )
    if violations:
        raise ValidationError(violations)
    capabilities = unique_items(capabilities, lambda item: item["capability_id"], "plan.capabilities")
    declarations = unique_items(declarations, lambda item: item["application_id"], "plan.third_party_declarations")
    waves = unique_items(waves, lambda item: item["name"], "plan.rollout.waves")
    percentages = [wave["target_percentage"] for wave in waves]
    if percentages != sorted(percentages) or percentages[-1] != 100.0:
        raise DomainError(
            "invalid_wave_percentages",
            "wave target percentages must be increasing and end at 100",
            path="plan.rollout.waves",
        )
    capability_ids = {item["capability_id"] for item in capabilities}
    for declaration in declarations:
        unknown = sorted(set(declaration["allowed_capabilities"]) - capability_ids)
        if unknown:
            raise DomainError(
                "unknown_declared_capability",
                "third-party declaration references unknown capabilities",
                details={"application_id": declaration["application_id"], "unknown": unknown},
            )
    for dependency in dependencies:
        unknown = sorted({dependency["predecessor"], dependency["successor"]} - capability_ids)
        if unknown:
            raise DomainError("unknown_dependency_capability", "dependency references unknown capabilities", details={"unknown": unknown})
    scope_payload = {
        "identity": identity,
        "versioning": versioning,
        "capabilities": capabilities,
        "third_party_declarations": declarations,
        "dependencies": dependencies,
    }
    if approval["scope_digest"] != fingerprint(scope_payload):
        raise DomainError("approval_scope_mismatch", "approval scope digest does not match the validated plan scope")
    return {
        "plan_id": plan_id,
        "title": title,
        "channel": channel,
        "identity": identity,
        "versioning": versioning,
        "approval": approval,
        "capabilities": capabilities,
        "third_party_declarations": declarations,
        "dependencies": dependencies,
        "rollout": {"waves": waves},
        "health_thresholds": thresholds,
        "failure_budget": budget,
        "rollback_window_minutes": rollback_window_minutes,
        "plan_fingerprint": fingerprint({key: source[key] for key in sorted(source)}),
    }


def validate_artifact(value: Any, plan: Mapping[str, Any]) -> dict[str, Any]:
    source = require_mapping(value, "artifact")
    files = require_list(source.get("files"), "artifact.files", minimum=1)
    normalized_files: list[dict[str, Any]] = []
    total_size = 0
    for index, item in enumerate(files):
        path = f"artifact.files[{index}]"
        file_source = require_mapping(item, path)
        size = require_int(file_source.get("size"), f"{path}.size", minimum=1)
        total_size += size
        normalized_files.append(
            {
                "path": require_string(file_source.get("path"), f"{path}.path", maximum=512),
                "digest": require_digest(file_source.get("digest"), f"{path}.digest"),
                "size": size,
                "kind": require_choice(
                    file_source.get("kind"), f"{path}.kind", ("agent", "manifest", "policy", "resource")
                ),
            }
        )
    unique_items(normalized_files, lambda item: item["path"], "artifact.files")
    artifact_digest = require_digest(source.get("artifact_digest"), "artifact.artifact_digest")
    manifest_digest = require_digest(source.get("manifest_digest"), "artifact.manifest_digest")
    if artifact_digest != plan["versioning"]["artifact_digest"]:
        raise DomainError("artifact_digest_mismatch", "artifact digest does not match the plan")
    if manifest_digest != plan["versioning"]["manifest_digest"]:
        raise DomainError("manifest_digest_mismatch", "manifest digest does not match the plan")
    signing = require_mapping(source.get("signing"), "artifact.signing")
    signed_at = parse_time(signing.get("signed_at"), "artifact.signing.signed_at")
    result = {
        "artifact_id": require_identifier(source.get("artifact_id"), "artifact.artifact_id"),
        "version": require_string(source.get("version"), "artifact.version"),
        "artifact_digest": artifact_digest,
        "manifest_digest": manifest_digest,
        "files": normalized_files,
        "total_size": total_size,
        "signing": {
            "signer": require_identifier(signing.get("signer"), "artifact.signing.signer"),
            "algorithm": require_choice(signing.get("algorithm"), "artifact.signing.algorithm", SIGNATURE_ALGORITHMS),
            "signature_digest": require_digest(signing.get("signature_digest"), "artifact.signing.signature_digest"),
            "signed_at": signed_at.isoformat(),
        },
        "provenance": require_string(source.get("provenance"), "artifact.provenance", maximum=1024),
    }
    if result["version"] != plan["versioning"]["target"]:
        raise DomainError("artifact_version_mismatch", "artifact version does not match target version")
    result["artifact_fingerprint"] = fingerprint(result)
    return result


def plan_scope_payload(plan: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "identity": plan["identity"],
        "versioning": plan["versioning"],
        "capabilities": plan["capabilities"],
        "third_party_declarations": plan["third_party_declarations"],
        "dependencies": plan["dependencies"],
    }


def approval_scope_digest(plan: Mapping[str, Any]) -> str:
    return fingerprint(plan_scope_payload(plan))


def describe_contract(plan: Mapping[str, Any], artifact: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "plan_id": plan["plan_id"],
        "identity_code": plan["identity"]["identity_code"],
        "version_transition": f"{plan['versioning']['current']}->{plan['versioning']['target']}",
        "capability_count": len(plan["capabilities"]),
        "third_party_count": len(plan["third_party_declarations"]),
        "artifact_id": artifact["artifact_id"],
        "artifact_bytes": artifact["total_size"],
        "contract_digest": fingerprint({"plan": plan, "artifact": artifact}),
        "canonical_contract": stable_json({"plan": plan, "artifact": artifact}),
    }

