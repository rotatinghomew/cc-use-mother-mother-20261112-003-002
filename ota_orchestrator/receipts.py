from __future__ import annotations

from collections import Counter
from typing import Any, Mapping

from .domain import (
    fingerprint,
    parse_time,
    require_choice,
    require_digest,
    require_identifier,
    require_int,
    require_mapping,
    require_string,
)
from .errors import ConflictError, ReceiptError
from .repository import Repository


RECEIPT_KINDS = (
    "download_started",
    "install_started",
    "install_completed",
    "install_failed",
    "rollback_started",
    "rollback_completed",
    "rollback_failed",
)


TRANSITIONS: dict[str, dict[str, str]] = {
    "download_started": {"scheduled": "downloading", "downloading": "downloading"},
    "install_started": {"scheduled": "installing", "downloading": "installing", "installing": "installing"},
    "install_completed": {"installing": "installed", "installed": "installed"},
    "install_failed": {
        "scheduled": "failed",
        "downloading": "failed",
        "installing": "failed",
        "failed": "failed",
    },
    "rollback_started": {"installed": "rolling_back", "failed": "rolling_back", "rolling_back": "rolling_back"},
    "rollback_completed": {"rolling_back": "rolled_back", "rolled_back": "rolled_back"},
    "rollback_failed": {"rolling_back": "rollback_failed", "rollback_failed": "rollback_failed"},
}


TERMINAL_KINDS = {"install_completed", "install_failed", "rollback_completed", "rollback_failed"}


def validate_receipt(value: Any) -> dict[str, Any]:
    source = require_mapping(value, "receipt")
    payload = require_mapping(source.get("payload", {}), "receipt.payload")
    result = {
        "receipt_id": require_identifier(source.get("receipt_id"), "receipt.receipt_id"),
        "release_id": require_identifier(source.get("release_id"), "receipt.release_id"),
        "device_id": require_identifier(source.get("device_id"), "receipt.device_id"),
        "wave_id": require_identifier(source.get("wave_id"), "receipt.wave_id"),
        "kind": require_choice(source.get("kind"), "receipt.kind", RECEIPT_KINDS),
        "sequence": require_int(source.get("sequence"), "receipt.sequence", minimum=1),
        "occurred_at": parse_time(source.get("occurred_at"), "receipt.occurred_at").isoformat(),
        "received_at": parse_time(source.get("received_at"), "receipt.received_at").isoformat(),
        "payload": {str(key): item for key, item in sorted(payload.items())},
        "signature_digest": require_digest(source.get("signature_digest"), "receipt.signature_digest"),
    }
    if parse_time(result["received_at"]) < parse_time(result["occurred_at"]):
        raise ReceiptError("receipt_received_before_occurrence", "receipt received time cannot precede occurrence")
    result["payload_digest"] = fingerprint(result["payload"])
    return result


def _event_for(receipt: Mapping[str, Any], disposition: str) -> dict[str, Any]:
    return {
        "event_id": f"receipt:{receipt['receipt_id']}:{disposition}",
        "event_type": "receipt_recorded",
        "occurred_at": receipt["received_at"],
        "actor": f"device:{receipt['device_id']}",
        "details": {
            "receipt_id": receipt["receipt_id"],
            "device_id": receipt["device_id"],
            "wave_id": receipt["wave_id"],
            "kind": receipt["kind"],
            "sequence": receipt["sequence"],
            "disposition": disposition,
            "payload_digest": receipt["payload_digest"],
        },
    }


def _conflicting_terminal(repository: Repository, receipt: Mapping[str, Any]) -> dict[str, Any] | None:
    if receipt["kind"] not in TERMINAL_KINDS:
        return None
    family = "install" if receipt["kind"].startswith("install") else "rollback"
    for existing in repository.list_receipts(receipt["release_id"], receipt["device_id"]):
        other = existing["receipt"]
        if other["kind"] in TERMINAL_KINDS and other["kind"].startswith(family) and other["kind"] != receipt["kind"]:
            return existing
    return None


def process_receipt(repository: Repository, value: Any) -> dict[str, Any]:
    receipt = validate_receipt(value)
    existing = repository.get_receipt(receipt["release_id"], receipt["receipt_id"])
    if existing:
        if existing["receipt"] == receipt:
            return {"status": "duplicate", "receipt": receipt, "device_state": repository.get_device_state(receipt["release_id"], receipt["device_id"])}
        raise ConflictError(
            "receipt_id_conflict",
            "receipt id was reused with different content",
            details={"receipt_id": receipt["receipt_id"]},
        )
    release = repository.get_release(receipt["release_id"])
    device = repository.get_device_state(receipt["release_id"], receipt["device_id"])
    if device["wave_id"] != receipt["wave_id"]:
        raise ReceiptError("receipt_wave_mismatch", "receipt wave does not match scheduled device wave")
    conflict = _conflicting_terminal(repository, receipt)
    if conflict:
        with repository.transaction():
            repository.insert_receipt(
                receipt["release_id"], receipt, "conflict", conflict_with=conflict["receipt_id"]
            )
            repository.append_audit(receipt["release_id"], _event_for(receipt, "conflict"))
        return {
            "status": "conflict",
            "receipt": receipt,
            "conflict_with": conflict["receipt_id"],
            "device_state": device,
        }
    allowed = TRANSITIONS[receipt["kind"]]
    if device["state"] not in allowed:
        if _is_late_receipt(device, receipt):
            with repository.transaction():
                repository.insert_receipt(receipt["release_id"], receipt, "late")
                repository.append_audit(receipt["release_id"], _event_for(receipt, "late"))
            return {"status": "late", "receipt": receipt, "device_state": device}
        reason = f"state {device['state']} cannot accept {receipt['kind']}"
        with repository.transaction():
            repository.queue_pending_receipt(receipt["release_id"], receipt, reason)
            repository.append_audit(receipt["release_id"], _event_for(receipt, "pending"))
        return {"status": "pending", "receipt": receipt, "reason": reason, "device_state": device}
    target_state = allowed[device["state"]]
    updates: dict[str, Any] = {
        "state": target_state,
        "last_receipt_at": receipt["occurred_at"],
        "attempts": device["attempts"] + (1 if receipt["kind"] == "install_started" else 0),
    }
    if receipt["kind"] == "install_completed":
        installed_version = require_string(receipt["payload"].get("installed_version"), "receipt.payload.installed_version")
        if installed_version != release["plan"]["versioning"]["target"]:
            raise ReceiptError("installed_version_mismatch", "completion receipt reports an unexpected version")
        updates["installed_version"] = installed_version
        updates["failure_code"] = None
    elif receipt["kind"] == "install_failed":
        updates["failure_code"] = require_identifier(receipt["payload"].get("failure_code"), "receipt.payload.failure_code")
    elif receipt["kind"] == "rollback_completed":
        rollback_version = require_string(receipt["payload"].get("rollback_version"), "receipt.payload.rollback_version")
        if rollback_version != release["plan"]["versioning"]["current"]:
            raise ReceiptError("rollback_version_mismatch", "rollback receipt reports an unexpected version")
        updates["rollback_version"] = rollback_version
    elif receipt["kind"] == "rollback_failed":
        updates["failure_code"] = require_identifier(receipt["payload"].get("failure_code"), "receipt.payload.failure_code")
    with repository.transaction():
        repository.insert_receipt(receipt["release_id"], receipt, "applied")
        repository.update_device(receipt["release_id"], receipt["device_id"], **updates)
        repository.append_audit(receipt["release_id"], _event_for(receipt, "applied"))
    drain = drain_pending_receipts(repository, receipt["release_id"], receipt["device_id"])
    return {
        "status": "applied",
        "receipt": receipt,
        "device_state": repository.get_device_state(receipt["release_id"], receipt["device_id"]),
        "drained": drain,
    }


def _is_late_receipt(device: Mapping[str, Any], receipt: Mapping[str, Any]) -> bool:
    if device["last_receipt_at"] is None:
        return False
    if parse_time(receipt["occurred_at"]) < parse_time(device["last_receipt_at"]):
        return True
    if device["state"] in {"installed", "rolled_back", "rollback_failed"}:
        return True
    return False


def drain_pending_receipts(repository: Repository, release_id: str, device_id: str | None = None) -> list[str]:
    applied: list[str] = []
    progress = True
    while progress:
        progress = False
        pending = repository.list_pending_receipts(release_id)
        for item in pending:
            receipt = item["receipt"]
            if device_id and receipt["device_id"] != device_id:
                continue
            device = repository.get_device_state(release_id, receipt["device_id"])
            allowed = TRANSITIONS[receipt["kind"]]
            if device["state"] not in allowed:
                continue
            with repository.transaction():
                repository.delete_pending_receipt(release_id, receipt["receipt_id"])
            result = process_receipt(repository, receipt)
            if result["status"] == "applied":
                applied.append(receipt["receipt_id"])
                progress = True
                break
    return applied


def receipt_summary(repository: Repository, release_id: str, wave_id: str | None = None) -> dict[str, Any]:
    receipts = repository.list_receipts(release_id)
    if wave_id:
        receipts = [item for item in receipts if item["wave_id"] == wave_id]
    dispositions = Counter(item["disposition"] for item in receipts)
    kinds = Counter(item["kind"] for item in receipts)
    pending = repository.list_pending_receipts(release_id)
    if wave_id:
        pending = [item for item in pending if item["receipt"]["wave_id"] == wave_id]
    return {
        "receipt_count": len(receipts),
        "dispositions": dict(sorted(dispositions.items())),
        "kinds": dict(sorted(kinds.items())),
        "pending_count": len(pending),
        "pending_ids": [item["receipt_id"] for item in pending],
        "conflict_ids": [item["receipt_id"] for item in receipts if item["disposition"] == "conflict"],
        "late_ids": [item["receipt_id"] for item in receipts if item["disposition"] == "late"],
    }

