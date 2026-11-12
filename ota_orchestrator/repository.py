from __future__ import annotations

import contextlib
import json
import os
import sqlite3
from pathlib import Path
from typing import Any, Iterator, Mapping, Sequence

from .domain import canonical_event_hash, fingerprint, stable_json
from .errors import ConflictError, IntegrityError, NotFoundError


SCHEMA = """
PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS releases (
    release_id TEXT PRIMARY KEY,
    plan_id TEXT NOT NULL,
    state TEXT NOT NULL,
    revision INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    plan_json TEXT NOT NULL,
    artifact_json TEXT NOT NULL,
    snapshot_json TEXT NOT NULL,
    dependency_json TEXT NOT NULL,
    schedule_json TEXT NOT NULL,
    active_wave_id TEXT,
    paused_reason TEXT,
    rollback_deadline TEXT,
    terminal_at TEXT,
    record_digest TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS wave_states (
    release_id TEXT NOT NULL,
    wave_id TEXT NOT NULL,
    sequence INTEGER NOT NULL,
    state TEXT NOT NULL,
    started_at TEXT,
    observation_started_at TEXT,
    completed_at TEXT,
    decision TEXT,
    decision_json TEXT,
    checkpoint_id TEXT,
    PRIMARY KEY (release_id, wave_id),
    FOREIGN KEY (release_id) REFERENCES releases(release_id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS device_states (
    release_id TEXT NOT NULL,
    device_id TEXT NOT NULL,
    wave_id TEXT NOT NULL,
    cohort_key TEXT NOT NULL,
    risk_level TEXT NOT NULL,
    state TEXT NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    last_receipt_at TEXT,
    failure_code TEXT,
    installed_version TEXT,
    rollback_version TEXT,
    PRIMARY KEY (release_id, device_id),
    FOREIGN KEY (release_id) REFERENCES releases(release_id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_device_wave ON device_states(release_id, wave_id, state);
CREATE TABLE IF NOT EXISTS receipts (
    release_id TEXT NOT NULL,
    receipt_id TEXT NOT NULL,
    device_id TEXT NOT NULL,
    wave_id TEXT NOT NULL,
    kind TEXT NOT NULL,
    occurred_at TEXT NOT NULL,
    received_at TEXT NOT NULL,
    sequence INTEGER NOT NULL,
    payload_digest TEXT NOT NULL,
    receipt_json TEXT NOT NULL,
    disposition TEXT NOT NULL,
    conflict_with TEXT,
    PRIMARY KEY (release_id, receipt_id),
    FOREIGN KEY (release_id) REFERENCES releases(release_id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_receipt_device ON receipts(release_id, device_id, occurred_at, sequence);
CREATE TABLE IF NOT EXISTS pending_receipts (
    release_id TEXT NOT NULL,
    receipt_id TEXT NOT NULL,
    dependency_reason TEXT NOT NULL,
    receipt_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (release_id, receipt_id),
    FOREIGN KEY (release_id) REFERENCES releases(release_id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS metric_samples (
    release_id TEXT NOT NULL,
    metric_id TEXT NOT NULL,
    wave_id TEXT,
    cohort_key TEXT NOT NULL,
    observed_at TEXT NOT NULL,
    sample_count INTEGER NOT NULL,
    metric_json TEXT NOT NULL,
    PRIMARY KEY (release_id, metric_id),
    FOREIGN KEY (release_id) REFERENCES releases(release_id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_metric_wave ON metric_samples(release_id, wave_id, observed_at);
CREATE TABLE IF NOT EXISTS checkpoints (
    release_id TEXT NOT NULL,
    checkpoint_id TEXT NOT NULL,
    created_at TEXT NOT NULL,
    revision INTEGER NOT NULL,
    reason TEXT NOT NULL,
    snapshot_json TEXT NOT NULL,
    snapshot_digest TEXT NOT NULL,
    PRIMARY KEY (release_id, checkpoint_id),
    FOREIGN KEY (release_id) REFERENCES releases(release_id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS audit_events (
    event_sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    release_id TEXT NOT NULL,
    event_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    occurred_at TEXT NOT NULL,
    actor TEXT NOT NULL,
    event_json TEXT NOT NULL,
    previous_hash TEXT NOT NULL,
    event_hash TEXT NOT NULL,
    UNIQUE (release_id, event_id),
    FOREIGN KEY (release_id) REFERENCES releases(release_id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_audit_release ON audit_events(release_id, event_sequence);
"""


class Repository:
    def __init__(self, path: str | os.PathLike[str]) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(str(self.path), timeout=30.0, isolation_level=None)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute("PRAGMA journal_mode=WAL")
        self.connection.execute("PRAGMA synchronous=FULL")
        self.connection.executescript(SCHEMA)

    def close(self) -> None:
        self.connection.close()

    def __enter__(self) -> "Repository":
        return self

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        self.close()

    @contextlib.contextmanager
    def transaction(self, *, immediate: bool = True) -> Iterator[sqlite3.Connection]:
        self.connection.execute("BEGIN IMMEDIATE" if immediate else "BEGIN")
        try:
            yield self.connection
        except BaseException:
            self.connection.rollback()
            raise
        else:
            self.connection.commit()

    @staticmethod
    def _dump(value: Any) -> str:
        return stable_json(value)

    @staticmethod
    def _load(value: str | None) -> Any:
        return None if value is None else json.loads(value)

    def create_release(self, record: Mapping[str, Any]) -> None:
        with self.transaction():
            try:
                self.connection.execute(
                    """
                    INSERT INTO releases(
                        release_id, plan_id, state, revision, created_at, updated_at,
                        plan_json, artifact_json, snapshot_json, dependency_json, schedule_json,
                        active_wave_id, paused_reason, rollback_deadline, terminal_at, record_digest
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        record["release_id"],
                        record["plan"]["plan_id"],
                        record["state"],
                        record["revision"],
                        record["created_at"],
                        record["updated_at"],
                        self._dump(record["plan"]),
                        self._dump(record["artifact"]),
                        self._dump(record["snapshot"]),
                        self._dump(record["dependency_graph"]),
                        self._dump(record["schedule"]),
                        record.get("active_wave_id"),
                        record.get("paused_reason"),
                        record.get("rollback_deadline"),
                        record.get("terminal_at"),
                        record["record_digest"],
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise ConflictError("release_exists", "release already exists", details={"release_id": record["release_id"]}) from exc
            for wave in record["schedule"]["waves"]:
                self.connection.execute(
                    "INSERT INTO wave_states(release_id,wave_id,sequence,state) VALUES(?,?,?,?)",
                    (record["release_id"], wave["wave_id"], wave["sequence"], "pending"),
                )
                for assignment in wave["assignments"]:
                    self.connection.execute(
                        """
                        INSERT INTO device_states(
                            release_id,device_id,wave_id,cohort_key,risk_level,state,attempts
                        ) VALUES(?,?,?,?,?,?,0)
                        """,
                        (
                            record["release_id"],
                            assignment["device_id"],
                            wave["wave_id"],
                            assignment["cohort_key"],
                            assignment["risk_level"],
                            "scheduled",
                        ),
                    )

    def get_release(self, release_id: str) -> dict[str, Any]:
        row = self.connection.execute("SELECT * FROM releases WHERE release_id=?", (release_id,)).fetchone()
        if row is None:
            raise NotFoundError("release_not_found", "release was not found", details={"release_id": release_id})
        record = {
            "release_id": row["release_id"],
            "state": row["state"],
            "revision": row["revision"],
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
            "plan": self._load(row["plan_json"]),
            "artifact": self._load(row["artifact_json"]),
            "snapshot": self._load(row["snapshot_json"]),
            "dependency_graph": self._load(row["dependency_json"]),
            "schedule": self._load(row["schedule_json"]),
            "active_wave_id": row["active_wave_id"],
            "paused_reason": row["paused_reason"],
            "rollback_deadline": row["rollback_deadline"],
            "terminal_at": row["terminal_at"],
            "record_digest": row["record_digest"],
        }
        record["waves"] = self.list_wave_states(release_id)
        record["devices"] = self.list_device_states(release_id)
        return record

    def update_release(self, record: Mapping[str, Any], expected_revision: int) -> None:
        digest = self.release_digest(record)
        cursor = self.connection.execute(
            """
            UPDATE releases SET state=?, revision=?, updated_at=?, active_wave_id=?, paused_reason=?,
                rollback_deadline=?, terminal_at=?, record_digest=?
            WHERE release_id=? AND revision=?
            """,
            (
                record["state"],
                record["revision"],
                record["updated_at"],
                record.get("active_wave_id"),
                record.get("paused_reason"),
                record.get("rollback_deadline"),
                record.get("terminal_at"),
                digest,
                record["release_id"],
                expected_revision,
            ),
        )
        if cursor.rowcount != 1:
            raise ConflictError(
                "revision_conflict",
                "release was updated by another transaction",
                details={"release_id": record["release_id"], "expected_revision": expected_revision},
            )

    def release_digest(self, record: Mapping[str, Any]) -> str:
        return fingerprint(
            {
                "release_id": record["release_id"],
                "state": record["state"],
                "revision": record["revision"],
                "created_at": record["created_at"],
                "updated_at": record["updated_at"],
                "plan": record["plan"],
                "artifact": record["artifact"],
                "snapshot": record["snapshot"],
                "dependency_graph": record["dependency_graph"],
                "schedule": record["schedule"],
                "active_wave_id": record.get("active_wave_id"),
                "paused_reason": record.get("paused_reason"),
                "rollback_deadline": record.get("rollback_deadline"),
                "terminal_at": record.get("terminal_at"),
            }
        )

    def list_wave_states(self, release_id: str) -> list[dict[str, Any]]:
        rows = self.connection.execute(
            "SELECT * FROM wave_states WHERE release_id=? ORDER BY sequence", (release_id,)
        ).fetchall()
        return [
            {
                "wave_id": row["wave_id"],
                "sequence": row["sequence"],
                "state": row["state"],
                "started_at": row["started_at"],
                "observation_started_at": row["observation_started_at"],
                "completed_at": row["completed_at"],
                "decision": row["decision"],
                "decision_details": self._load(row["decision_json"]),
                "checkpoint_id": row["checkpoint_id"],
            }
            for row in rows
        ]

    def update_wave(self, release_id: str, wave_id: str, **fields: Any) -> None:
        allowed = {
            "state",
            "started_at",
            "observation_started_at",
            "completed_at",
            "decision",
            "decision_json",
            "checkpoint_id",
        }
        unknown = set(fields) - allowed
        if unknown:
            raise ValueError(f"unknown wave fields: {sorted(unknown)}")
        if "decision_json" in fields and not isinstance(fields["decision_json"], str):
            fields["decision_json"] = self._dump(fields["decision_json"])
        assignments = ", ".join(f"{name}=?" for name in fields)
        values = list(fields.values()) + [release_id, wave_id]
        cursor = self.connection.execute(
            f"UPDATE wave_states SET {assignments} WHERE release_id=? AND wave_id=?", values
        )
        if cursor.rowcount != 1:
            raise NotFoundError("wave_not_found", "wave was not found", details={"wave_id": wave_id})

    def list_device_states(self, release_id: str, wave_id: str | None = None) -> list[dict[str, Any]]:
        sql = "SELECT * FROM device_states WHERE release_id=?"
        parameters: list[Any] = [release_id]
        if wave_id is not None:
            sql += " AND wave_id=?"
            parameters.append(wave_id)
        sql += " ORDER BY wave_id, cohort_key, device_id"
        rows = self.connection.execute(sql, parameters).fetchall()
        return [dict(row) for row in rows]

    def get_device_state(self, release_id: str, device_id: str) -> dict[str, Any]:
        row = self.connection.execute(
            "SELECT * FROM device_states WHERE release_id=? AND device_id=?", (release_id, device_id)
        ).fetchone()
        if row is None:
            raise NotFoundError("device_not_scheduled", "device is not scheduled in this release", details={"device_id": device_id})
        return dict(row)

    def update_device(self, release_id: str, device_id: str, **fields: Any) -> None:
        allowed = {
            "state",
            "attempts",
            "last_receipt_at",
            "failure_code",
            "installed_version",
            "rollback_version",
        }
        unknown = set(fields) - allowed
        if unknown:
            raise ValueError(f"unknown device fields: {sorted(unknown)}")
        assignments = ", ".join(f"{name}=?" for name in fields)
        values = list(fields.values()) + [release_id, device_id]
        cursor = self.connection.execute(
            f"UPDATE device_states SET {assignments} WHERE release_id=? AND device_id=?", values
        )
        if cursor.rowcount != 1:
            raise NotFoundError("device_not_scheduled", "device is not scheduled in this release", details={"device_id": device_id})

    def get_receipt(self, release_id: str, receipt_id: str) -> dict[str, Any] | None:
        row = self.connection.execute(
            "SELECT * FROM receipts WHERE release_id=? AND receipt_id=?", (release_id, receipt_id)
        ).fetchone()
        if row is None:
            return None
        result = dict(row)
        result["receipt"] = self._load(result.pop("receipt_json"))
        return result

    def insert_receipt(self, release_id: str, receipt: Mapping[str, Any], disposition: str, conflict_with: str | None = None) -> None:
        self.connection.execute(
            """
            INSERT INTO receipts(
                release_id,receipt_id,device_id,wave_id,kind,occurred_at,received_at,
                sequence,payload_digest,receipt_json,disposition,conflict_with
            ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                release_id,
                receipt["receipt_id"],
                receipt["device_id"],
                receipt["wave_id"],
                receipt["kind"],
                receipt["occurred_at"],
                receipt["received_at"],
                receipt["sequence"],
                receipt["payload_digest"],
                self._dump(receipt),
                disposition,
                conflict_with,
            ),
        )

    def list_receipts(self, release_id: str, device_id: str | None = None) -> list[dict[str, Any]]:
        sql = "SELECT * FROM receipts WHERE release_id=?"
        parameters: list[Any] = [release_id]
        if device_id:
            sql += " AND device_id=?"
            parameters.append(device_id)
        sql += " ORDER BY occurred_at, sequence, receipt_id"
        rows = self.connection.execute(sql, parameters).fetchall()
        result = []
        for row in rows:
            value = dict(row)
            value["receipt"] = self._load(value.pop("receipt_json"))
            result.append(value)
        return result

    def queue_pending_receipt(self, release_id: str, receipt: Mapping[str, Any], reason: str) -> None:
        self.connection.execute(
            """
            INSERT OR REPLACE INTO pending_receipts(
                release_id,receipt_id,dependency_reason,receipt_json,created_at
            ) VALUES(?,?,?,?,?)
            """,
            (release_id, receipt["receipt_id"], reason, self._dump(receipt), receipt["received_at"]),
        )

    def list_pending_receipts(self, release_id: str) -> list[dict[str, Any]]:
        rows = self.connection.execute(
            "SELECT * FROM pending_receipts WHERE release_id=? ORDER BY created_at,receipt_id", (release_id,)
        ).fetchall()
        return [
            {
                "receipt_id": row["receipt_id"],
                "dependency_reason": row["dependency_reason"],
                "receipt": self._load(row["receipt_json"]),
                "created_at": row["created_at"],
            }
            for row in rows
        ]

    def delete_pending_receipt(self, release_id: str, receipt_id: str) -> None:
        self.connection.execute(
            "DELETE FROM pending_receipts WHERE release_id=? AND receipt_id=?", (release_id, receipt_id)
        )

    def insert_metric(self, release_id: str, metric: Mapping[str, Any]) -> str:
        existing = self.connection.execute(
            "SELECT metric_json FROM metric_samples WHERE release_id=? AND metric_id=?",
            (release_id, metric["metric_id"]),
        ).fetchone()
        if existing:
            if self._load(existing["metric_json"]) == metric:
                return "duplicate"
            raise ConflictError("metric_conflict", "metric id was reused with different content", details={"metric_id": metric["metric_id"]})
        self.connection.execute(
            """
            INSERT INTO metric_samples(
                release_id,metric_id,wave_id,cohort_key,observed_at,sample_count,metric_json
            ) VALUES(?,?,?,?,?,?,?)
            """,
            (
                release_id,
                metric["metric_id"],
                metric.get("wave_id"),
                metric["cohort_key"],
                metric["observed_at"],
                metric["sample_count"],
                self._dump(metric),
            ),
        )
        return "inserted"

    def list_metrics(self, release_id: str, wave_id: str | None = None) -> list[dict[str, Any]]:
        sql = "SELECT metric_json FROM metric_samples WHERE release_id=?"
        parameters: list[Any] = [release_id]
        if wave_id is None:
            sql += " AND wave_id IS NULL"
        elif wave_id != "*":
            sql += " AND wave_id=?"
            parameters.append(wave_id)
        sql += " ORDER BY observed_at,metric_id"
        return [self._load(row["metric_json"]) for row in self.connection.execute(sql, parameters).fetchall()]

    def create_checkpoint(self, release_id: str, checkpoint: Mapping[str, Any]) -> None:
        self.connection.execute(
            """
            INSERT INTO checkpoints(
                release_id,checkpoint_id,created_at,revision,reason,snapshot_json,snapshot_digest
            ) VALUES(?,?,?,?,?,?,?)
            """,
            (
                release_id,
                checkpoint["checkpoint_id"],
                checkpoint["created_at"],
                checkpoint["revision"],
                checkpoint["reason"],
                self._dump(checkpoint["snapshot"]),
                checkpoint["snapshot_digest"],
            ),
        )

    def get_checkpoint(self, release_id: str, checkpoint_id: str) -> dict[str, Any]:
        row = self.connection.execute(
            "SELECT * FROM checkpoints WHERE release_id=? AND checkpoint_id=?", (release_id, checkpoint_id)
        ).fetchone()
        if row is None:
            raise NotFoundError("checkpoint_not_found", "checkpoint was not found", details={"checkpoint_id": checkpoint_id})
        return {
            "checkpoint_id": row["checkpoint_id"],
            "created_at": row["created_at"],
            "revision": row["revision"],
            "reason": row["reason"],
            "snapshot": self._load(row["snapshot_json"]),
            "snapshot_digest": row["snapshot_digest"],
        }

    def list_checkpoints(self, release_id: str) -> list[dict[str, Any]]:
        rows = self.connection.execute(
            "SELECT checkpoint_id,created_at,revision,reason,snapshot_digest FROM checkpoints WHERE release_id=? ORDER BY revision",
            (release_id,),
        ).fetchall()
        return [dict(row) for row in rows]

    def append_audit(self, release_id: str, event: Mapping[str, Any]) -> dict[str, Any]:
        existing = self.connection.execute(
            "SELECT event_json,event_hash FROM audit_events WHERE release_id=? AND event_id=?",
            (release_id, event["event_id"]),
        ).fetchone()
        if existing:
            existing_event = self._load(existing["event_json"])
            if existing_event != event:
                raise ConflictError("audit_event_conflict", "audit event id was reused with different content")
            return {"status": "duplicate", "event_hash": existing["event_hash"]}
        previous = self.connection.execute(
            "SELECT event_hash FROM audit_events WHERE release_id=? ORDER BY event_sequence DESC LIMIT 1",
            (release_id,),
        ).fetchone()
        previous_hash = previous["event_hash"] if previous else "0" * 64
        event_hash = canonical_event_hash(previous_hash, event)
        self.connection.execute(
            """
            INSERT INTO audit_events(
                release_id,event_id,event_type,occurred_at,actor,event_json,previous_hash,event_hash
            ) VALUES(?,?,?,?,?,?,?,?)
            """,
            (
                release_id,
                event["event_id"],
                event["event_type"],
                event["occurred_at"],
                event["actor"],
                self._dump(event),
                previous_hash,
                event_hash,
            ),
        )
        return {"status": "inserted", "event_hash": event_hash, "previous_hash": previous_hash}

    def list_audit(self, release_id: str) -> list[dict[str, Any]]:
        rows = self.connection.execute(
            "SELECT * FROM audit_events WHERE release_id=? ORDER BY event_sequence", (release_id,)
        ).fetchall()
        return [
            {
                "event_sequence": row["event_sequence"],
                "event": self._load(row["event_json"]),
                "previous_hash": row["previous_hash"],
                "event_hash": row["event_hash"],
            }
            for row in rows
        ]

    def verify_audit_chain(self, release_id: str) -> dict[str, Any]:
        previous = "0" * 64
        failures: list[dict[str, Any]] = []
        rows = self.list_audit(release_id)
        for row in rows:
            expected = canonical_event_hash(previous, row["event"])
            if row["previous_hash"] != previous or row["event_hash"] != expected:
                failures.append(
                    {
                        "event_sequence": row["event_sequence"],
                        "expected_previous": previous,
                        "actual_previous": row["previous_hash"],
                        "expected_hash": expected,
                        "actual_hash": row["event_hash"],
                    }
                )
            previous = row["event_hash"]
        return {
            "valid": not failures,
            "event_count": len(rows),
            "head_hash": previous,
            "failures": failures,
        }

    def integrity_check(self, release_id: str) -> dict[str, Any]:
        release = self.get_release(release_id)
        expected_release_digest = self.release_digest(release)
        audit = self.verify_audit_chain(release_id)
        sqlite_result = self.connection.execute("PRAGMA integrity_check").fetchone()[0]
        orphan_receipts = self.connection.execute(
            """
            SELECT COUNT(*) FROM receipts r LEFT JOIN device_states d
              ON d.release_id=r.release_id AND d.device_id=r.device_id
            WHERE r.release_id=? AND d.device_id IS NULL
            """,
            (release_id,),
        ).fetchone()[0]
        result = {
            "valid": (
                expected_release_digest == release["record_digest"]
                and audit["valid"]
                and sqlite_result == "ok"
                and orphan_receipts == 0
            ),
            "release_digest_valid": expected_release_digest == release["record_digest"],
            "expected_release_digest": expected_release_digest,
            "actual_release_digest": release["record_digest"],
            "audit": audit,
            "sqlite_integrity": sqlite_result,
            "orphan_receipts": orphan_receipts,
        }
        return result

    def require_integrity(self, release_id: str) -> dict[str, Any]:
        result = self.integrity_check(release_id)
        if not result["valid"]:
            raise IntegrityError("repository_integrity_failed", "repository integrity verification failed", details=result)
        return result

    def export_release(self, release_id: str) -> dict[str, Any]:
        return {
            "release": self.get_release(release_id),
            "receipts": self.list_receipts(release_id),
            "pending_receipts": self.list_pending_receipts(release_id),
            "metrics": self.list_metrics(release_id, "*"),
            "checkpoints": self.list_checkpoints(release_id),
            "audit": self.list_audit(release_id),
            "integrity": self.integrity_check(release_id),
        }

    def backup(self, destination: str | os.PathLike[str]) -> None:
        target_path = Path(destination)
        target_path.parent.mkdir(parents=True, exist_ok=True)
        target = sqlite3.connect(str(target_path))
        try:
            self.connection.backup(target)
        finally:
            target.close()

