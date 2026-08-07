"""SQLite-backed representation-neutral permit and replay state."""

from __future__ import annotations

import secrets
import sqlite3
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Callable, Sequence

from .model import (
    GateError,
    NeutralObservationRecord,
    NeutralPermitRecord,
    NeutralPermitStateSnapshot,
    ObservationKind,
    PermitLifecycle,
    PermitTransitionResult,
    format_timestamp,
    parse_timestamp,
    require_identifier,
)


class ReplayDetected(RuntimeError):
    """The local neutral replay key is already reserved."""


class EvidenceConflict(RuntimeError):
    """A stored interaction or sender sequence names another handoff."""


class StateChanged(RuntimeError):
    """The supplied decision-time snapshot revision is no longer current."""


_INITIALIZE_LOCK = threading.Lock()


class NeutralPermitStore:
    """Durable local permit state with revision-checked atomic reservation."""

    def __init__(
        self,
        path: str | Path,
        *,
        permit_store_id: str,
        permit_id_factory: Callable[[], str] | None = None,
    ) -> None:
        require_identifier(permit_store_id, "permit_store_id")
        self.path = str(path)
        self.permit_store_id = permit_store_id
        if permit_id_factory is not None and not callable(permit_id_factory):
            raise GateError("permit_id_factory must be callable")
        self._permit_id_factory = permit_id_factory
        self._lock = threading.Lock()
        self._connection = sqlite3.connect(
            self.path,
            timeout=5.0,
            check_same_thread=False,
        )
        with _INITIALIZE_LOCK:
            self._connection.execute("PRAGMA busy_timeout = 5000")
            self._connection.execute("PRAGMA foreign_keys = ON")
            self._connection.execute("PRAGMA journal_mode = WAL")
            self._connection.executescript("""
            CREATE TABLE IF NOT EXISTS neutral_store_metadata (
                singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                permit_store_id TEXT NOT NULL,
                revision INTEGER NOT NULL CHECK (revision >= 0)
            );
            CREATE TABLE IF NOT EXISTS neutral_observations (
                observation_kind TEXT NOT NULL,
                observation_key TEXT NOT NULL,
                neutral_handoff_id TEXT NOT NULL,
                PRIMARY KEY (observation_kind, observation_key)
            );
            CREATE TABLE IF NOT EXISTS neutral_permits (
                permit_id TEXT PRIMARY KEY,
                leaf_neutral_handoff_id TEXT NOT NULL,
                neutral_chain_id TEXT NOT NULL,
                controlling_status_id TEXT NOT NULL,
                replay_scope_id TEXT NOT NULL,
                request_hash TEXT NOT NULL,
                action_nonce TEXT NOT NULL,
                tool_id TEXT NOT NULL,
                state TEXT NOT NULL CHECK (
                    state IN ('RESERVED', 'ATTEMPTED', 'SUCCEEDED', 'FAILED')
                ),
                issued_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                UNIQUE (tool_id, replay_scope_id, action_nonce)
            );
            """)
            try:
                self._connection.execute("BEGIN IMMEDIATE")
                self._connection.execute(
                    """
                    INSERT OR IGNORE INTO neutral_store_metadata(
                        singleton, permit_store_id, revision
                    ) VALUES (1, ?, 0)
                    """,
                    (self.permit_store_id,),
                )
                row = self._connection.execute("""
                    SELECT permit_store_id FROM neutral_store_metadata
                    WHERE singleton = 1
                    """).fetchone()
                if row is None:
                    raise sqlite3.DatabaseError(
                        "neutral permit metadata is unavailable"
                    )
                if row[0] != self.permit_store_id:
                    raise GateError(
                        "permit database belongs to another permit_store_id"
                    )
                self._connection.commit()
            except Exception:
                self._connection.rollback()
                self._connection.close()
                raise

    def close(self) -> None:
        with self._lock:
            self._connection.close()

    def snapshot(self, *, captured_at: datetime) -> NeutralPermitStateSnapshot:
        """Return one immutable neutral snapshot at a declared whole second."""

        captured_text = format_timestamp(captured_at)
        captured = parse_timestamp(captured_text, "captured_at")
        with self._lock:
            cursor = self._connection.cursor()
            try:
                cursor.execute("BEGIN")
                revision_row = cursor.execute(
                    "SELECT revision FROM neutral_store_metadata WHERE singleton = 1"
                ).fetchone()
                if revision_row is None:
                    raise sqlite3.DatabaseError(
                        "neutral permit metadata is unavailable"
                    )
                rows = cursor.execute("""
                    SELECT permit_id, leaf_neutral_handoff_id, neutral_chain_id,
                           controlling_status_id, replay_scope_id, request_hash,
                           action_nonce, tool_id, state, issued_at, expires_at
                    FROM neutral_permits
                    ORDER BY permit_id
                    """).fetchall()
                observation_rows = cursor.execute("""
                    SELECT observation_kind, observation_key, neutral_handoff_id
                    FROM neutral_observations
                    ORDER BY observation_kind, observation_key
                    """).fetchall()
                self._connection.commit()
            except Exception:
                self._connection.rollback()
                raise
            finally:
                cursor.close()
        records = tuple(
            NeutralPermitRecord(
                permit_id=row[0],
                leaf_neutral_handoff_id=row[1],
                neutral_chain_id=row[2],
                controlling_status_id=row[3],
                replay_scope_id=row[4],
                request_hash=row[5],
                action_nonce=row[6],
                tool_id=row[7],
                state=PermitLifecycle(row[8]),
                issued_at=parse_timestamp(row[9], "permit.issued_at"),
                expires_at=parse_timestamp(row[10], "permit.expires_at"),
            )
            for row in rows
        )
        observations = tuple(
            NeutralObservationRecord(
                observation_kind=ObservationKind(row[0]),
                observation_key=row[1],
                neutral_handoff_id=row[2],
            )
            for row in observation_rows
        )
        return NeutralPermitStateSnapshot(
            permit_store_id=self.permit_store_id,
            revision=revision_row[0],
            captured_at=captured,
            records=records,
            observations=observations,
        )

    def reserve(
        self,
        *,
        expected_revision: int,
        observations: Sequence[NeutralObservationRecord],
        leaf_neutral_handoff_id: str,
        neutral_chain_id: str,
        controlling_status_id: str,
        replay_scope_id: str,
        request_hash: str,
        action_nonce: str,
        tool_id: str,
        issued_at: datetime,
        expires_at: datetime,
    ) -> NeutralPermitRecord:
        """Atomically compare revision, record conflicts, and reserve once."""

        permit_id = (
            "permit_" + secrets.token_urlsafe(32)
            if self._permit_id_factory is None
            else self._permit_id_factory()
        )
        candidate = NeutralPermitRecord(
            permit_id=permit_id,
            leaf_neutral_handoff_id=leaf_neutral_handoff_id,
            neutral_chain_id=neutral_chain_id,
            controlling_status_id=controlling_status_id,
            replay_scope_id=replay_scope_id,
            request_hash=request_hash,
            action_nonce=action_nonce,
            tool_id=tool_id,
            state=PermitLifecycle.RESERVED,
            issued_at=issued_at,
            expires_at=expires_at,
        )
        if type(expected_revision) is not int or expected_revision < 0:
            raise GateError("expected_revision must be a non-negative integer")
        if not all(isinstance(item, NeutralObservationRecord) for item in observations):
            raise GateError("observations must contain NeutralObservationRecord values")

        with self._lock:
            cursor = self._connection.cursor()
            try:
                cursor.execute("BEGIN IMMEDIATE")
                revision_row = cursor.execute(
                    "SELECT revision FROM neutral_store_metadata WHERE singleton = 1"
                ).fetchone()
                if revision_row is None:
                    raise sqlite3.DatabaseError(
                        "neutral permit metadata is unavailable"
                    )
                if revision_row[0] != expected_revision:
                    raise StateChanged
                for observation in observations:
                    row = cursor.execute(
                        """
                        SELECT neutral_handoff_id FROM neutral_observations
                        WHERE observation_kind = ? AND observation_key = ?
                        """,
                        (
                            observation.observation_kind.value,
                            observation.observation_key,
                        ),
                    ).fetchone()
                    if row is not None and row[0] != observation.neutral_handoff_id:
                        raise EvidenceConflict
                    cursor.execute(
                        """
                        INSERT OR IGNORE INTO neutral_observations(
                            observation_kind, observation_key, neutral_handoff_id
                        ) VALUES (?, ?, ?)
                        """,
                        (
                            observation.observation_kind.value,
                            observation.observation_key,
                            observation.neutral_handoff_id,
                        ),
                    )
                try:
                    cursor.execute(
                        """
                        INSERT INTO neutral_permits(
                            permit_id, leaf_neutral_handoff_id, neutral_chain_id,
                            controlling_status_id, replay_scope_id, request_hash,
                            action_nonce, tool_id, state, issued_at, expires_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'RESERVED', ?, ?)
                        """,
                        (
                            candidate.permit_id,
                            candidate.leaf_neutral_handoff_id,
                            candidate.neutral_chain_id,
                            candidate.controlling_status_id,
                            candidate.replay_scope_id,
                            candidate.request_hash,
                            candidate.action_nonce,
                            candidate.tool_id,
                            format_timestamp(candidate.issued_at),
                            format_timestamp(candidate.expires_at),
                        ),
                    )
                except sqlite3.IntegrityError as exc:
                    raise ReplayDetected from exc
                cursor.execute(
                    """
                    UPDATE neutral_store_metadata SET revision = revision + 1
                    WHERE singleton = 1 AND revision = ?
                    """,
                    (expected_revision,),
                )
                if cursor.rowcount != 1:
                    raise StateChanged
                self._connection.commit()
                return candidate
            except Exception:
                self._connection.rollback()
                raise
            finally:
                cursor.close()

    def consume(
        self,
        *,
        permit_id: str,
        tool_id: str,
        request_hash: str,
        action_nonce: str,
        now: datetime,
    ) -> PermitTransitionResult:
        """Move RESERVED to ATTEMPTED before the adapter acts."""

        require_identifier(permit_id, "permit_id")
        require_identifier(tool_id, "tool_id")
        require_identifier(action_nonce, "action_nonce")
        now_text = format_timestamp(now)
        now = parse_timestamp(now_text, "now")
        with self._lock:
            cursor = self._connection.cursor()
            try:
                cursor.execute("BEGIN IMMEDIATE")
                row = cursor.execute(
                    """
                    SELECT tool_id, request_hash, action_nonce, state, issued_at,
                           expires_at
                    FROM neutral_permits WHERE permit_id = ?
                    """,
                    (permit_id,),
                ).fetchone()
                if row is None or row[0] != tool_id:
                    self._connection.rollback()
                    return PermitTransitionResult("PAUSE", "PERMIT_INVALID", permit_id)
                if row[1] != request_hash or row[2] != action_nonce:
                    self._connection.rollback()
                    return PermitTransitionResult(
                        "PAUSE",
                        "PERMIT_ACTION_MISMATCH",
                        permit_id,
                    )
                if row[3] != PermitLifecycle.RESERVED.value:
                    self._connection.rollback()
                    return PermitTransitionResult("PAUSE", "REPLAY_DETECTED", permit_id)
                if now < parse_timestamp(row[4], "permit.issued_at"):
                    self._connection.rollback()
                    return PermitTransitionResult(
                        "PAUSE",
                        "PERMIT_NOT_YET_VALID",
                        permit_id,
                    )
                if now >= parse_timestamp(row[5], "permit.expires_at"):
                    self._connection.rollback()
                    return PermitTransitionResult("PAUSE", "PERMIT_EXPIRED", permit_id)
                cursor.execute(
                    """
                    UPDATE neutral_permits SET state = 'ATTEMPTED'
                    WHERE permit_id = ? AND state = 'RESERVED'
                    """,
                    (permit_id,),
                )
                if cursor.rowcount != 1:
                    self._connection.rollback()
                    return PermitTransitionResult("PAUSE", "REPLAY_DETECTED", permit_id)
                cursor.execute(
                    "UPDATE neutral_store_metadata SET revision = revision + 1 WHERE singleton = 1"
                )
                if cursor.rowcount != 1:
                    raise sqlite3.DatabaseError(
                        "neutral permit metadata is unavailable"
                    )
                self._connection.commit()
                return PermitTransitionResult("ALLOW", None, permit_id)
            except Exception:
                self._connection.rollback()
                raise
            finally:
                cursor.close()

    def finish(self, *, permit_id: str, succeeded: bool) -> bool:
        """Record the adapter result exactly once from ATTEMPTED."""

        require_identifier(permit_id, "permit_id")
        if type(succeeded) is not bool:
            raise GateError("succeeded must be boolean")
        target = PermitLifecycle.SUCCEEDED if succeeded else PermitLifecycle.FAILED
        with self._lock:
            cursor = self._connection.cursor()
            try:
                cursor.execute("BEGIN IMMEDIATE")
                cursor.execute(
                    """
                    UPDATE neutral_permits SET state = ?
                    WHERE permit_id = ? AND state = 'ATTEMPTED'
                    """,
                    (target.value, permit_id),
                )
                if cursor.rowcount != 1:
                    self._connection.rollback()
                    return False
                cursor.execute(
                    "UPDATE neutral_store_metadata SET revision = revision + 1 WHERE singleton = 1"
                )
                if cursor.rowcount != 1:
                    raise sqlite3.DatabaseError(
                        "neutral permit metadata is unavailable"
                    )
                self._connection.commit()
                return True
            except Exception:
                self._connection.rollback()
                raise
            finally:
                cursor.close()


__all__ = [
    "EvidenceConflict",
    "NeutralPermitStore",
    "ReplayDetected",
    "StateChanged",
]
