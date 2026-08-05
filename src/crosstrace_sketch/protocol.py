"""Narrow paired-receipt feasibility sketch for a synthetic payment action.

The module deliberately implements a small, inspectable protocol surface.  It
does not provide a production identity system, distributed consensus, global
replay protection, or evidence that the mechanism improves safety.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
import secrets
import sqlite3
import threading
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


PROTOCOL_VERSION = "crosstrace-sketch/0.1"
SCOPE_PROFILE = "payment-v1"
MAX_SAFE_INTEGER = (2**53) - 1
_DOMAIN_PREFIX = b"CROSSTRACE-SKETCH\x00"
_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$")
_HASH_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_CURRENCY_RE = re.compile(r"^[A-Z]{3}$")
_TIMESTAMP_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
_SIGNATURE_RE = re.compile(r"^[A-Za-z0-9_-]{86}$")


class ProtocolError(ValueError):
    """Raised when an object is outside the sketch's deterministic profile."""


class _ReplayDetected(RuntimeError):
    pass


class _EvidenceConflict(RuntimeError):
    pass


def _require_exact_keys(value: Mapping[str, Any], expected: set[str], name: str) -> None:
    actual = set(value)
    if actual != expected:
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        raise ProtocolError(f"{name} keys differ; missing={missing}, extra={extra}")


def _require_identifier(value: Any, name: str) -> str:
    if not isinstance(value, str) or not _ID_RE.fullmatch(value):
        raise ProtocolError(f"{name} must be a bounded ASCII identifier")
    return value


def _parse_timestamp(value: Any, name: str) -> datetime:
    if not isinstance(value, str) or not _TIMESTAMP_RE.fullmatch(value):
        raise ProtocolError(f"{name} must be a UTC timestamp with second precision")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError as exc:
        raise ProtocolError(f"{name} is not a real timestamp") from exc


def format_timestamp(value: datetime) -> str:
    """Return the protocol's UTC, second-precision timestamp format."""

    if value.tzinfo is None:
        raise ProtocolError("timestamps must be timezone-aware")
    return value.astimezone(UTC).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")


def _validate_canonical_value(value: Any, path: str = "$") -> None:
    if value is None or isinstance(value, bool):
        return
    if type(value) is int:
        if not -MAX_SAFE_INTEGER <= value <= MAX_SAFE_INTEGER:
            raise ProtocolError(f"{path} integer is outside the interoperable range")
        return
    if isinstance(value, float):
        raise ProtocolError(f"{path} floating-point values are prohibited")
    if isinstance(value, str):
        if any(ord(character) < 0x20 or ord(character) > 0x7E for character in value):
            raise ProtocolError(f"{path} strings must use printable ASCII")
        return
    if isinstance(value, list):
        for index, child in enumerate(value):
            _validate_canonical_value(child, f"{path}[{index}]")
        return
    if isinstance(value, dict):
        for key, child in value.items():
            if not isinstance(key, str):
                raise ProtocolError(f"{path} object keys must be strings")
            _validate_canonical_value(key, f"{path}.<key>")
            _validate_canonical_value(child, f"{path}.{key}")
        return
    raise ProtocolError(f"{path} has unsupported type {type(value).__name__}")


def canonical_json(value: Any) -> bytes:
    """Encode the sketch's strict deterministic JSON subset.

    All strings are printable ASCII, all numbers are interoperable-range
    integers, object keys are sorted, and insignificant whitespace is absent.
    This is intentionally described as a local profile, not as full RFC 8785.
    """

    _validate_canonical_value(value)
    return json.dumps(
        value,
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")


def loads_strict(raw: str | bytes) -> Any:
    """Parse JSON while rejecting duplicate keys and profile violations."""

    def object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ProtocolError(f"duplicate JSON key: {key}")
            result[key] = value
        return result

    try:
        value = json.loads(raw, object_pairs_hook=object_pairs)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ProtocolError("invalid JSON") from exc
    _validate_canonical_value(value)
    return value


def _domain_bytes(label: str, value: Any) -> bytes:
    return _DOMAIN_PREFIX + label.encode("ascii") + b"\x00" + canonical_json(value)


def content_id(label: str, value: Any) -> str:
    """Return a domain-separated SHA-256 identifier."""

    return "sha256:" + hashlib.sha256(_domain_bytes(label, value)).hexdigest()


def _encode_signature(signature: bytes) -> str:
    return base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=")


def _decode_signature(signature: Any) -> bytes:
    if not isinstance(signature, str) or not _SIGNATURE_RE.fullmatch(signature):
        raise ProtocolError("signature must be unpadded base64url Ed25519 bytes")
    try:
        decoded = base64.urlsafe_b64decode(signature + "==")
    except (ValueError, TypeError) as exc:
        raise ProtocolError("invalid base64url signature") from exc
    if len(decoded) != 64:
        raise ProtocolError("Ed25519 signatures must contain 64 bytes")
    if _encode_signature(decoded) != signature:
        raise ProtocolError("signature must use canonical unpadded base64url encoding")
    return decoded


def _sign(label: str, value: Any, private_key: Ed25519PrivateKey) -> str:
    return _encode_signature(private_key.sign(_domain_bytes(label, value)))


def _verify(label: str, value: Any, signature: Any, public_key: Ed25519PublicKey) -> None:
    public_key.verify(_decode_signature(signature), _domain_bytes(label, value))


def _validate_party(party: Any, name: str) -> None:
    if not isinstance(party, dict):
        raise ProtocolError(f"{name} must be an object")
    _require_exact_keys(party, {"principal_id", "agent_id", "key_id"}, name)
    _require_identifier(party["principal_id"], f"{name}.principal_id")
    _require_identifier(party["agent_id"], f"{name}.agent_id")
    _require_identifier(party["key_id"], f"{name}.key_id")


def _validate_scope(scope: Any) -> None:
    if not isinstance(scope, dict):
        raise ProtocolError("scope must be an object")
    _require_exact_keys(
        scope,
        {
            "operations",
            "resources",
            "currency",
            "max_amount_minor",
            "not_before",
            "not_after",
            "redelegations_remaining",
        },
        "scope",
    )
    for field in ("operations", "resources"):
        values = scope[field]
        if not isinstance(values, list) or not values:
            raise ProtocolError(f"scope.{field} must be a non-empty list")
        for index, value in enumerate(values):
            _require_identifier(value, f"scope.{field}[{index}]")
        if values != sorted(set(values)):
            raise ProtocolError(f"scope.{field} must be sorted and unique")
    if not isinstance(scope["currency"], str) or not _CURRENCY_RE.fullmatch(scope["currency"]):
        raise ProtocolError("scope.currency must be a three-letter uppercase code")
    if type(scope["max_amount_minor"]) is not int or not 0 <= scope["max_amount_minor"] <= MAX_SAFE_INTEGER:
        raise ProtocolError("scope.max_amount_minor must be a non-negative integer")
    not_before = _parse_timestamp(scope["not_before"], "scope.not_before")
    not_after = _parse_timestamp(scope["not_after"], "scope.not_after")
    if not_before >= not_after:
        raise ProtocolError("scope.not_before must precede scope.not_after")
    remaining = scope["redelegations_remaining"]
    if type(remaining) is not int or not 0 <= remaining <= 32:
        raise ProtocolError("scope.redelegations_remaining must be between 0 and 32")


def make_scope(
    *,
    operations: Iterable[str],
    resources: Iterable[str],
    currency: str,
    max_amount_minor: int,
    not_before: str,
    not_after: str,
    redelegations_remaining: int,
) -> dict[str, Any]:
    """Construct and validate a structured payment-v1 scope."""

    scope = {
        "operations": sorted(set(operations)),
        "resources": sorted(set(resources)),
        "currency": currency,
        "max_amount_minor": max_amount_minor,
        "not_before": not_before,
        "not_after": not_after,
        "redelegations_remaining": redelegations_remaining,
    }
    _validate_scope(scope)
    return scope


def _validate_action(action: Any) -> None:
    if not isinstance(action, dict):
        raise ProtocolError("action must be an object")
    _require_exact_keys(
        action,
        {
            "protocol_version",
            "type",
            "action_nonce",
            "operation",
            "resource",
            "currency",
            "amount_minor",
        },
        "action",
    )
    if action["protocol_version"] != PROTOCOL_VERSION or action["type"] != "payment_action":
        raise ProtocolError("unsupported action type or protocol version")
    _require_identifier(action["action_nonce"], "action.action_nonce")
    _require_identifier(action["operation"], "action.operation")
    _require_identifier(action["resource"], "action.resource")
    if not isinstance(action["currency"], str) or not _CURRENCY_RE.fullmatch(action["currency"]):
        raise ProtocolError("action.currency must be a three-letter uppercase code")
    if type(action["amount_minor"]) is not int or not 0 <= action["amount_minor"] <= MAX_SAFE_INTEGER:
        raise ProtocolError("action.amount_minor must be a non-negative integer")


def make_action(
    *,
    action_nonce: str,
    operation: str,
    resource: str,
    currency: str,
    amount_minor: int,
) -> dict[str, Any]:
    action = {
        "protocol_version": PROTOCOL_VERSION,
        "type": "payment_action",
        "action_nonce": action_nonce,
        "operation": operation,
        "resource": resource,
        "currency": currency,
        "amount_minor": amount_minor,
    }
    _validate_action(action)
    return action


def action_id(action: Mapping[str, Any]) -> str:
    _validate_action(action)
    return content_id("ACTION", action)


def _validate_authority(authority: Any) -> None:
    if not isinstance(authority, dict):
        raise ProtocolError("authority must be an object")
    _require_exact_keys(
        authority,
        {
            "issuer_principal_id",
            "subject_principal_id",
            "subject_key_id",
            "authority_version",
            "revocation_status_id",
        },
        "authority",
    )
    _require_identifier(authority["issuer_principal_id"], "authority.issuer_principal_id")
    _require_identifier(authority["subject_principal_id"], "authority.subject_principal_id")
    _require_identifier(authority["subject_key_id"], "authority.subject_key_id")
    if type(authority["authority_version"]) is not int or authority["authority_version"] < 1:
        raise ProtocolError("authority.authority_version must be a positive integer")
    if not isinstance(authority["revocation_status_id"], str) or not _HASH_RE.fullmatch(
        authority["revocation_status_id"]
    ):
        raise ProtocolError("authority.revocation_status_id must be a SHA-256 identifier")


def _validate_proposal(proposal: Any) -> None:
    if not isinstance(proposal, dict):
        raise ProtocolError("proposal must be an object")
    _require_exact_keys(
        proposal,
        {
            "protocol_version",
            "type",
            "interaction_id",
            "event_type",
            "created_at",
            "nonce",
            "sender",
            "receiver",
            "sender_sequence",
            "previous_receipt_id",
            "scope_profile",
            "scope",
            "authority",
            "request_hash",
        },
        "proposal",
    )
    if proposal["protocol_version"] != PROTOCOL_VERSION or proposal["type"] != "handoff_proposal":
        raise ProtocolError("unsupported proposal type or protocol version")
    if proposal["event_type"] not in {"delegation", "action_intent"}:
        raise ProtocolError("proposal.event_type is unsupported")
    _require_identifier(proposal["interaction_id"], "proposal.interaction_id")
    _require_identifier(proposal["nonce"], "proposal.nonce")
    _parse_timestamp(proposal["created_at"], "proposal.created_at")
    _validate_party(proposal["sender"], "proposal.sender")
    _validate_party(proposal["receiver"], "proposal.receiver")
    sequence = proposal["sender_sequence"]
    if type(sequence) is not int or not 0 <= sequence <= MAX_SAFE_INTEGER:
        raise ProtocolError("proposal.sender_sequence must be a non-negative integer")
    parent_id = proposal["previous_receipt_id"]
    if parent_id is not None and (not isinstance(parent_id, str) or not _HASH_RE.fullmatch(parent_id)):
        raise ProtocolError("proposal.previous_receipt_id must be null or a SHA-256 identifier")
    if proposal["scope_profile"] != SCOPE_PROFILE:
        raise ProtocolError("unsupported scope profile")
    _validate_scope(proposal["scope"])
    _validate_authority(proposal["authority"])
    if not isinstance(proposal["request_hash"], str) or not _HASH_RE.fullmatch(proposal["request_hash"]):
        raise ProtocolError("proposal.request_hash must be a SHA-256 identifier")
    canonical_json(proposal)


def make_proposal(
    *,
    interaction_id: str,
    event_type: str,
    created_at: str,
    nonce: str,
    sender: Mapping[str, str],
    receiver: Mapping[str, str],
    sender_sequence: int,
    previous_receipt_id: str | None,
    scope: Mapping[str, Any],
    authority: Mapping[str, Any],
    request_hash: str,
) -> dict[str, Any]:
    proposal = {
        "protocol_version": PROTOCOL_VERSION,
        "type": "handoff_proposal",
        "interaction_id": interaction_id,
        "event_type": event_type,
        "created_at": created_at,
        "nonce": nonce,
        "sender": dict(sender),
        "receiver": dict(receiver),
        "sender_sequence": sender_sequence,
        "previous_receipt_id": previous_receipt_id,
        "scope_profile": SCOPE_PROFILE,
        "scope": dict(scope),
        "authority": dict(authority),
        "request_hash": request_hash,
    }
    _validate_proposal(proposal)
    return proposal


def sign_receipt(
    proposal: Mapping[str, Any],
    *,
    sender_private_key: Ed25519PrivateKey,
    receiver_private_key: Ed25519PrivateKey,
    receiver_decision: str,
    decided_at: str,
    reason_code: str | None = None,
) -> dict[str, Any]:
    """Create both attestations over one byte-identical handoff proposal."""

    proposal_dict = dict(proposal)
    _validate_proposal(proposal_dict)
    if receiver_decision not in {"ACCEPT", "REJECT"}:
        raise ProtocolError("receiver_decision must be ACCEPT or REJECT")
    if receiver_decision == "ACCEPT" and reason_code is not None:
        raise ProtocolError("an accepted receipt must not contain a reason_code")
    if receiver_decision == "REJECT":
        _require_identifier(reason_code, "reason_code")
    _parse_timestamp(decided_at, "decided_at")

    proposal_hash = content_id("PROPOSAL", proposal_dict)
    sender_attestation_body = {
        "algorithm": "Ed25519",
        "key_id": proposal_dict["sender"]["key_id"],
        "proposal_hash": proposal_hash,
    }
    sender_attestation = {
        **sender_attestation_body,
        "signature": _sign("SENDER_ATTESTATION", sender_attestation_body, sender_private_key),
    }
    receiver_attestation_body = {
        "algorithm": "Ed25519",
        "key_id": proposal_dict["receiver"]["key_id"],
        "proposal_hash": proposal_hash,
        "sender_attestation": sender_attestation,
        "decision": receiver_decision,
        "reason_code": reason_code,
        "decided_at": decided_at,
    }
    receiver_attestation = {
        **receiver_attestation_body,
        "signature": _sign("RECEIVER_ATTESTATION", receiver_attestation_body, receiver_private_key),
    }
    receipt = {
        "proposal": proposal_dict,
        "proposal_hash": proposal_hash,
        "sender_attestation": sender_attestation,
        "receiver_attestation": receiver_attestation,
    }
    canonical_json(receipt)
    return receipt


def receipt_id(receipt: Mapping[str, Any]) -> str:
    return content_id("COMPLETED_RECEIPT", receipt)


def sign_authority_status(
    *,
    issuer_principal_id: str,
    issuer_key_id: str,
    subject_principal_id: str,
    subject_key_id: str,
    authority_version: int,
    state: str,
    issued_at: str,
    fresh_until: str,
    issuer_private_key: Ed25519PrivateKey,
) -> dict[str, Any]:
    """Create a principal-signed status for one delegated authority."""

    status = {
        "protocol_version": PROTOCOL_VERSION,
        "type": "authority_status",
        "issuer_principal_id": issuer_principal_id,
        "issuer_key_id": issuer_key_id,
        "subject_principal_id": subject_principal_id,
        "subject_key_id": subject_key_id,
        "authority_version": authority_version,
        "state": state,
        "issued_at": issued_at,
        "fresh_until": fresh_until,
    }
    _validate_status_payload(status)
    status_id = content_id("AUTHORITY_STATUS", status)
    attestation_body = {
        "algorithm": "Ed25519",
        "key_id": issuer_key_id,
        "status_id": status_id,
    }
    return {
        "status_id": status_id,
        "status": status,
        "attestation": {
            **attestation_body,
            "signature": _sign("AUTHORITY_STATUS_ATTESTATION", attestation_body, issuer_private_key),
        },
    }


def _validate_status_payload(status: Any) -> None:
    if not isinstance(status, dict):
        raise ProtocolError("authority status payload must be an object")
    _require_exact_keys(
        status,
        {
            "protocol_version",
            "type",
            "issuer_principal_id",
            "issuer_key_id",
            "subject_principal_id",
            "subject_key_id",
            "authority_version",
            "state",
            "issued_at",
            "fresh_until",
        },
        "authority status payload",
    )
    if status["protocol_version"] != PROTOCOL_VERSION or status["type"] != "authority_status":
        raise ProtocolError("unsupported authority status type or protocol version")
    for field in (
        "issuer_principal_id",
        "issuer_key_id",
        "subject_principal_id",
        "subject_key_id",
    ):
        _require_identifier(status[field], f"status.{field}")
    if type(status["authority_version"]) is not int or status["authority_version"] < 1:
        raise ProtocolError("status.authority_version must be a positive integer")
    if status["state"] not in {"ACTIVE", "REVOKED"}:
        raise ProtocolError("status.state must be ACTIVE or REVOKED")
    issued = _parse_timestamp(status["issued_at"], "status.issued_at")
    fresh_until = _parse_timestamp(status["fresh_until"], "status.fresh_until")
    if issued >= fresh_until:
        raise ProtocolError("status.issued_at must precede status.fresh_until")
    canonical_json(status)


@dataclass(frozen=True)
class _TrustedKey:
    principal_id: str
    public_key: Ed25519PublicKey
    roles: frozenset[str]


class KeyRegistry:
    """Explicit local mapping from key IDs to principals and public keys."""

    def __init__(self) -> None:
        self._keys: dict[str, _TrustedKey] = {}

    def add(
        self,
        *,
        principal_id: str,
        key_id: str,
        public_key: Ed25519PublicKey,
        roles: Iterable[str],
    ) -> None:
        _require_identifier(principal_id, "principal_id")
        _require_identifier(key_id, "key_id")
        role_set = frozenset(roles)
        if not role_set or not role_set.issubset({"receipt", "status"}):
            raise ProtocolError("key roles must be a non-empty subset of receipt and status")
        existing = self._keys.get(key_id)
        candidate = _TrustedKey(principal_id, public_key, role_set)
        if existing is not None and existing != candidate:
            raise ProtocolError(f"key_id already registered: {key_id}")
        self._keys[key_id] = candidate

    def resolve(self, *, principal_id: str, key_id: str, required_role: str) -> Ed25519PublicKey:
        if required_role not in {"receipt", "status"}:
            raise ProtocolError("unsupported key role")
        record = self._keys.get(key_id)
        if (
            record is None
            or record.principal_id != principal_id
            or required_role not in record.roles
        ):
            raise KeyError(key_id)
        return record.public_key


@dataclass(frozen=True)
class GateDecision:
    verdict: str
    reasons: tuple[str, ...]
    receipt_id: str | None = None
    permit_id: str | None = None
    permit_expires_at: str | None = None

    @property
    def allowed(self) -> bool:
        return self.verdict == "ALLOW"

    def to_dict(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict,
            "reasons": list(self.reasons),
            "receipt_id": self.receipt_id,
            "permit_id": self.permit_id,
            "permit_expires_at": self.permit_expires_at,
        }


@dataclass(frozen=True)
class ConsumeResult:
    verdict: str
    reason: str | None
    permit_id: str

    @property
    def allowed(self) -> bool:
        return self.verdict == "ALLOW"

    def to_dict(self) -> dict[str, Any]:
        return {"verdict": self.verdict, "reason": self.reason, "permit_id": self.permit_id}


class PermitStore:
    """SQLite-backed local replay reservation and single-attempt permit state."""

    def __init__(self, path: str | Path) -> None:
        self.path = str(path)
        self._lock = threading.Lock()
        self._connection = sqlite3.connect(self.path, timeout=5.0, check_same_thread=False)
        self._connection.execute("PRAGMA foreign_keys = ON")
        self._connection.execute("PRAGMA journal_mode = WAL")
        self._connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS observations (
                observation_kind TEXT NOT NULL,
                observation_key TEXT NOT NULL,
                receipt_id TEXT NOT NULL,
                PRIMARY KEY (observation_kind, observation_key)
            );
            CREATE TABLE IF NOT EXISTS permits (
                permit_id TEXT PRIMARY KEY,
                leaf_receipt_id TEXT NOT NULL,
                replay_scope TEXT NOT NULL,
                request_hash TEXT NOT NULL,
                action_nonce TEXT NOT NULL,
                tool_id TEXT NOT NULL,
                state TEXT NOT NULL CHECK (state IN ('RESERVED', 'ATTEMPTED', 'SUCCEEDED', 'FAILED')),
                issued_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                UNIQUE (tool_id, replay_scope, action_nonce)
            );
            """
        )
        self._connection.commit()

    def close(self) -> None:
        with self._lock:
            self._connection.close()

    def reserve(
        self,
        *,
        receipts: Sequence[Mapping[str, Any]],
        leaf_receipt_id: str,
        replay_scope: str,
        request_hash: str,
        action_nonce: str,
        tool_id: str,
        issued_at: str,
        expires_at: str,
    ) -> str:
        permit_id = "permit_" + secrets.token_urlsafe(32)
        with self._lock:
            cursor = self._connection.cursor()
            try:
                cursor.execute("BEGIN IMMEDIATE")
                for receipt in receipts:
                    current_id = receipt_id(receipt)
                    proposal = receipt["proposal"]
                    observations = (
                        ("interaction", proposal["interaction_id"]),
                        (
                            "sender_sequence",
                            f"{proposal['sender']['key_id']}:{proposal['sender_sequence']}",
                        ),
                    )
                    for kind, key in observations:
                        row = cursor.execute(
                            "SELECT receipt_id FROM observations WHERE observation_kind = ? AND observation_key = ?",
                            (kind, key),
                        ).fetchone()
                        if row is not None and row[0] != current_id:
                            raise _EvidenceConflict(f"{kind}:{key}")
                        cursor.execute(
                            "INSERT OR IGNORE INTO observations(observation_kind, observation_key, receipt_id) VALUES (?, ?, ?)",
                            (kind, key, current_id),
                        )
                try:
                    cursor.execute(
                        """
                        INSERT INTO permits(
                            permit_id, leaf_receipt_id, replay_scope, request_hash, action_nonce,
                            tool_id, state, issued_at, expires_at
                        ) VALUES (?, ?, ?, ?, ?, ?, 'RESERVED', ?, ?)
                        """,
                        (
                            permit_id,
                            leaf_receipt_id,
                            replay_scope,
                            request_hash,
                            action_nonce,
                            tool_id,
                            issued_at,
                            expires_at,
                        ),
                    )
                except sqlite3.IntegrityError as exc:
                    raise _ReplayDetected from exc
                self._connection.commit()
                return permit_id
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
    ) -> ConsumeResult:
        with self._lock:
            cursor = self._connection.cursor()
            try:
                cursor.execute("BEGIN IMMEDIATE")
                row = cursor.execute(
                    "SELECT tool_id, request_hash, action_nonce, state, expires_at FROM permits WHERE permit_id = ?",
                    (permit_id,),
                ).fetchone()
                if row is None or row[0] != tool_id:
                    self._connection.rollback()
                    return ConsumeResult("PAUSE", "PERMIT_INVALID", permit_id)
                if row[1] != request_hash or row[2] != action_nonce:
                    self._connection.rollback()
                    return ConsumeResult("PAUSE", "PERMIT_ACTION_MISMATCH", permit_id)
                if row[3] != "RESERVED":
                    self._connection.rollback()
                    return ConsumeResult("PAUSE", "REPLAY_DETECTED", permit_id)
                if now >= _parse_timestamp(row[4], "permit.expires_at"):
                    self._connection.rollback()
                    return ConsumeResult("PAUSE", "PERMIT_EXPIRED", permit_id)
                cursor.execute(
                    "UPDATE permits SET state = 'ATTEMPTED' WHERE permit_id = ? AND state = 'RESERVED'",
                    (permit_id,),
                )
                if cursor.rowcount != 1:
                    self._connection.rollback()
                    return ConsumeResult("PAUSE", "REPLAY_DETECTED", permit_id)
                self._connection.commit()
                return ConsumeResult("ALLOW", None, permit_id)
            except Exception:
                self._connection.rollback()
                raise
            finally:
                cursor.close()

    def finish(self, *, permit_id: str, succeeded: bool) -> bool:
        target = "SUCCEEDED" if succeeded else "FAILED"
        with self._lock, self._connection:
            cursor = self._connection.execute(
                "UPDATE permits SET state = ? WHERE permit_id = ? AND state = 'ATTEMPTED'",
                (target, permit_id),
            )
            return cursor.rowcount == 1


def _same_party(left: Mapping[str, Any], right: Mapping[str, Any]) -> bool:
    return all(left[field] == right[field] for field in ("principal_id", "agent_id", "key_id"))


def _scope_is_attenuated(parent: Mapping[str, Any], child: Mapping[str, Any]) -> bool:
    return (
        set(child["operations"]).issubset(parent["operations"])
        and set(child["resources"]).issubset(parent["resources"])
        and child["currency"] == parent["currency"]
        and child["max_amount_minor"] <= parent["max_amount_minor"]
        and _parse_timestamp(child["not_before"], "scope.not_before")
        >= _parse_timestamp(parent["not_before"], "scope.not_before")
        and _parse_timestamp(child["not_after"], "scope.not_after")
        <= _parse_timestamp(parent["not_after"], "scope.not_after")
        and child["redelegations_remaining"] < parent["redelegations_remaining"]
    )


def _action_within_scope(action: Mapping[str, Any], scope: Mapping[str, Any]) -> bool:
    return (
        action["operation"] in scope["operations"]
        and action["resource"] in scope["resources"]
        and action["currency"] == scope["currency"]
        and action["amount_minor"] <= scope["max_amount_minor"]
    )


def _deduplicate(reasons: Iterable[str]) -> tuple[str, ...]:
    return tuple(dict.fromkeys(reasons))


class ActionGate:
    """Fail-closed local checker for the synthetic payment-v1 profile."""

    def __init__(self, *, registry: KeyRegistry, permit_store: PermitStore) -> None:
        self.registry = registry
        self.permit_store = permit_store

    def _verify_receipt(self, receipt: Any) -> list[str]:
        reasons: list[str] = []
        try:
            if not isinstance(receipt, dict):
                raise ProtocolError("receipt must be an object")
            _require_exact_keys(
                receipt,
                {"proposal", "proposal_hash", "sender_attestation", "receiver_attestation"},
                "receipt",
            )
            _validate_proposal(receipt["proposal"])
            expected_hash = content_id("PROPOSAL", receipt["proposal"])
            if receipt["proposal_hash"] != expected_hash:
                reasons.append("DIGEST_MISMATCH")

            sender_attestation = receipt["sender_attestation"]
            if not isinstance(sender_attestation, dict):
                raise ProtocolError("sender_attestation must be an object")
            _require_exact_keys(
                sender_attestation,
                {"algorithm", "key_id", "proposal_hash", "signature"},
                "sender_attestation",
            )
            sender = receipt["proposal"]["sender"]
            if (
                sender_attestation["algorithm"] != "Ed25519"
                or sender_attestation["key_id"] != sender["key_id"]
                or sender_attestation["proposal_hash"] != expected_hash
            ):
                reasons.append("SENDER_ATTESTATION_MISMATCH")
            try:
                sender_public = self.registry.resolve(
                    principal_id=sender["principal_id"],
                    key_id=sender["key_id"],
                    required_role="receipt",
                )
            except KeyError:
                reasons.append("UNTRUSTED_SENDER_KEY")
            else:
                sender_body = {
                    "algorithm": sender_attestation["algorithm"],
                    "key_id": sender_attestation["key_id"],
                    "proposal_hash": sender_attestation["proposal_hash"],
                }
                try:
                    _verify(
                        "SENDER_ATTESTATION",
                        sender_body,
                        sender_attestation["signature"],
                        sender_public,
                    )
                except (InvalidSignature, ProtocolError):
                    reasons.append("SENDER_SIGNATURE_INVALID")

            receiver_attestation = receipt["receiver_attestation"]
            if not isinstance(receiver_attestation, dict):
                raise ProtocolError("receiver_attestation must be an object")
            _require_exact_keys(
                receiver_attestation,
                {
                    "algorithm",
                    "key_id",
                    "proposal_hash",
                    "sender_attestation",
                    "decision",
                    "reason_code",
                    "decided_at",
                    "signature",
                },
                "receiver_attestation",
            )
            receiver = receipt["proposal"]["receiver"]
            if (
                receiver_attestation["algorithm"] != "Ed25519"
                or receiver_attestation["key_id"] != receiver["key_id"]
                or receiver_attestation["proposal_hash"] != expected_hash
                or receiver_attestation["sender_attestation"] != sender_attestation
            ):
                reasons.append("RECEIVER_ATTESTATION_MISMATCH")
            if receiver_attestation["decision"] not in {"ACCEPT", "REJECT"}:
                raise ProtocolError("unsupported receiver decision")
            if receiver_attestation["decision"] == "ACCEPT" and receiver_attestation["reason_code"] is not None:
                raise ProtocolError("accepted receipt has a reason code")
            if receiver_attestation["decision"] == "REJECT":
                _require_identifier(receiver_attestation["reason_code"], "receiver reason_code")
                reasons.append("RECEIVER_REJECTED")
            _parse_timestamp(receiver_attestation["decided_at"], "receiver decided_at")
            try:
                receiver_public = self.registry.resolve(
                    principal_id=receiver["principal_id"],
                    key_id=receiver["key_id"],
                    required_role="receipt",
                )
            except KeyError:
                reasons.append("UNTRUSTED_RECEIVER_KEY")
            else:
                receiver_body = {
                    field: receiver_attestation[field]
                    for field in (
                        "algorithm",
                        "key_id",
                        "proposal_hash",
                        "sender_attestation",
                        "decision",
                        "reason_code",
                        "decided_at",
                    )
                }
                try:
                    _verify(
                        "RECEIVER_ATTESTATION",
                        receiver_body,
                        receiver_attestation["signature"],
                        receiver_public,
                    )
                except (InvalidSignature, ProtocolError):
                    reasons.append("RECEIVER_SIGNATURE_INVALID")
            canonical_json(receipt)
        except (KeyError, TypeError, ProtocolError):
            reasons.append("SCHEMA_INVALID")
        return reasons

    def _verify_status(self, signed_status: Any) -> tuple[list[str], Mapping[str, Any] | None, str | None]:
        reasons: list[str] = []
        try:
            if not isinstance(signed_status, dict):
                raise ProtocolError("signed authority status must be an object")
            _require_exact_keys(signed_status, {"status_id", "status", "attestation"}, "signed status")
            status = signed_status["status"]
            _validate_status_payload(status)
            expected_id = content_id("AUTHORITY_STATUS", status)
            if signed_status["status_id"] != expected_id:
                reasons.append("STATUS_DIGEST_MISMATCH")
            attestation = signed_status["attestation"]
            if not isinstance(attestation, dict):
                raise ProtocolError("status attestation must be an object")
            _require_exact_keys(
                attestation,
                {"algorithm", "key_id", "status_id", "signature"},
                "status attestation",
            )
            if (
                attestation["algorithm"] != "Ed25519"
                or attestation["key_id"] != status["issuer_key_id"]
                or attestation["status_id"] != expected_id
            ):
                reasons.append("STATUS_ATTESTATION_MISMATCH")
            try:
                public_key = self.registry.resolve(
                    principal_id=status["issuer_principal_id"],
                    key_id=status["issuer_key_id"],
                    required_role="status",
                )
            except KeyError:
                reasons.append("UNTRUSTED_STATUS_KEY")
            else:
                body = {
                    "algorithm": attestation["algorithm"],
                    "key_id": attestation["key_id"],
                    "status_id": attestation["status_id"],
                }
                try:
                    _verify("AUTHORITY_STATUS_ATTESTATION", body, attestation["signature"], public_key)
                except (InvalidSignature, ProtocolError):
                    reasons.append("STATUS_SIGNATURE_INVALID")
            canonical_json(signed_status)
            return reasons, status, expected_id
        except (KeyError, TypeError, ProtocolError):
            return [*reasons, "STATUS_INVALID"], None, None

    def authorize(
        self,
        *,
        receipt_chain: Sequence[Mapping[str, Any]],
        current_authority_status: Mapping[str, Any],
        action: Mapping[str, Any],
        now: datetime,
        tool_id: str = "simulated-payment-adapter",
        permit_ttl_seconds: int = 60,
    ) -> GateDecision:
        """Validate supplied evidence and reserve one local action attempt."""

        leaf_id: str | None = None
        try:
            if now.tzinfo is None:
                raise ProtocolError("now must be timezone-aware")
            now = now.astimezone(UTC).replace(microsecond=0)
            _require_identifier(tool_id, "tool_id")
            if not 1 <= permit_ttl_seconds <= 300:
                raise ProtocolError("permit_ttl_seconds must be between 1 and 300")
            _validate_action(action)
            if not receipt_chain:
                return GateDecision("PAUSE", ("MISSING_RECEIPT",))

            receipts = list(receipt_chain)
            receipt_ids = [receipt_id(receipt) for receipt in receipts]
            leaf_id = receipt_ids[-1]
            reasons: list[str] = []
            for receipt in receipts:
                reasons.extend(self._verify_receipt(receipt))
            if reasons:
                return GateDecision("PAUSE", _deduplicate(reasons), leaf_id)

            proposals = [receipt["proposal"] for receipt in receipts]
            if len(set(receipt_ids)) != len(receipt_ids):
                reasons.append("CHAIN_CYCLE")
            if proposals[0]["previous_receipt_id"] is not None:
                reasons.append("PARENT_MISSING")
            if proposals[0]["event_type"] != "delegation":
                reasons.append("ROOT_NOT_DELEGATION")
            if proposals[-1]["event_type"] != "action_intent":
                reasons.append("LEAF_NOT_ACTION_INTENT")

            root_authority = proposals[0]["authority"]
            if (
                root_authority["issuer_principal_id"] != proposals[0]["sender"]["principal_id"]
                or root_authority["subject_principal_id"] != proposals[0]["receiver"]["principal_id"]
                or root_authority["subject_key_id"] != proposals[0]["receiver"]["key_id"]
            ):
                reasons.append("ROOT_AUTHORITY_MISMATCH")

            authority_core = {
                key: root_authority[key]
                for key in (
                    "issuer_principal_id",
                    "subject_principal_id",
                    "subject_key_id",
                    "authority_version",
                )
            }
            for index in range(1, len(proposals)):
                parent = proposals[index - 1]
                child = proposals[index]
                if child["previous_receipt_id"] != receipt_ids[index - 1]:
                    reasons.append("PARENT_MISSING")
                if not _same_party(parent["receiver"], child["sender"]):
                    reasons.append("PARTY_CONTINUITY_BROKEN")
                child_authority = {key: child["authority"][key] for key in authority_core}
                if child_authority != authority_core:
                    reasons.append("AUTHORITY_CHAIN_MISMATCH")
                if not _scope_is_attenuated(parent["scope"], child["scope"]):
                    reasons.append("SCOPE_EXPANSION")

            status_reasons, status, status_id = self._verify_status(current_authority_status)
            reasons.extend(status_reasons)
            if status is not None:
                for field, authority_field in (
                    ("issuer_principal_id", "issuer_principal_id"),
                    ("subject_principal_id", "subject_principal_id"),
                    ("subject_key_id", "subject_key_id"),
                ):
                    if status[field] != root_authority[authority_field]:
                        reasons.append("STATUS_SUBJECT_MISMATCH")
                if status["authority_version"] != root_authority["authority_version"]:
                    reasons.append("AUTHORITY_VERSION_STALE")
                if status["state"] == "REVOKED":
                    reasons.append("AUTHORITY_REVOKED")
                if status_id != proposals[-1]["authority"]["revocation_status_id"]:
                    reasons.append("REVOCATION_STATUS_STALE")
                issued_at = _parse_timestamp(status["issued_at"], "status.issued_at")
                fresh_until = _parse_timestamp(status["fresh_until"], "status.fresh_until")
                if issued_at > now:
                    reasons.append("STATUS_NOT_YET_VALID")
                if fresh_until <= now:
                    reasons.append("STATUS_STALE")
                for proposal in proposals:
                    if (
                        proposal["authority"]["revocation_status_id"] == status_id
                        and issued_at
                        > _parse_timestamp(proposal["created_at"], "proposal.created_at")
                    ):
                        reasons.append("STATUS_CAUSAL_TIME_INVALID")

            for decision_index, proposal in enumerate(proposals):
                created_at = _parse_timestamp(proposal["created_at"], "proposal.created_at")
                decided_at = _parse_timestamp(
                    receipts[decision_index]["receiver_attestation"]["decided_at"],
                    "receiver decided_at",
                )
                if created_at > now:
                    reasons.append("NOT_YET_VALID")
                if decided_at < created_at or decided_at > now:
                    reasons.append("CAUSAL_TIME_INVALID")
                not_before = _parse_timestamp(proposal["scope"]["not_before"], "scope.not_before")
                not_after = _parse_timestamp(proposal["scope"]["not_after"], "scope.not_after")
                if now < not_before:
                    reasons.append("NOT_YET_VALID")
                if now >= not_after:
                    reasons.append("EXPIRED")

            for index in range(1, len(proposals)):
                parent_decided_at = _parse_timestamp(
                    receipts[index - 1]["receiver_attestation"]["decided_at"],
                    "parent receiver decided_at",
                )
                child_created_at = _parse_timestamp(proposals[index]["created_at"], "child created_at")
                if child_created_at < parent_decided_at:
                    reasons.append("CAUSAL_TIME_INVALID")

            if proposals[-1]["request_hash"] != action_id(action):
                reasons.append("REQUEST_HASH_MISMATCH")
            if any(not _action_within_scope(action, proposal["scope"]) for proposal in proposals):
                reasons.append("ACTION_OUT_OF_SCOPE")

            if reasons:
                return GateDecision("PAUSE", _deduplicate(reasons), leaf_id)

            scope_expiry = min(
                _parse_timestamp(proposal["scope"]["not_after"], "scope.not_after")
                for proposal in proposals
            )
            permit_expiry = min(scope_expiry, now + timedelta(seconds=permit_ttl_seconds))
            issued_at_text = format_timestamp(now)
            expires_at_text = format_timestamp(permit_expiry)
            try:
                permit_id = self.permit_store.reserve(
                    receipts=receipts,
                    leaf_receipt_id=leaf_id,
                    replay_scope=content_id("LOCAL_REPLAY_SCOPE", authority_core),
                    request_hash=proposals[-1]["request_hash"],
                    action_nonce=action["action_nonce"],
                    tool_id=tool_id,
                    issued_at=issued_at_text,
                    expires_at=expires_at_text,
                )
            except _EvidenceConflict:
                return GateDecision("PAUSE", ("CONFLICTING_RECEIPT",), leaf_id)
            except _ReplayDetected:
                return GateDecision("PAUSE", ("REPLAY_DETECTED",), leaf_id)
            except (sqlite3.Error, OSError):
                return GateDecision("PAUSE", ("STATE_UNAVAILABLE",), leaf_id)
            return GateDecision(
                "ALLOW",
                (),
                receipt_id=leaf_id,
                permit_id=permit_id,
                permit_expires_at=expires_at_text,
            )
        except (KeyError, TypeError, ProtocolError):
            return GateDecision("PAUSE", ("SCHEMA_INVALID",), leaf_id)
        except Exception:
            return GateDecision("PAUSE", ("INTERNAL_ERROR",), leaf_id)

    def consume(
        self,
        *,
        permit_id: str,
        tool_id: str,
        action: Mapping[str, Any],
        now: datetime,
    ) -> ConsumeResult:
        """Mark one local attempt before the simulated adapter acts."""

        try:
            if now.tzinfo is None:
                raise ProtocolError("now must be timezone-aware")
            _validate_action(action)
            return self.permit_store.consume(
                permit_id=permit_id,
                tool_id=tool_id,
                request_hash=action_id(action),
                action_nonce=action["action_nonce"],
                now=now.astimezone(UTC).replace(microsecond=0),
            )
        except ProtocolError:
            return ConsumeResult("PAUSE", "PERMIT_ACTION_MISMATCH", permit_id)
        except (sqlite3.Error, OSError):
            return ConsumeResult("PAUSE", "STATE_UNAVAILABLE", permit_id)
        except Exception:
            return ConsumeResult("PAUSE", "INTERNAL_ERROR", permit_id)
