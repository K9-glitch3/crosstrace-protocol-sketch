"""Representation-neutral Sprint 3 gate and permit records.

The objects in this module are development-only protocol fixtures.  They are
strict audit records, not transferable authorisation credentials.
"""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from typing import Any, Mapping

from crosstrace_sketch.protocol import canonical_json, content_id, loads_strict
from preaward.crosstrace_sprint2.model import PolicyView

COMMON_GATE_INPUT_VERSION = "crosstrace-common-gate-input/0.1"
COMMON_GATE_DECISION_VERSION = "crosstrace-common-gate-decision/0.1"
NEUTRAL_PERMIT_STATE_VERSION = "crosstrace-neutral-permit-state/0.1"
PERMIT_TRANSITION_VERSION = "crosstrace-permit-transition/0.1"
MAX_SAFE_INTEGER = (2**53) - 1

_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$")
_HASH_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_TIMESTAMP_RE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")
_PREPARATION_TOKEN = object()
_PROCESS_PREPARATION_SECRET = secrets.token_bytes(32)


class GateError(ValueError):
    """Raised when a Sprint 3 object is outside its exact profile."""


class PermitLifecycle(str, Enum):
    RESERVED = "RESERVED"
    ATTEMPTED = "ATTEMPTED"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"


class ObservationKind(str, Enum):
    INTERACTION = "INTERACTION"
    SENDER_SEQUENCE = "SENDER_SEQUENCE"


def _require_exact_fields(
    value: Any,
    expected: frozenset[str],
    name: str,
) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or not all(isinstance(key, str) for key in value):
        raise GateError(f"{name} must be an object with string keys")
    actual = frozenset(value)
    if actual != expected:
        raise GateError(
            f"{name} fields mismatch; "
            f"missing={sorted(expected - actual)}, extra={sorted(actual - expected)}"
        )
    return value


def require_identifier(value: Any, name: str) -> str:
    if not isinstance(value, str) or not _ID_RE.fullmatch(value):
        raise GateError(f"{name} must be a bounded ASCII identifier")
    return value


def require_hash(value: Any, name: str) -> str:
    if not isinstance(value, str) or not _HASH_RE.fullmatch(value):
        raise GateError(f"{name} must be a sha256 identifier")
    return value


def parse_timestamp(value: Any, name: str) -> datetime:
    if not isinstance(value, str) or not _TIMESTAMP_RE.fullmatch(value):
        raise GateError(f"{name} must be a whole-second UTC timestamp")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError as exc:
        raise GateError(f"{name} must be a real timestamp") from exc
    if format_timestamp(parsed) != value:
        raise GateError(f"{name} must use canonical UTC encoding")
    return parsed


def format_timestamp(value: datetime) -> str:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise GateError("timestamp must be timezone-aware")
    normalised = value.astimezone(UTC)
    if normalised.microsecond:
        raise GateError("timestamp must use whole-second precision")
    return normalised.strftime("%Y-%m-%dT%H:%M:%SZ")


def _canonical_object(value: Any, name: str) -> bytes:
    if not isinstance(value, Mapping):
        raise GateError(f"{name} must be an object")
    try:
        return canonical_json(dict(value))
    except ValueError as exc:
        raise GateError(f"{name} must use the canonical JSON profile") from exc


def _decode_canonical_object(raw: Any, name: str) -> Mapping[str, Any]:
    if not isinstance(raw, bytes):
        raise GateError(f"{name} must be bytes")
    try:
        parsed = loads_strict(raw)
    except ValueError as exc:
        raise GateError(f"{name} must be canonical-profile JSON") from exc
    if not isinstance(parsed, dict) or canonical_json(parsed) != raw:
        raise GateError(f"{name} must be a canonically encoded object")
    return parsed


def _process_tag(label: str, payload: bytes) -> bytes:
    return hmac.new(
        _PROCESS_PREPARATION_SECRET,
        label.encode("ascii") + b"\x00" + payload,
        hashlib.sha256,
    ).digest()


@dataclass(frozen=True, slots=True)
class AuthorityStatusEvidence:
    """One strictly authenticated status message retained for gate selection."""

    message_id: str
    delivery_slot_id: str
    origin_store_id: str
    status_id: str
    signed_status_bytes: bytes

    def __post_init__(self) -> None:
        require_hash(self.message_id, "authority status message_id")
        require_identifier(self.delivery_slot_id, "authority status delivery_slot_id")
        require_identifier(self.origin_store_id, "authority status origin_store_id")
        require_hash(self.status_id, "authority status status_id")
        payload = _decode_canonical_object(
            self.signed_status_bytes,
            "signed authority status",
        )
        if payload.get("status_id") != self.status_id:
            raise GateError("status evidence status_id does not match its payload")

    @property
    def signed_status(self) -> dict[str, Any]:
        value = loads_strict(self.signed_status_bytes)
        assert isinstance(value, dict)
        return value

    @classmethod
    def from_dict(cls, value: Any) -> "AuthorityStatusEvidence":
        fields = _require_exact_fields(
            value,
            frozenset(
                {
                    "message_id",
                    "delivery_slot_id",
                    "origin_store_id",
                    "status_id",
                    "signed_status",
                }
            ),
            "authority status evidence",
        )
        return cls(
            message_id=fields["message_id"],
            delivery_slot_id=fields["delivery_slot_id"],
            origin_store_id=fields["origin_store_id"],
            status_id=fields["status_id"],
            signed_status_bytes=_canonical_object(
                fields["signed_status"],
                "signed authority status",
            ),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "message_id": self.message_id,
            "delivery_slot_id": self.delivery_slot_id,
            "origin_store_id": self.origin_store_id,
            "status_id": self.status_id,
            "signed_status": self.signed_status,
        }


@dataclass(frozen=True, slots=True)
class NeutralPermitRecord:
    permit_id: str
    leaf_neutral_handoff_id: str
    neutral_chain_id: str
    controlling_status_id: str
    replay_scope_id: str
    request_hash: str
    action_nonce: str
    tool_id: str
    state: PermitLifecycle
    issued_at: datetime
    expires_at: datetime

    def __post_init__(self) -> None:
        require_identifier(self.permit_id, "permit_id")
        for name in (
            "leaf_neutral_handoff_id",
            "neutral_chain_id",
            "controlling_status_id",
            "replay_scope_id",
            "request_hash",
        ):
            require_hash(getattr(self, name), name)
        require_identifier(self.action_nonce, "action_nonce")
        require_identifier(self.tool_id, "tool_id")
        if not isinstance(self.state, PermitLifecycle):
            raise GateError("permit state is unsupported")
        issued = self.issued_at.astimezone(UTC) if self.issued_at.tzinfo else None
        expires = self.expires_at.astimezone(UTC) if self.expires_at.tzinfo else None
        if issued is None or expires is None:
            raise GateError("permit timestamps must be timezone-aware")
        if issued.microsecond or expires.microsecond or issued >= expires:
            raise GateError("permit timestamps must be ordered whole seconds")
        object.__setattr__(self, "issued_at", issued)
        object.__setattr__(self, "expires_at", expires)

    @classmethod
    def from_dict(cls, value: Any) -> "NeutralPermitRecord":
        fields = _require_exact_fields(
            value,
            frozenset(
                {
                    "permit_id",
                    "leaf_neutral_handoff_id",
                    "neutral_chain_id",
                    "controlling_status_id",
                    "replay_scope_id",
                    "request_hash",
                    "action_nonce",
                    "tool_id",
                    "state",
                    "issued_at",
                    "expires_at",
                }
            ),
            "neutral permit record",
        )
        try:
            state = PermitLifecycle(fields["state"])
        except (TypeError, ValueError) as exc:
            raise GateError("permit state is unsupported") from exc
        return cls(
            permit_id=fields["permit_id"],
            leaf_neutral_handoff_id=fields["leaf_neutral_handoff_id"],
            neutral_chain_id=fields["neutral_chain_id"],
            controlling_status_id=fields["controlling_status_id"],
            replay_scope_id=fields["replay_scope_id"],
            request_hash=fields["request_hash"],
            action_nonce=fields["action_nonce"],
            tool_id=fields["tool_id"],
            state=state,
            issued_at=parse_timestamp(fields["issued_at"], "permit.issued_at"),
            expires_at=parse_timestamp(fields["expires_at"], "permit.expires_at"),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "permit_id": self.permit_id,
            "leaf_neutral_handoff_id": self.leaf_neutral_handoff_id,
            "neutral_chain_id": self.neutral_chain_id,
            "controlling_status_id": self.controlling_status_id,
            "replay_scope_id": self.replay_scope_id,
            "request_hash": self.request_hash,
            "action_nonce": self.action_nonce,
            "tool_id": self.tool_id,
            "state": self.state.value,
            "issued_at": format_timestamp(self.issued_at),
            "expires_at": format_timestamp(self.expires_at),
        }


@dataclass(frozen=True, slots=True)
class NeutralObservationRecord:
    observation_kind: ObservationKind
    observation_key: str
    neutral_handoff_id: str

    def __post_init__(self) -> None:
        if not isinstance(self.observation_kind, ObservationKind):
            raise GateError("observation_kind is unsupported")
        require_hash(self.observation_key, "observation_key")
        require_hash(self.neutral_handoff_id, "neutral_handoff_id")

    @classmethod
    def from_dict(cls, value: Any) -> "NeutralObservationRecord":
        fields = _require_exact_fields(
            value,
            frozenset({"observation_kind", "observation_key", "neutral_handoff_id"}),
            "neutral observation record",
        )
        try:
            kind = ObservationKind(fields["observation_kind"])
        except (TypeError, ValueError) as exc:
            raise GateError("observation_kind is unsupported") from exc
        return cls(
            observation_kind=kind,
            observation_key=fields["observation_key"],
            neutral_handoff_id=fields["neutral_handoff_id"],
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "observation_kind": self.observation_kind.value,
            "observation_key": self.observation_key,
            "neutral_handoff_id": self.neutral_handoff_id,
        }


@dataclass(frozen=True, slots=True)
class NeutralPermitStateSnapshot:
    permit_store_id: str
    revision: int
    captured_at: datetime
    records: tuple[NeutralPermitRecord, ...] = ()
    observations: tuple[NeutralObservationRecord, ...] = ()

    def __post_init__(self) -> None:
        require_identifier(self.permit_store_id, "permit_store_id")
        if type(self.revision) is not int or not 0 <= self.revision <= MAX_SAFE_INTEGER:
            raise GateError("permit revision must be a non-negative safe integer")
        captured = self.captured_at.astimezone(UTC) if self.captured_at.tzinfo else None
        if captured is None or captured.microsecond:
            raise GateError("snapshot captured_at must be a whole-second timestamp")
        if not isinstance(self.records, tuple) or not all(
            isinstance(item, NeutralPermitRecord) for item in self.records
        ):
            raise GateError("snapshot records must contain NeutralPermitRecord values")
        if not isinstance(self.observations, tuple) or not all(
            isinstance(item, NeutralObservationRecord) for item in self.observations
        ):
            raise GateError(
                "snapshot observations must contain NeutralObservationRecord values"
            )
        records = tuple(sorted(self.records, key=lambda item: item.permit_id))
        observations = tuple(
            sorted(
                self.observations,
                key=lambda item: (item.observation_kind.value, item.observation_key),
            )
        )
        if len({item.permit_id for item in records}) != len(records):
            raise GateError("snapshot permit_id values must be unique")
        replay_keys = {
            (item.tool_id, item.replay_scope_id, item.action_nonce) for item in records
        }
        if len(replay_keys) != len(records):
            raise GateError("snapshot replay keys must be unique")
        observation_keys = {
            (item.observation_kind, item.observation_key) for item in observations
        }
        if len(observation_keys) != len(observations):
            raise GateError("snapshot observation keys must be unique")
        if any(item.issued_at > captured for item in records):
            raise GateError("snapshot contains a future-issued permit")
        object.__setattr__(self, "captured_at", captured)
        object.__setattr__(self, "records", records)
        object.__setattr__(self, "observations", observations)

    @classmethod
    def from_dict(cls, value: Any) -> "NeutralPermitStateSnapshot":
        fields = _require_exact_fields(
            value,
            frozenset(
                {
                    "version",
                    "permit_store_id",
                    "revision",
                    "captured_at",
                    "records",
                    "observations",
                }
            ),
            "neutral permit snapshot",
        )
        if fields["version"] != NEUTRAL_PERMIT_STATE_VERSION:
            raise GateError("unsupported neutral permit state version")
        if not isinstance(fields["records"], list) or not isinstance(
            fields["observations"], list
        ):
            raise GateError("snapshot records and observations must be arrays")
        return cls(
            permit_store_id=fields["permit_store_id"],
            revision=fields["revision"],
            captured_at=parse_timestamp(fields["captured_at"], "captured_at"),
            records=tuple(
                NeutralPermitRecord.from_dict(item) for item in fields["records"]
            ),
            observations=tuple(
                NeutralObservationRecord.from_dict(item)
                for item in fields["observations"]
            ),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": NEUTRAL_PERMIT_STATE_VERSION,
            "permit_store_id": self.permit_store_id,
            "revision": self.revision,
            "captured_at": format_timestamp(self.captured_at),
            "records": [item.to_dict() for item in self.records],
            "observations": [item.to_dict() for item in self.observations],
        }

    @property
    def canonical_bytes(self) -> bytes:
        return canonical_json(self.to_dict())


def _common_input_body(
    *,
    verifier_id: str,
    evidence_store_id: str,
    permit_store_id: str,
    decision_time: datetime,
    policy_views: tuple[PolicyView, ...],
    authority_status_evidence: tuple[AuthorityStatusEvidence, ...],
    permit_state: NeutralPermitStateSnapshot,
    preparation_reasons: tuple[str, ...],
) -> dict[str, Any]:
    return {
        "version": COMMON_GATE_INPUT_VERSION,
        "verifier_id": verifier_id,
        "evidence_store_id": evidence_store_id,
        "permit_store_id": permit_store_id,
        "decision_time": format_timestamp(decision_time),
        "policy_views": [item.to_dict() for item in policy_views],
        "authority_status_evidence": [
            item.to_dict() for item in authority_status_evidence
        ],
        "permit_state": permit_state.to_dict(),
        "preparation_reasons": list(preparation_reasons),
    }


@dataclass(frozen=True, slots=True)
class CommonGateInput:
    """Audit-serialisable, representation-blind input prepared from one view.

    The non-serialised tag prevents accidental use of caller-authored or
    deserialised all-true policy projections.  It is an honest-caller process
    boundary, not protection from arbitrary code in the same process.
    """

    input_id: str
    verifier_id: str
    evidence_store_id: str
    permit_store_id: str
    decision_time: datetime
    policy_views: tuple[PolicyView, ...]
    authority_status_evidence: tuple[AuthorityStatusEvidence, ...]
    permit_state: NeutralPermitStateSnapshot
    preparation_reasons: tuple[str, ...]
    _preparation_tag: bytes | None = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        require_hash(self.input_id, "input_id")
        require_identifier(self.verifier_id, "verifier_id")
        require_identifier(self.evidence_store_id, "evidence_store_id")
        require_identifier(self.permit_store_id, "permit_store_id")
        decision_time = (
            self.decision_time.astimezone(UTC) if self.decision_time.tzinfo else None
        )
        if decision_time is None or decision_time.microsecond:
            raise GateError("decision_time must be a whole-second timestamp")
        if not isinstance(self.policy_views, tuple) or not all(
            type(item) is PolicyView for item in self.policy_views
        ):
            raise GateError("policy_views must contain exact PolicyView objects")
        if not isinstance(self.authority_status_evidence, tuple) or not all(
            isinstance(item, AuthorityStatusEvidence)
            for item in self.authority_status_evidence
        ):
            raise GateError(
                "authority_status_evidence must contain authenticated evidence"
            )
        if not isinstance(self.permit_state, NeutralPermitStateSnapshot):
            raise GateError("permit_state must be a NeutralPermitStateSnapshot")
        if self.permit_state.permit_store_id != self.permit_store_id:
            raise GateError("permit snapshot store does not match gate input")
        if self.permit_state.captured_at != decision_time:
            raise GateError("permit snapshot was not captured at decision_time")
        if not isinstance(self.preparation_reasons, tuple):
            raise GateError("preparation_reasons must be a tuple")
        reasons = tuple(sorted(set(self.preparation_reasons)))
        for reason in reasons:
            require_identifier(reason, "preparation reason")
        views = tuple(
            sorted(
                self.policy_views,
                key=lambda item: item.to_dict()["neutral_handoff_id"],
            )
        )
        if len({item.to_dict()["neutral_handoff_id"] for item in views}) != len(views):
            raise GateError("common gate input contains duplicate neutral handoffs")
        statuses = tuple(
            sorted(
                self.authority_status_evidence,
                key=lambda item: (item.status_id, item.message_id),
            )
        )
        body = _common_input_body(
            verifier_id=self.verifier_id,
            evidence_store_id=self.evidence_store_id,
            permit_store_id=self.permit_store_id,
            decision_time=decision_time,
            policy_views=views,
            authority_status_evidence=statuses,
            permit_state=self.permit_state,
            preparation_reasons=reasons,
        )
        expected_id = content_id("COMMON_GATE_INPUT", body)
        if self.input_id != expected_id:
            raise GateError("input_id does not match common gate input")
        if self._preparation_tag is not None:
            expected_tag = _process_tag(
                "COMMON_GATE_INPUT",
                canonical_json({"input_id": self.input_id, **body}),
            )
            if not hmac.compare_digest(self._preparation_tag, expected_tag):
                raise GateError("common gate input preparation tag is invalid")
        object.__setattr__(self, "decision_time", decision_time)
        object.__setattr__(self, "policy_views", views)
        object.__setattr__(self, "authority_status_evidence", statuses)
        object.__setattr__(self, "preparation_reasons", reasons)

    @classmethod
    def _from_preparer(
        cls,
        *,
        verifier_id: str,
        evidence_store_id: str,
        permit_store_id: str,
        decision_time: datetime,
        policy_views: tuple[PolicyView, ...],
        authority_status_evidence: tuple[AuthorityStatusEvidence, ...],
        permit_state: NeutralPermitStateSnapshot,
        preparation_reasons: tuple[str, ...],
        _preparation_token: object,
    ) -> "CommonGateInput":
        if _preparation_token is not _PREPARATION_TOKEN:
            raise GateError("CommonGateInput can only be issued by its preparer")
        if not all(
            type(item) is PolicyView and item.validator_issued for item in policy_views
        ):
            raise GateError("preparer requires validator-issued PolicyView objects")
        reasons = tuple(sorted(set(preparation_reasons)))
        views = tuple(
            sorted(policy_views, key=lambda item: item.to_dict()["neutral_handoff_id"])
        )
        statuses = tuple(
            sorted(
                authority_status_evidence,
                key=lambda item: (item.status_id, item.message_id),
            )
        )
        body = _common_input_body(
            verifier_id=verifier_id,
            evidence_store_id=evidence_store_id,
            permit_store_id=permit_store_id,
            decision_time=decision_time,
            policy_views=views,
            authority_status_evidence=statuses,
            permit_state=permit_state,
            preparation_reasons=reasons,
        )
        input_id = content_id("COMMON_GATE_INPUT", body)
        tag = _process_tag(
            "COMMON_GATE_INPUT",
            canonical_json({"input_id": input_id, **body}),
        )
        return cls(
            input_id=input_id,
            verifier_id=verifier_id,
            evidence_store_id=evidence_store_id,
            permit_store_id=permit_store_id,
            decision_time=decision_time,
            policy_views=views,
            authority_status_evidence=statuses,
            permit_state=permit_state,
            preparation_reasons=reasons,
            _preparation_tag=tag,
        )

    @property
    def preparer_issued(self) -> bool:
        if self._preparation_tag is None:
            return False
        body = self.to_dict()
        expected = _process_tag("COMMON_GATE_INPUT", canonical_json(body))
        return hmac.compare_digest(self._preparation_tag, expected)

    @classmethod
    def from_dict(cls, value: Any) -> "CommonGateInput":
        fields = _require_exact_fields(
            value,
            frozenset(
                {
                    "version",
                    "input_id",
                    "verifier_id",
                    "evidence_store_id",
                    "permit_store_id",
                    "decision_time",
                    "policy_views",
                    "authority_status_evidence",
                    "permit_state",
                    "preparation_reasons",
                }
            ),
            "common gate input",
        )
        if fields["version"] != COMMON_GATE_INPUT_VERSION:
            raise GateError("unsupported common gate input version")
        for name in (
            "policy_views",
            "authority_status_evidence",
            "preparation_reasons",
        ):
            if not isinstance(fields[name], list):
                raise GateError(f"{name} must be an array")
        return cls(
            input_id=fields["input_id"],
            verifier_id=fields["verifier_id"],
            evidence_store_id=fields["evidence_store_id"],
            permit_store_id=fields["permit_store_id"],
            decision_time=parse_timestamp(fields["decision_time"], "decision_time"),
            policy_views=tuple(
                PolicyView.from_dict(item) for item in fields["policy_views"]
            ),
            authority_status_evidence=tuple(
                AuthorityStatusEvidence.from_dict(item)
                for item in fields["authority_status_evidence"]
            ),
            permit_state=NeutralPermitStateSnapshot.from_dict(fields["permit_state"]),
            preparation_reasons=tuple(fields["preparation_reasons"]),
        )

    @classmethod
    def from_bytes(cls, raw: Any) -> "CommonGateInput":
        parsed = cls.from_dict(_decode_canonical_object(raw, "common gate input"))
        if parsed.canonical_bytes != raw:
            raise GateError("common gate input bytes are not canonical")
        return parsed

    def to_dict(self) -> dict[str, Any]:
        return {
            "input_id": self.input_id,
            **_common_input_body(
                verifier_id=self.verifier_id,
                evidence_store_id=self.evidence_store_id,
                permit_store_id=self.permit_store_id,
                decision_time=self.decision_time,
                policy_views=self.policy_views,
                authority_status_evidence=self.authority_status_evidence,
                permit_state=self.permit_state,
                preparation_reasons=self.preparation_reasons,
            ),
        }

    @property
    def canonical_bytes(self) -> bytes:
        return canonical_json(self.to_dict())


@dataclass(frozen=True, slots=True)
class CommonGateDecision:
    decision_id: str
    verdict: str
    reasons: tuple[str, ...]
    action_id: str
    leaf_neutral_handoff_id: str | None = None
    neutral_chain_id: str | None = None
    controlling_status_id: str | None = None
    replay_scope_id: str | None = None
    permit_id: str | None = None
    permit_expires_at: str | None = None

    def __post_init__(self) -> None:
        require_hash(self.decision_id, "decision_id")
        if self.verdict not in {"ALLOW", "PAUSE"}:
            raise GateError("gate verdict must be ALLOW or PAUSE")
        if not isinstance(self.reasons, tuple):
            raise GateError("gate reasons must be a tuple")
        reasons = tuple(sorted(set(self.reasons)))
        for reason in reasons:
            require_identifier(reason, "gate reason")
        require_hash(self.action_id, "action_id")
        for name in (
            "leaf_neutral_handoff_id",
            "neutral_chain_id",
            "controlling_status_id",
            "replay_scope_id",
        ):
            value = getattr(self, name)
            if value is not None:
                require_hash(value, name)
        if self.permit_id is not None:
            require_identifier(self.permit_id, "permit_id")
        if self.permit_expires_at is not None:
            parse_timestamp(self.permit_expires_at, "permit_expires_at")
        if self.verdict == "ALLOW":
            required = (
                self.leaf_neutral_handoff_id,
                self.neutral_chain_id,
                self.controlling_status_id,
                self.replay_scope_id,
                self.permit_id,
                self.permit_expires_at,
            )
            if reasons or any(item is None for item in required):
                raise GateError(
                    "ALLOW requires complete permit bindings and no reasons"
                )
        elif (
            not reasons
            or self.permit_id is not None
            or self.permit_expires_at is not None
        ):
            raise GateError("PAUSE requires reasons and cannot contain a permit")
        object.__setattr__(self, "reasons", reasons)
        expected = content_id("COMMON_GATE_DECISION", self._body_dict())
        if self.decision_id != expected:
            raise GateError("decision_id does not match gate decision")

    def _body_dict(self) -> dict[str, Any]:
        return {
            "version": COMMON_GATE_DECISION_VERSION,
            "verdict": self.verdict,
            "reasons": list(self.reasons),
            "action_id": self.action_id,
            "leaf_neutral_handoff_id": self.leaf_neutral_handoff_id,
            "neutral_chain_id": self.neutral_chain_id,
            "controlling_status_id": self.controlling_status_id,
            "replay_scope_id": self.replay_scope_id,
            "permit_id": self.permit_id,
            "permit_expires_at": self.permit_expires_at,
        }

    @classmethod
    def make(
        cls,
        *,
        verdict: str,
        reasons: tuple[str, ...],
        action_id: str,
        leaf_neutral_handoff_id: str | None = None,
        neutral_chain_id: str | None = None,
        controlling_status_id: str | None = None,
        replay_scope_id: str | None = None,
        permit_id: str | None = None,
        permit_expires_at: str | None = None,
    ) -> "CommonGateDecision":
        reasons = tuple(sorted(set(reasons)))
        body = {
            "version": COMMON_GATE_DECISION_VERSION,
            "verdict": verdict,
            "reasons": list(reasons),
            "action_id": action_id,
            "leaf_neutral_handoff_id": leaf_neutral_handoff_id,
            "neutral_chain_id": neutral_chain_id,
            "controlling_status_id": controlling_status_id,
            "replay_scope_id": replay_scope_id,
            "permit_id": permit_id,
            "permit_expires_at": permit_expires_at,
        }
        return cls(
            decision_id=content_id("COMMON_GATE_DECISION", body),
            verdict=verdict,
            reasons=reasons,
            action_id=action_id,
            leaf_neutral_handoff_id=leaf_neutral_handoff_id,
            neutral_chain_id=neutral_chain_id,
            controlling_status_id=controlling_status_id,
            replay_scope_id=replay_scope_id,
            permit_id=permit_id,
            permit_expires_at=permit_expires_at,
        )

    @property
    def allowed(self) -> bool:
        return self.verdict == "ALLOW"

    def to_dict(self) -> dict[str, Any]:
        return {"decision_id": self.decision_id, **self._body_dict()}


@dataclass(frozen=True, slots=True)
class PermitTransitionResult:
    verdict: str
    reason: str | None
    permit_id: str

    def __post_init__(self) -> None:
        if self.verdict not in {"ALLOW", "PAUSE"}:
            raise GateError("transition verdict must be ALLOW or PAUSE")
        require_identifier(self.permit_id, "permit_id")
        if self.reason is not None:
            require_identifier(self.reason, "transition reason")
        if (self.verdict == "ALLOW") != (self.reason is None):
            raise GateError("ALLOW requires no reason and PAUSE requires a reason")

    @property
    def allowed(self) -> bool:
        return self.verdict == "ALLOW"

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": PERMIT_TRANSITION_VERSION,
            "verdict": self.verdict,
            "reason": self.reason,
            "permit_id": self.permit_id,
        }


__all__ = [
    "AuthorityStatusEvidence",
    "COMMON_GATE_DECISION_VERSION",
    "COMMON_GATE_INPUT_VERSION",
    "CommonGateDecision",
    "CommonGateInput",
    "GateError",
    "NEUTRAL_PERMIT_STATE_VERSION",
    "NeutralObservationRecord",
    "NeutralPermitRecord",
    "NeutralPermitStateSnapshot",
    "ObservationKind",
    "PermitLifecycle",
    "PermitTransitionResult",
]
