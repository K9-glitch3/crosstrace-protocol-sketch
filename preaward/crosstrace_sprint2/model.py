"""Strict Sprint 2 evidence records and representation-neutral outputs."""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from typing import Any, Mapping

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from crosstrace_sketch.protocol import (
    MAX_SAFE_INTEGER,
    ProtocolError,
    canonical_json,
    content_id,
    loads_strict,
)

from .crypto_compat import sign_endpoint_attestation

EVIDENCE_VERSION = "crosstrace-evidence/0.1"
VALIDATION_VERSION = "crosstrace-validation/0.1"
POLICY_VIEW_VERSION = "crosstrace-policy-view/0.1"
_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$")
_HASH_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_SIGNATURE_RE = re.compile(r"^[A-Za-z0-9_-]{86}$")
_TIMESTAMP_RE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")
_VALIDATOR_TOKEN = object()
_PROCESS_VALIDATION_SECRET = secrets.token_bytes(32)


class EvidenceError(ValueError):
    """Raised when an object is outside the Sprint 2 evidence profile."""


class EvidenceRepresentation(str, Enum):
    SL = "SL"
    CR = "CR"
    PR = "PR"


class EndpointRole(str, Enum):
    SENDER = "SENDER"
    RECEIVER = "RECEIVER"


class ReceiverDecision(str, Enum):
    ACCEPT = "ACCEPT"
    REJECT = "REJECT"


def _require_exact_fields(
    value: Any,
    expected: frozenset[str],
    name: str,
) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise EvidenceError(f"{name} must be an object")
    if not all(isinstance(key, str) for key in value):
        raise EvidenceError(f"{name} contains a non-string key")
    actual = frozenset(value)
    if actual != expected:
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        raise EvidenceError(f"{name} fields mismatch; missing={missing}, extra={extra}")
    return value


def _require_identifier(value: Any, name: str) -> str:
    if not isinstance(value, str) or not _ID_RE.fullmatch(value):
        raise EvidenceError(f"{name} must be a bounded ASCII identifier")
    return value


def _require_hash(value: Any, name: str) -> str:
    if not isinstance(value, str) or not _HASH_RE.fullmatch(value):
        raise EvidenceError(f"{name} must be a SHA-256 identifier")
    return value


def _parse_timestamp(value: Any, name: str) -> datetime:
    if not isinstance(value, str) or not _TIMESTAMP_RE.fullmatch(value):
        raise EvidenceError(f"{name} must be a whole-second UTC timestamp")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError as exc:
        raise EvidenceError(f"{name} must be a real UTC timestamp") from exc
    if _format_timestamp(parsed) != value:
        raise EvidenceError(f"{name} must use canonical UTC encoding")
    return parsed


def _format_timestamp(value: datetime) -> str:
    return value.strftime("%Y-%m-%dT%H:%M:%SZ")


def _canonical_bytes(value: Any, name: str) -> bytes:
    try:
        return canonical_json(value)
    except (ProtocolError, ValueError) as exc:
        raise EvidenceError(f"{name} must use canonical-profile JSON values") from exc


def _process_validation_tag(label: str, payload: bytes) -> bytes:
    """Create a process-local provenance tag that is never serialized.

    This is an in-process misuse barrier, not a portable signature. Serialized
    normalized objects must be revalidated from their source observation before
    they can be supplied to policy.
    """

    return hmac.new(
        _PROCESS_VALIDATION_SECRET,
        label.encode("ascii") + b"\x00" + payload,
        hashlib.sha256,
    ).digest()


def _decode_canonical_object(raw: Any, name: str) -> Mapping[str, Any]:
    if not isinstance(raw, bytes):
        raise EvidenceError(f"{name} must be bytes")
    try:
        value = loads_strict(raw)
        encoded = canonical_json(value)
    except (ProtocolError, ValueError) as exc:
        raise EvidenceError(f"{name} must be canonical-profile JSON") from exc
    if not isinstance(value, dict):
        raise EvidenceError(f"{name} must encode an object")
    if encoded != raw:
        raise EvidenceError(f"{name} must use canonical JSON encoding")
    return value


def _validate_party(value: Any, name: str) -> None:
    fields = _require_exact_fields(
        value,
        frozenset({"principal_id", "agent_id", "key_id"}),
        name,
    )
    _require_identifier(fields["principal_id"], f"{name}.principal_id")
    _require_identifier(fields["agent_id"], f"{name}.agent_id")
    _require_identifier(fields["key_id"], f"{name}.key_id")


def _validate_scope(value: Any) -> None:
    fields = _require_exact_fields(
        value,
        frozenset(
            {
                "operations",
                "resources",
                "currency",
                "max_amount_minor",
                "not_before",
                "not_after",
                "redelegations_remaining",
            }
        ),
        "scope",
    )
    for field_name in ("operations", "resources"):
        entries = fields[field_name]
        if not isinstance(entries, list) or not entries:
            raise EvidenceError(f"scope.{field_name} must be a non-empty array")
        for index, entry in enumerate(entries):
            _require_identifier(entry, f"scope.{field_name}[{index}]")
        if entries != sorted(set(entries)):
            raise EvidenceError(f"scope.{field_name} must be sorted and unique")
    currency = fields["currency"]
    if not isinstance(currency, str) or not re.fullmatch(r"^[A-Z]{3}$", currency):
        raise EvidenceError("scope.currency must be three uppercase letters")
    amount = fields["max_amount_minor"]
    if type(amount) is not int or not 0 <= amount <= MAX_SAFE_INTEGER:
        raise EvidenceError("scope.max_amount_minor is outside the safe range")
    not_before = _parse_timestamp(fields["not_before"], "scope.not_before")
    not_after = _parse_timestamp(fields["not_after"], "scope.not_after")
    if not_before >= not_after:
        raise EvidenceError("scope.not_before must precede scope.not_after")
    remaining = fields["redelegations_remaining"]
    if type(remaining) is not int or not 0 <= remaining <= 32:
        raise EvidenceError("scope.redelegations_remaining must be between 0 and 32")


def _validate_authority_lineage(value: Any) -> None:
    fields = _require_exact_fields(
        value,
        frozenset(
            {
                "issuer_principal_id",
                "subject_principal_id",
                "subject_key_id",
            }
        ),
        "authority_lineage",
    )
    for field_name in (
        "issuer_principal_id",
        "subject_principal_id",
        "subject_key_id",
    ):
        _require_identifier(fields[field_name], f"authority_lineage.{field_name}")


def _validate_neutral_handoff(value: Any) -> None:
    fields = _require_exact_fields(
        value,
        frozenset(
            {
                "interaction_id",
                "sender",
                "receiver",
                "event_type",
                "sender_sequence",
                "previous_interaction_id",
                "scope",
                "authority_lineage",
                "authority_version",
                "referenced_status_id",
                "created_at",
                "request_hash",
            }
        ),
        "neutral handoff",
    )
    _require_identifier(fields["interaction_id"], "interaction_id")
    _validate_party(fields["sender"], "sender")
    _validate_party(fields["receiver"], "receiver")
    if fields["sender"]["principal_id"] == fields["receiver"]["principal_id"]:
        raise EvidenceError("sender and receiver must be different principals")
    if fields["event_type"] not in {"delegation", "action_intent"}:
        raise EvidenceError("event_type must be delegation or action_intent")
    sequence = fields["sender_sequence"]
    if type(sequence) is not int or not 0 <= sequence <= MAX_SAFE_INTEGER:
        raise EvidenceError("sender_sequence is outside the safe range")
    previous = fields["previous_interaction_id"]
    if previous is not None:
        _require_identifier(previous, "previous_interaction_id")
    _validate_scope(fields["scope"])
    _validate_authority_lineage(fields["authority_lineage"])
    version = fields["authority_version"]
    if type(version) is not int or not 1 <= version <= MAX_SAFE_INTEGER:
        raise EvidenceError("authority_version is outside the safe range")
    _require_hash(fields["referenced_status_id"], "referenced_status_id")
    _parse_timestamp(fields["created_at"], "created_at")
    _require_hash(fields["request_hash"], "request_hash")
    _canonical_bytes(fields, "neutral handoff")


@dataclass(frozen=True, slots=True)
class NeutralHandoff:
    """Immutable canonical semantic handoff shared by all representations."""

    body_bytes: bytes

    def __post_init__(self) -> None:
        body = _decode_canonical_object(self.body_bytes, "neutral handoff")
        _validate_neutral_handoff(body)

    @classmethod
    def from_dict(cls, value: Any) -> NeutralHandoff:
        if not isinstance(value, Mapping):
            raise EvidenceError("neutral handoff must be an object")
        body_bytes = _canonical_bytes(dict(value), "neutral handoff")
        return cls(body_bytes=body_bytes)

    @classmethod
    def from_bytes(cls, raw: Any) -> NeutralHandoff:
        parsed = cls(body_bytes=bytes(raw) if isinstance(raw, bytes) else raw)
        if parsed.body_bytes != raw:
            raise EvidenceError("neutral handoff bytes are not canonical")
        return parsed

    def to_dict(self) -> dict[str, Any]:
        value = loads_strict(self.body_bytes)
        assert isinstance(value, dict)
        return value

    @property
    def neutral_handoff_id(self) -> str:
        return content_id("NEUTRAL_HANDOFF", self.to_dict())

    @property
    def canonical_bytes(self) -> bytes:
        return self.body_bytes


def make_neutral_handoff(
    *,
    interaction_id: str,
    sender: Mapping[str, Any],
    receiver: Mapping[str, Any],
    event_type: str,
    sender_sequence: int,
    previous_interaction_id: str | None,
    scope: Mapping[str, Any],
    authority_lineage: Mapping[str, Any],
    authority_version: int,
    referenced_status_id: str,
    created_at: str,
    request_hash: str,
) -> NeutralHandoff:
    return NeutralHandoff.from_dict(
        {
            "interaction_id": interaction_id,
            "sender": dict(sender),
            "receiver": dict(receiver),
            "event_type": event_type,
            "sender_sequence": sender_sequence,
            "previous_interaction_id": previous_interaction_id,
            "scope": dict(scope),
            "authority_lineage": dict(authority_lineage),
            "authority_version": authority_version,
            "referenced_status_id": referenced_status_id,
            "created_at": created_at,
            "request_hash": request_hash,
        }
    )


def _validate_endpoint_record(value: Any) -> None:
    fields = _require_exact_fields(
        value,
        frozenset({"record_id", "body_id", "body", "attestation"}),
        "endpoint record",
    )
    body = _require_exact_fields(
        fields["body"],
        frozenset(
            {
                "record_version",
                "record_type",
                "holder",
                "role",
                "handoff",
                "sender_record_id",
                "decision",
                "reason_code",
                "decided_at",
            }
        ),
        "endpoint record body",
    )
    if body["record_version"] != EVIDENCE_VERSION:
        raise EvidenceError(f"record_version must equal {EVIDENCE_VERSION}")
    if body["record_type"] != "signed_endpoint_record":
        raise EvidenceError("record_type must be signed_endpoint_record")
    _validate_party(body["holder"], "holder")
    try:
        role = EndpointRole(body["role"])
    except (TypeError, ValueError) as exc:
        raise EvidenceError("role must be SENDER or RECEIVER") from exc
    handoff = NeutralHandoff.from_dict(body["handoff"])
    handoff_body = handoff.to_dict()
    expected_holder = handoff_body[
        "sender" if role is EndpointRole.SENDER else "receiver"
    ]
    if body["holder"] != expected_holder:
        raise EvidenceError("holder does not match the handoff endpoint role")
    sender_record_id = body["sender_record_id"]
    if sender_record_id is not None:
        _require_hash(sender_record_id, "sender_record_id")
    if role is EndpointRole.SENDER:
        if any(
            body[field_name] is not None
            for field_name in (
                "sender_record_id",
                "decision",
                "reason_code",
                "decided_at",
            )
        ):
            raise EvidenceError(
                "sender record decision and cross-reference fields must be null"
            )
    else:
        try:
            decision = ReceiverDecision(body["decision"])
        except (TypeError, ValueError) as exc:
            raise EvidenceError("receiver decision must be ACCEPT or REJECT") from exc
        decided_at = _parse_timestamp(body["decided_at"], "decided_at")
        if decided_at < _parse_timestamp(handoff_body["created_at"], "created_at"):
            raise EvidenceError("decided_at cannot precede handoff creation")
        if decision is ReceiverDecision.ACCEPT and body["reason_code"] is not None:
            raise EvidenceError("accepted receiver record must have null reason_code")
        if decision is ReceiverDecision.REJECT:
            _require_identifier(body["reason_code"], "reason_code")
    expected_body_id = content_id("ENDPOINT_RECORD_BODY", body)
    if fields["body_id"] != expected_body_id:
        raise EvidenceError("body_id does not match endpoint record body")
    attestation = _require_exact_fields(
        fields["attestation"],
        frozenset({"algorithm", "key_id", "body_id", "signature"}),
        "endpoint attestation",
    )
    if attestation["algorithm"] != "Ed25519":
        raise EvidenceError("endpoint attestation algorithm must be Ed25519")
    if attestation["key_id"] != body["holder"]["key_id"]:
        raise EvidenceError("endpoint attestation key does not match holder")
    if attestation["body_id"] != expected_body_id:
        raise EvidenceError("endpoint attestation does not bind body_id")
    if not isinstance(attestation["signature"], str) or not _SIGNATURE_RE.fullmatch(
        attestation["signature"]
    ):
        raise EvidenceError("endpoint signature must be canonical Ed25519 base64url")
    core = {"body": body, "body_id": expected_body_id, "attestation": attestation}
    expected_record_id = content_id("SIGNED_ENDPOINT_RECORD", core)
    if fields["record_id"] != expected_record_id:
        raise EvidenceError("record_id does not match the complete signed record")
    _canonical_bytes(fields, "endpoint record")


@dataclass(frozen=True, slots=True)
class EndpointRecord:
    """One complete, content-bound signed endpoint record."""

    record_bytes: bytes

    def __post_init__(self) -> None:
        value = _decode_canonical_object(self.record_bytes, "endpoint record")
        _validate_endpoint_record(value)

    @classmethod
    def from_dict(cls, value: Any) -> EndpointRecord:
        if not isinstance(value, Mapping):
            raise EvidenceError("endpoint record must be an object")
        return cls(_canonical_bytes(dict(value), "endpoint record"))

    @classmethod
    def from_bytes(cls, raw: Any) -> EndpointRecord:
        parsed = cls(bytes(raw) if isinstance(raw, bytes) else raw)
        if parsed.canonical_bytes != raw:
            raise EvidenceError("endpoint record bytes are not canonical")
        return parsed

    def to_dict(self) -> dict[str, Any]:
        value = loads_strict(self.record_bytes)
        assert isinstance(value, dict)
        return value

    @property
    def record_id(self) -> str:
        return self.to_dict()["record_id"]

    @property
    def body_id(self) -> str:
        return self.to_dict()["body_id"]

    @property
    def body(self) -> dict[str, Any]:
        return self.to_dict()["body"]

    @property
    def attestation(self) -> dict[str, Any]:
        return self.to_dict()["attestation"]

    @property
    def neutral_handoff(self) -> NeutralHandoff:
        return NeutralHandoff.from_dict(self.body["handoff"])

    @property
    def canonical_bytes(self) -> bytes:
        return self.record_bytes


def sign_endpoint_record(
    handoff: NeutralHandoff,
    *,
    role: EndpointRole,
    private_key: Ed25519PrivateKey,
    sender_record_id: str | None = None,
    decision: ReceiverDecision | None = None,
    reason_code: str | None = None,
    decided_at: str | None = None,
) -> EndpointRecord:
    if not isinstance(handoff, NeutralHandoff):
        raise EvidenceError("handoff must be a NeutralHandoff")
    if not isinstance(role, EndpointRole):
        raise EvidenceError("role must be an EndpointRole")
    if not isinstance(private_key, Ed25519PrivateKey):
        raise EvidenceError("private_key must be an Ed25519PrivateKey")
    handoff_body = handoff.to_dict()
    holder = handoff_body["sender" if role is EndpointRole.SENDER else "receiver"]
    body = {
        "record_version": EVIDENCE_VERSION,
        "record_type": "signed_endpoint_record",
        "holder": holder,
        "role": role.value,
        "handoff": handoff_body,
        "sender_record_id": sender_record_id,
        "decision": None if decision is None else decision.value,
        "reason_code": reason_code,
        "decided_at": decided_at,
    }
    body_id = content_id("ENDPOINT_RECORD_BODY", body)
    attestation_body = {
        "algorithm": "Ed25519",
        "key_id": holder["key_id"],
        "body_id": body_id,
    }
    attestation = {
        **attestation_body,
        "signature": sign_endpoint_attestation(attestation_body, private_key),
    }
    core = {"body": body, "body_id": body_id, "attestation": attestation}
    return EndpointRecord.from_dict(
        {"record_id": content_id("SIGNED_ENDPOINT_RECORD", core), **core}
    )


@dataclass(frozen=True, slots=True)
class SourceDelivery:
    message_id: str
    delivery_slot_id: str
    origin_store_id: str
    holder_principal_id: str
    holder_role: EndpointRole
    source_record_id: str

    def __post_init__(self) -> None:
        _require_hash(self.message_id, "source delivery message_id")
        _require_identifier(self.delivery_slot_id, "source delivery slot")
        _require_identifier(self.origin_store_id, "source delivery origin store")
        _require_identifier(
            self.holder_principal_id,
            "source delivery holder principal",
        )
        if not isinstance(self.holder_role, EndpointRole):
            raise EvidenceError("source delivery holder_role must be an EndpointRole")
        _require_hash(self.source_record_id, "source delivery source_record_id")

    @classmethod
    def from_dict(cls, value: Any) -> SourceDelivery:
        fields = _require_exact_fields(
            value,
            frozenset(
                {
                    "message_id",
                    "delivery_slot_id",
                    "origin_store_id",
                    "holder_principal_id",
                    "holder_role",
                    "source_record_id",
                }
            ),
            "source delivery",
        )
        try:
            holder_role = EndpointRole(fields["holder_role"])
        except (TypeError, ValueError) as exc:
            raise EvidenceError("source delivery holder_role is unsupported") from exc
        return cls(
            message_id=fields["message_id"],
            delivery_slot_id=fields["delivery_slot_id"],
            origin_store_id=fields["origin_store_id"],
            holder_principal_id=fields["holder_principal_id"],
            holder_role=holder_role,
            source_record_id=fields["source_record_id"],
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "message_id": self.message_id,
            "delivery_slot_id": self.delivery_slot_id,
            "origin_store_id": self.origin_store_id,
            "holder_principal_id": self.holder_principal_id,
            "holder_role": self.holder_role.value,
            "source_record_id": self.source_record_id,
        }


def _validate_binding_facts(
    representation: EvidenceRepresentation,
    value: Any,
) -> None:
    if representation is EvidenceRepresentation.SL:
        fields = _require_exact_fields(
            value,
            frozenset(
                {
                    "binding_type",
                    "sender_body_id",
                    "receiver_body_id",
                    "receiver_binds_sender_record",
                    "parent_reference_type",
                    "encoded_parent_reference",
                }
            ),
            "SL binding_facts",
        )
        if fields["binding_type"] != "INDEPENDENT_ENDPOINT_SIGNATURES":
            raise EvidenceError("invalid SL binding_type")
        if fields["receiver_binds_sender_record"] is not False:
            raise EvidenceError("SL receiver must not bind a sender record")
    elif representation is EvidenceRepresentation.CR:
        fields = _require_exact_fields(
            value,
            frozenset(
                {
                    "binding_type",
                    "sender_body_id",
                    "receiver_body_id",
                    "receiver_binds_sender_record",
                    "receiver_bound_sender_record_id",
                    "parent_reference_type",
                    "encoded_parent_reference",
                }
            ),
            "CR binding_facts",
        )
        if fields["binding_type"] != "CROSS_REFERENCED_ENDPOINT_SIGNATURES":
            raise EvidenceError("invalid CR binding_type")
        if fields["receiver_binds_sender_record"] is not True:
            raise EvidenceError("CR receiver must bind a sender record")
        _require_hash(
            fields["receiver_bound_sender_record_id"],
            "receiver_bound_sender_record_id",
        )
    else:
        fields = _require_exact_fields(
            value,
            frozenset(
                {
                    "binding_type",
                    "proposal_hash",
                    "nested_sender_attestation_bound",
                    "parent_reference_type",
                    "encoded_parent_reference",
                    "resolved_parent_receipt_id",
                }
            ),
            "PR binding_facts",
        )
        if fields["binding_type"] != "NESTED_DUAL_ATTESTATION":
            raise EvidenceError("invalid PR binding_type")
        if fields["nested_sender_attestation_bound"] is not True:
            raise EvidenceError("PR receiver must bind the sender attestation")
        _require_hash(fields["proposal_hash"], "proposal_hash")
        resolved = fields["resolved_parent_receipt_id"]
        if resolved is not None:
            _require_hash(resolved, "resolved_parent_receipt_id")
    for hash_field in ("sender_body_id", "receiver_body_id"):
        if hash_field in fields:
            _require_hash(fields[hash_field], hash_field)
    if fields["parent_reference_type"] not in {
        "SEMANTIC_INTERACTION_ID",
        "COMPLETED_RECEIPT_ID",
    }:
        raise EvidenceError("unsupported parent_reference_type")
    parent_reference = fields["encoded_parent_reference"]
    if parent_reference is not None:
        if fields["parent_reference_type"] == "SEMANTIC_INTERACTION_ID":
            _require_identifier(parent_reference, "encoded_parent_reference")
        else:
            _require_hash(parent_reference, "encoded_parent_reference")


@dataclass(frozen=True, slots=True)
class ValidatedHandoff:
    validated_handoff_id: str
    representation: EvidenceRepresentation
    handoff: NeutralHandoff
    sender_authenticated: bool
    receiver_authenticated: bool
    bilateral_agreement: bool
    receiver_decision: ReceiverDecision | None
    receiver_decided_at: str | None
    parent_relation_valid: bool
    conflict_free: bool
    delivered_holder_principal_ids: tuple[str, ...]
    source_record_ids: tuple[str, ...]
    source_message_ids: tuple[str, ...]
    source_deliveries: tuple[SourceDelivery, ...]
    validation_reasons: tuple[str, ...]
    binding_facts_bytes: bytes
    _validation_tag: bytes | None = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        _require_hash(self.validated_handoff_id, "validated_handoff_id")
        if not isinstance(self.representation, EvidenceRepresentation):
            raise EvidenceError("representation must be an EvidenceRepresentation")
        if not isinstance(self.handoff, NeutralHandoff):
            raise EvidenceError("handoff must be a NeutralHandoff")
        for field_name in (
            "sender_authenticated",
            "receiver_authenticated",
            "bilateral_agreement",
            "parent_relation_valid",
            "conflict_free",
        ):
            if type(getattr(self, field_name)) is not bool:
                raise EvidenceError(f"{field_name} must be boolean")
        if self.receiver_decision is not None and not isinstance(
            self.receiver_decision,
            ReceiverDecision,
        ):
            raise EvidenceError("receiver_decision is unsupported")
        if self.receiver_decided_at is not None:
            _parse_timestamp(self.receiver_decided_at, "receiver_decided_at")
        for name in (
            "delivered_holder_principal_ids",
            "source_record_ids",
            "source_message_ids",
            "source_deliveries",
            "validation_reasons",
        ):
            if not isinstance(getattr(self, name), tuple):
                raise EvidenceError(f"{name} must be a tuple")
        holders = tuple(sorted(set(self.delivered_holder_principal_ids)))
        for holder in holders:
            _require_identifier(holder, "delivered holder principal")
        records = tuple(sorted(set(self.source_record_ids)))
        messages = tuple(sorted(set(self.source_message_ids)))
        for record_id in records:
            _require_hash(record_id, "source_record_id")
        for message_id in messages:
            _require_hash(message_id, "source_message_id")
        if not all(isinstance(item, SourceDelivery) for item in self.source_deliveries):
            raise EvidenceError("source_deliveries must contain SourceDelivery objects")
        deliveries = tuple(
            sorted(
                self.source_deliveries,
                key=lambda item: (
                    item.message_id,
                    item.delivery_slot_id,
                    item.origin_store_id,
                    item.holder_principal_id,
                    item.holder_role.value,
                    item.source_record_id,
                ),
            )
        )
        delivery_message_ids = tuple(sorted({item.message_id for item in deliveries}))
        if len(delivery_message_ids) != len(deliveries):
            raise EvidenceError("source_deliveries must contain unique message IDs")
        delivery_holders = tuple(
            sorted({item.holder_principal_id for item in deliveries})
        )
        delivery_record_ids = tuple(
            sorted({item.source_record_id for item in deliveries})
        )
        if messages != delivery_message_ids:
            raise EvidenceError("source_message_ids do not match source_deliveries")
        if holders != delivery_holders:
            raise EvidenceError(
                "delivered_holder_principal_ids do not match source_deliveries"
            )
        if records != delivery_record_ids:
            raise EvidenceError("source_record_ids do not match source_deliveries")
        reasons = tuple(sorted(set(self.validation_reasons)))
        for reason in reasons:
            _require_identifier(reason, "validation reason")
        binding_facts = _decode_canonical_object(
            self.binding_facts_bytes,
            "binding_facts",
        )
        _validate_binding_facts(self.representation, binding_facts)
        handoff_body = self.handoff.to_dict()
        created_at = _parse_timestamp(handoff_body["created_at"], "created_at")
        if not self.sender_authenticated or not self.receiver_authenticated:
            raise EvidenceError(
                "ValidatedHandoff is emitted only after both endpoints authenticate"
            )
        if self.receiver_decision is None or self.receiver_decided_at is None:
            raise EvidenceError(
                "ValidatedHandoff requires an authenticated receiver decision"
            )
        if (
            _parse_timestamp(self.receiver_decided_at, "receiver_decided_at")
            < created_at
        ):
            raise EvidenceError("receiver_decided_at cannot precede handoff creation")
        expected_bilateral = self.receiver_decision is ReceiverDecision.ACCEPT
        if self.bilateral_agreement is not expected_bilateral:
            raise EvidenceError(
                "bilateral_agreement must reflect the authenticated receiver decision"
            )
        if not self.parent_relation_valid or not self.conflict_free:
            raise EvidenceError(
                "invalid parent relations and conflicts belong in ValidationReport"
            )
        expected_reasons = (
            ()
            if self.receiver_decision is ReceiverDecision.ACCEPT
            else ("RECEIVER_REJECTED",)
        )
        if reasons != expected_reasons:
            raise EvidenceError(
                "validation_reasons must exactly reflect an authenticated rejection"
            )
        if not deliveries:
            raise EvidenceError("ValidatedHandoff requires delivered source evidence")
        endpoint_pairs = {
            (
                handoff_body["sender"]["principal_id"],
                EndpointRole.SENDER,
            ),
            (
                handoff_body["receiver"]["principal_id"],
                EndpointRole.RECEIVER,
            ),
        }
        for delivery in deliveries:
            if (
                delivery.holder_principal_id,
                delivery.holder_role,
            ) not in endpoint_pairs:
                raise EvidenceError(
                    "source delivery holder does not match a handoff endpoint"
                )
        previous = handoff_body["previous_interaction_id"]
        if self.representation in {
            EvidenceRepresentation.SL,
            EvidenceRepresentation.CR,
        }:
            if binding_facts["parent_reference_type"] != "SEMANTIC_INTERACTION_ID":
                raise EvidenceError("SL and CR must encode semantic parent references")
            if binding_facts["encoded_parent_reference"] != previous:
                raise EvidenceError(
                    "endpoint parent reference does not match neutral handoff"
                )
            if len(records) != 2:
                raise EvidenceError("SL and CR require two signed source records")
            if {item.holder_role for item in deliveries} != {
                EndpointRole.SENDER,
                EndpointRole.RECEIVER,
            }:
                raise EvidenceError("SL and CR require both endpoint-held records")
        else:
            if binding_facts["parent_reference_type"] != "COMPLETED_RECEIPT_ID":
                raise EvidenceError(
                    "PR must encode completed-receipt parent references"
                )
            encoded_parent = binding_facts["encoded_parent_reference"]
            resolved_parent = binding_facts["resolved_parent_receipt_id"]
            if (previous is None) != (encoded_parent is None):
                raise EvidenceError(
                    "PR parent encoding does not match neutral handoff root status"
                )
            if encoded_parent != resolved_parent:
                raise EvidenceError("PR parent receipt must be delivered and resolved")
            if len(records) != 1:
                raise EvidenceError("PR requires one complete signed receipt record")
        if self.delivered_holder_principal_ids != holders:
            raise EvidenceError(
                "delivered_holder_principal_ids must be sorted and unique"
            )
        if self.source_record_ids != records:
            raise EvidenceError("source_record_ids must be sorted and unique")
        if self.source_message_ids != messages:
            raise EvidenceError("source_message_ids must be sorted and unique")
        if self.source_deliveries != deliveries:
            raise EvidenceError("source_deliveries must use canonical order")
        if self.validation_reasons != reasons:
            raise EvidenceError("validation_reasons must be sorted and unique")
        expected_id = content_id("VALIDATED_HANDOFF", self._body_dict())
        if self.validated_handoff_id != expected_id:
            raise EvidenceError(
                "validated_handoff_id does not match the normalized body"
            )
        if self._validation_tag is not None:
            if (
                not isinstance(self._validation_tag, bytes)
                or len(self._validation_tag) != 32
            ):
                raise EvidenceError("validation tag is malformed")
            expected_tag = _process_validation_tag(
                "VALIDATED_HANDOFF",
                self._validation_payload_bytes(),
            )
            if not hmac.compare_digest(self._validation_tag, expected_tag):
                raise EvidenceError("validation tag does not match normalized evidence")

    def _body_dict(self) -> dict[str, Any]:
        binding_facts = loads_strict(self.binding_facts_bytes)
        assert isinstance(binding_facts, dict)
        return {
            "version": VALIDATION_VERSION,
            "representation": self.representation.value,
            "neutral_handoff_id": self.handoff.neutral_handoff_id,
            "handoff": self.handoff.to_dict(),
            "sender_authenticated": self.sender_authenticated,
            "receiver_authenticated": self.receiver_authenticated,
            "bilateral_agreement": self.bilateral_agreement,
            "receiver_decision": (
                None if self.receiver_decision is None else self.receiver_decision.value
            ),
            "receiver_decided_at": self.receiver_decided_at,
            "parent_relation_valid": self.parent_relation_valid,
            "conflict_free": self.conflict_free,
            "delivered_holder_principal_ids": list(self.delivered_holder_principal_ids),
            "source_record_ids": list(self.source_record_ids),
            "source_message_ids": list(self.source_message_ids),
            "source_deliveries": [item.to_dict() for item in self.source_deliveries],
            "validation_reasons": list(self.validation_reasons),
            "binding_facts": binding_facts,
        }

    def _validation_payload_bytes(self) -> bytes:
        return canonical_json(
            {"validated_handoff_id": self.validated_handoff_id, **self._body_dict()}
        )

    @property
    def validator_issued(self) -> bool:
        """Whether this in-memory object came directly from the validator.

        The flag is intentionally process-local and is not serialized.
        """

        if self._validation_tag is None:
            return False
        expected = _process_validation_tag(
            "VALIDATED_HANDOFF",
            self._validation_payload_bytes(),
        )
        return hmac.compare_digest(self._validation_tag, expected)

    @classmethod
    def _build_from_validator(
        cls,
        *,
        _validator_token: object,
        representation: EvidenceRepresentation,
        handoff: NeutralHandoff,
        sender_authenticated: bool,
        receiver_authenticated: bool,
        bilateral_agreement: bool,
        receiver_decision: ReceiverDecision | None,
        receiver_decided_at: str | None,
        parent_relation_valid: bool,
        conflict_free: bool,
        source_record_ids: tuple[str, ...],
        source_deliveries: tuple[SourceDelivery, ...],
        validation_reasons: tuple[str, ...],
        binding_facts: Mapping[str, Any],
    ) -> ValidatedHandoff:
        if _validator_token is not _VALIDATOR_TOKEN:
            raise EvidenceError(
                "ValidatedHandoff construction is reserved for validate_observation"
            )
        holders = tuple(
            sorted({item.holder_principal_id for item in source_deliveries})
        )
        messages = tuple(sorted({item.message_id for item in source_deliveries}))
        records = tuple(sorted(set(source_record_ids)))
        deliveries = tuple(
            sorted(
                source_deliveries,
                key=lambda item: (
                    item.message_id,
                    item.delivery_slot_id,
                    item.origin_store_id,
                    item.holder_principal_id,
                    item.holder_role.value,
                    item.source_record_id,
                ),
            )
        )
        reasons = tuple(sorted(set(validation_reasons)))
        binding_bytes = _canonical_bytes(dict(binding_facts), "binding_facts")
        provisional = cls.__new__(cls)
        object.__setattr__(provisional, "validated_handoff_id", "sha256:" + "0" * 64)
        object.__setattr__(provisional, "representation", representation)
        object.__setattr__(provisional, "handoff", handoff)
        object.__setattr__(provisional, "sender_authenticated", sender_authenticated)
        object.__setattr__(
            provisional, "receiver_authenticated", receiver_authenticated
        )
        object.__setattr__(provisional, "bilateral_agreement", bilateral_agreement)
        object.__setattr__(provisional, "receiver_decision", receiver_decision)
        object.__setattr__(provisional, "receiver_decided_at", receiver_decided_at)
        object.__setattr__(provisional, "parent_relation_valid", parent_relation_valid)
        object.__setattr__(provisional, "conflict_free", conflict_free)
        object.__setattr__(provisional, "delivered_holder_principal_ids", holders)
        object.__setattr__(
            provisional,
            "source_record_ids",
            records,
        )
        object.__setattr__(provisional, "source_message_ids", messages)
        object.__setattr__(provisional, "source_deliveries", deliveries)
        object.__setattr__(provisional, "validation_reasons", reasons)
        object.__setattr__(provisional, "binding_facts_bytes", binding_bytes)
        validated_id = content_id("VALIDATED_HANDOFF", provisional._body_dict())
        validation_tag = _process_validation_tag(
            "VALIDATED_HANDOFF",
            canonical_json(
                {
                    "validated_handoff_id": validated_id,
                    **provisional._body_dict(),
                }
            ),
        )
        return cls(
            validated_handoff_id=validated_id,
            representation=representation,
            handoff=handoff,
            sender_authenticated=sender_authenticated,
            receiver_authenticated=receiver_authenticated,
            bilateral_agreement=bilateral_agreement,
            receiver_decision=receiver_decision,
            receiver_decided_at=receiver_decided_at,
            parent_relation_valid=parent_relation_valid,
            conflict_free=conflict_free,
            delivered_holder_principal_ids=holders,
            source_record_ids=records,
            source_message_ids=messages,
            source_deliveries=deliveries,
            validation_reasons=reasons,
            binding_facts_bytes=binding_bytes,
            _validation_tag=validation_tag,
        )

    @classmethod
    def from_dict(cls, value: Any) -> ValidatedHandoff:
        fields = _require_exact_fields(
            value,
            frozenset(
                {
                    "version",
                    "validated_handoff_id",
                    "representation",
                    "neutral_handoff_id",
                    "handoff",
                    "sender_authenticated",
                    "receiver_authenticated",
                    "bilateral_agreement",
                    "receiver_decision",
                    "receiver_decided_at",
                    "parent_relation_valid",
                    "conflict_free",
                    "delivered_holder_principal_ids",
                    "source_record_ids",
                    "source_message_ids",
                    "source_deliveries",
                    "validation_reasons",
                    "binding_facts",
                }
            ),
            "validated handoff",
        )
        if fields["version"] != VALIDATION_VERSION:
            raise EvidenceError(f"version must equal {VALIDATION_VERSION}")
        try:
            representation = EvidenceRepresentation(fields["representation"])
        except (TypeError, ValueError) as exc:
            raise EvidenceError("representation is unsupported") from exc
        handoff = NeutralHandoff.from_dict(fields["handoff"])
        if fields["neutral_handoff_id"] != handoff.neutral_handoff_id:
            raise EvidenceError("neutral_handoff_id does not match handoff")
        decision_value = fields["receiver_decision"]
        try:
            decision = (
                None if decision_value is None else ReceiverDecision(decision_value)
            )
        except (TypeError, ValueError) as exc:
            raise EvidenceError("receiver_decision is unsupported") from exc
        for array_name in (
            "delivered_holder_principal_ids",
            "source_record_ids",
            "source_message_ids",
            "source_deliveries",
            "validation_reasons",
        ):
            if not isinstance(fields[array_name], list):
                raise EvidenceError(f"{array_name} must be an array")
        return cls(
            validated_handoff_id=fields["validated_handoff_id"],
            representation=representation,
            handoff=handoff,
            sender_authenticated=fields["sender_authenticated"],
            receiver_authenticated=fields["receiver_authenticated"],
            bilateral_agreement=fields["bilateral_agreement"],
            receiver_decision=decision,
            receiver_decided_at=fields["receiver_decided_at"],
            parent_relation_valid=fields["parent_relation_valid"],
            conflict_free=fields["conflict_free"],
            delivered_holder_principal_ids=tuple(
                fields["delivered_holder_principal_ids"]
            ),
            source_record_ids=tuple(fields["source_record_ids"]),
            source_message_ids=tuple(fields["source_message_ids"]),
            source_deliveries=tuple(
                SourceDelivery.from_dict(item) for item in fields["source_deliveries"]
            ),
            validation_reasons=tuple(fields["validation_reasons"]),
            binding_facts_bytes=_canonical_bytes(
                fields["binding_facts"],
                "binding_facts",
            ),
        )

    @classmethod
    def from_bytes(cls, raw: Any) -> ValidatedHandoff:
        parsed = cls.from_dict(_decode_canonical_object(raw, "validated handoff"))
        if parsed.canonical_bytes != raw:
            raise EvidenceError("validated handoff object order is not canonical")
        return parsed

    def to_dict(self) -> dict[str, Any]:
        return {"validated_handoff_id": self.validated_handoff_id, **self._body_dict()}

    @property
    def canonical_bytes(self) -> bytes:
        return canonical_json(self.to_dict())

    def policy_view(self) -> PolicyView:
        """Return a validator-issued, representation-blind policy input.

        Objects recreated from serialized normalized JSON are audit records,
        not policy credentials. Revalidate their source observation first.
        """

        if type(self) is not ValidatedHandoff or not self.validator_issued:
            raise EvidenceError(
                "deserialized ValidatedHandoff must be revalidated before policy use"
            )
        body = {
            "version": POLICY_VIEW_VERSION,
            "neutral_handoff_id": self.handoff.neutral_handoff_id,
            "handoff": self.handoff.to_dict(),
            "sender_authenticated": self.sender_authenticated,
            "receiver_authenticated": self.receiver_authenticated,
            "bilateral_agreement": self.bilateral_agreement,
            "receiver_decision": (
                None if self.receiver_decision is None else self.receiver_decision.value
            ),
            "receiver_decided_at": self.receiver_decided_at,
            "parent_relation_valid": self.parent_relation_valid,
            "conflict_free": self.conflict_free,
        }
        return PolicyView._from_validator(body, _validator_token=_VALIDATOR_TOKEN)


def _parse_policy_view_fields(
    value: Any,
) -> tuple[Mapping[str, Any], NeutralHandoff, ReceiverDecision]:
    fields = _require_exact_fields(
        value,
        frozenset(
            {
                "version",
                "neutral_handoff_id",
                "handoff",
                "sender_authenticated",
                "receiver_authenticated",
                "bilateral_agreement",
                "receiver_decision",
                "receiver_decided_at",
                "parent_relation_valid",
                "conflict_free",
            }
        ),
        "policy_view",
    )
    if fields["version"] != POLICY_VIEW_VERSION:
        raise EvidenceError(f"policy_view.version must equal {POLICY_VIEW_VERSION}")
    handoff = NeutralHandoff.from_dict(fields["handoff"])
    if fields["neutral_handoff_id"] != handoff.neutral_handoff_id:
        raise EvidenceError("policy_view neutral_handoff_id does not match handoff")
    for field_name in (
        "sender_authenticated",
        "receiver_authenticated",
        "bilateral_agreement",
        "parent_relation_valid",
        "conflict_free",
    ):
        if type(fields[field_name]) is not bool:
            raise EvidenceError(f"policy_view.{field_name} must be boolean")
    try:
        receiver_decision = ReceiverDecision(fields["receiver_decision"])
    except (TypeError, ValueError) as exc:
        raise EvidenceError("policy_view.receiver_decision is unsupported") from exc
    if fields["receiver_decided_at"] is None:
        raise EvidenceError("policy_view.receiver_decided_at is required")
    decided_at = _parse_timestamp(
        fields["receiver_decided_at"],
        "policy_view.receiver_decided_at",
    )
    if decided_at < _parse_timestamp(handoff.to_dict()["created_at"], "created_at"):
        raise EvidenceError("policy_view receiver decision precedes handoff creation")
    _canonical_bytes(dict(fields), "policy_view")
    return fields, handoff, receiver_decision


@dataclass(frozen=True, slots=True)
class PolicyView:
    """Representation-blind policy input issued by this process's validator.

    Serialized forms are useful for audit, but are deliberately not portable
    authorization credentials.
    """

    body_bytes: bytes
    _validation_tag: bytes | None = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        body = _decode_canonical_object(self.body_bytes, "policy_view")
        _parse_policy_view_fields(body)
        if self._validation_tag is not None:
            if (
                not isinstance(self._validation_tag, bytes)
                or len(self._validation_tag) != 32
            ):
                raise EvidenceError("policy_view validation tag is malformed")
            expected = _process_validation_tag("POLICY_VIEW", self.body_bytes)
            if not hmac.compare_digest(self._validation_tag, expected):
                raise EvidenceError("policy_view validation tag is invalid")

    @classmethod
    def _from_validator(
        cls,
        value: Mapping[str, Any],
        *,
        _validator_token: object,
    ) -> PolicyView:
        if _validator_token is not _VALIDATOR_TOKEN:
            raise EvidenceError("PolicyView can only be issued by the validator")
        body_bytes = _canonical_bytes(dict(value), "policy_view")
        return cls(
            body_bytes=body_bytes,
            _validation_tag=_process_validation_tag("POLICY_VIEW", body_bytes),
        )

    @classmethod
    def from_dict(cls, value: Any) -> PolicyView:
        if not isinstance(value, Mapping):
            raise EvidenceError("policy_view must be an object")
        return cls(body_bytes=_canonical_bytes(dict(value), "policy_view"))

    @classmethod
    def from_bytes(cls, raw: Any) -> PolicyView:
        parsed = cls(body_bytes=bytes(raw) if isinstance(raw, bytes) else raw)
        if parsed.canonical_bytes != raw:
            raise EvidenceError("policy_view bytes are not canonical")
        return parsed

    @property
    def validator_issued(self) -> bool:
        if self._validation_tag is None:
            return False
        expected = _process_validation_tag("POLICY_VIEW", self.body_bytes)
        return hmac.compare_digest(self._validation_tag, expected)

    def to_dict(self) -> dict[str, Any]:
        value = loads_strict(self.body_bytes)
        assert isinstance(value, dict)
        return value

    @property
    def canonical_bytes(self) -> bytes:
        return self.body_bytes


@dataclass(frozen=True, slots=True)
class EvidencePolicyDecision:
    verdict: str
    reasons: tuple[str, ...]
    neutral_handoff_id: str

    def __post_init__(self) -> None:
        if self.verdict not in {"ALLOW", "PAUSE"}:
            raise EvidenceError("policy verdict must be ALLOW or PAUSE")
        _require_hash(self.neutral_handoff_id, "neutral_handoff_id")
        if not isinstance(self.reasons, tuple):
            raise EvidenceError("policy reasons must be a tuple")
        reasons = tuple(sorted(set(self.reasons)))
        for reason in reasons:
            _require_identifier(reason, "policy reason")
        if (self.verdict == "ALLOW") != (not reasons):
            raise EvidenceError("ALLOW requires no reasons and PAUSE requires reasons")
        object.__setattr__(self, "reasons", reasons)

    @property
    def allowed(self) -> bool:
        return self.verdict == "ALLOW"

    def to_dict(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict,
            "reasons": list(self.reasons),
            "neutral_handoff_id": self.neutral_handoff_id,
        }


def evaluate_common_evidence_policy(
    policy_view: PolicyView,
) -> EvidencePolicyDecision:
    """Apply representation-neutral evidence-admission predicates.

    The strict input is the result of :meth:`ValidatedHandoff.policy_view`, not
    a ``ValidatedHandoff``.  This makes representation and binding provenance
    unavailable to the common policy by construction.  It is not yet the full
    action, authority-status, scope, or permit policy.
    """

    if type(policy_view) is not PolicyView or not policy_view.validator_issued:
        raise EvidenceError(
            "policy_view must be issued directly by validate_observation"
        )
    fields, handoff, receiver_decision = _parse_policy_view_fields(
        policy_view.to_dict()
    )
    reasons: list[str] = []
    if not fields["sender_authenticated"]:
        reasons.append("SENDER_UNAUTHENTICATED")
    if not fields["receiver_authenticated"]:
        reasons.append("RECEIVER_UNAUTHENTICATED")
    if not fields["bilateral_agreement"]:
        reasons.append("BILATERAL_AGREEMENT_MISSING")
    if receiver_decision is ReceiverDecision.REJECT:
        reasons.append("RECEIVER_REJECTED")
    if not fields["parent_relation_valid"]:
        reasons.append("PARENT_RELATION_INVALID")
    if not fields["conflict_free"]:
        reasons.append("EQUIVOCATION")
    return EvidencePolicyDecision(
        verdict="ALLOW" if not reasons else "PAUSE",
        reasons=tuple(reasons),
        neutral_handoff_id=handoff.neutral_handoff_id,
    )
