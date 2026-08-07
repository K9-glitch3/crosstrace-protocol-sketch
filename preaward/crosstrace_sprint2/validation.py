"""Fail-closed validators for the three Sprint 2 evidence representations.

The validators consume only a Sprint 1 local or audit observation.  They do
not reconstruct a global inbox, choose between conflicting signed records, or
use transport metadata as a substitute for an authenticated endpoint.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Iterable, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from crosstrace_sketch.protocol import (
    KeyRegistry,
    PROTOCOL_VERSION,
    ProtocolError,
    SCOPE_PROFILE,
    canonical_json,
    content_id,
    make_proposal,
    receipt_id,
    sign_receipt,
)
from preaward.crosstrace_sprint1 import (
    AuditObservation,
    DeliveredMessage,
    LocalObservation,
    PayloadKind,
)

from .crypto_compat import (
    verify_endpoint_attestation,
    verify_p0_receiver_attestation,
    verify_p0_sender_attestation,
)
from .model import (
    VALIDATION_VERSION,
    EndpointRecord,
    EndpointRole,
    EvidenceError,
    EvidenceRepresentation,
    NeutralHandoff,
    ReceiverDecision,
    SourceDelivery,
    ValidatedHandoff,
    _VALIDATOR_TOKEN,
    _parse_timestamp,
    _require_exact_fields,
    _require_hash,
    _require_identifier,
)

_HANDOFF_PAYLOAD_KINDS = frozenset(
    {
        PayloadKind.SIGNED_ENDPOINT_RECORD,
        PayloadKind.CROSS_REFERENCED_RECORD,
        PayloadKind.RECEIPT,
    }
)
_EXPECTED_PAYLOAD_KIND = {
    EvidenceRepresentation.SL: PayloadKind.SIGNED_ENDPOINT_RECORD,
    EvidenceRepresentation.CR: PayloadKind.CROSS_REFERENCED_RECORD,
    EvidenceRepresentation.PR: PayloadKind.RECEIPT,
}


@dataclass(frozen=True, slots=True)
class _StoreBinding:
    principal_id: str
    roles: frozenset[EndpointRole]


class StoreRegistry:
    """Explicitly bind evidence origins to principals and endpoint roles."""

    def __init__(self) -> None:
        self._stores: dict[str, _StoreBinding] = {}

    def add(
        self,
        *,
        store_id: str,
        principal_id: str,
        roles: Iterable[EndpointRole],
    ) -> None:
        _require_identifier(store_id, "store_id")
        _require_identifier(principal_id, "store principal_id")
        try:
            role_set = frozenset(roles)
        except TypeError as exc:
            raise EvidenceError("store roles must be an iterable") from exc
        if not role_set or not all(isinstance(role, EndpointRole) for role in role_set):
            raise EvidenceError(
                "store roles must be a non-empty set of EndpointRole values"
            )
        candidate = _StoreBinding(principal_id=principal_id, roles=role_set)
        existing = self._stores.get(store_id)
        if existing is not None and existing != candidate:
            raise EvidenceError(f"store_id already registered: {store_id}")
        self._stores[store_id] = candidate

    def resolve(
        self,
        *,
        store_id: str,
        principal_id: str,
        role: EndpointRole,
    ) -> _StoreBinding:
        if not isinstance(role, EndpointRole):
            raise EvidenceError("store role must be an EndpointRole")
        binding = self._stores.get(store_id)
        if (
            binding is None
            or binding.principal_id != principal_id
            or role not in binding.roles
        ):
            raise KeyError(store_id)
        return binding


@dataclass(frozen=True, slots=True)
class ValidationIssue:
    """A stable fail-closed reason attached to visible source messages."""

    reason_code: str
    interaction_id: str | None = None
    source_message_ids: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _require_identifier(self.reason_code, "validation issue reason_code")
        if self.interaction_id is not None:
            _require_identifier(self.interaction_id, "validation issue interaction_id")
        if not isinstance(self.source_message_ids, tuple):
            raise EvidenceError("validation issue source_message_ids must be a tuple")
        message_ids = tuple(sorted(set(self.source_message_ids)))
        for message_id in message_ids:
            _require_hash(message_id, "validation issue source message_id")
        object.__setattr__(self, "source_message_ids", message_ids)

    def to_dict(self) -> dict[str, Any]:
        return {
            "reason_code": self.reason_code,
            "interaction_id": self.interaction_id,
            "source_message_ids": list(self.source_message_ids),
        }


@dataclass(frozen=True, slots=True)
class ValidationReport:
    """Deterministic normalized output plus evidence-admission failures."""

    representation: EvidenceRepresentation
    validated_handoffs: tuple[ValidatedHandoff, ...]
    issues: tuple[ValidationIssue, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.representation, EvidenceRepresentation):
            raise EvidenceError(
                "report representation must be an EvidenceRepresentation"
            )
        if not isinstance(self.validated_handoffs, tuple) or not all(
            isinstance(item, ValidatedHandoff) for item in self.validated_handoffs
        ):
            raise EvidenceError(
                "validated_handoffs must be a tuple of ValidatedHandoff"
            )
        if not isinstance(self.issues, tuple) or not all(
            isinstance(item, ValidationIssue) for item in self.issues
        ):
            raise EvidenceError("issues must be a tuple of ValidationIssue")
        handoffs = tuple(
            sorted(
                self.validated_handoffs,
                key=lambda item: (
                    item.handoff.to_dict()["interaction_id"],
                    item.validated_handoff_id,
                ),
            )
        )
        if len({item.handoff.neutral_handoff_id for item in handoffs}) != len(handoffs):
            raise EvidenceError(
                "validation report contains a duplicate neutral handoff"
            )
        issues = tuple(
            sorted(
                set(self.issues),
                key=lambda item: (
                    item.interaction_id or "",
                    item.reason_code,
                    item.source_message_ids,
                ),
            )
        )
        object.__setattr__(self, "validated_handoffs", handoffs)
        object.__setattr__(self, "issues", issues)

    @property
    def handoffs(self) -> tuple[ValidatedHandoff, ...]:
        """Short read-only alias for callers that already name the report."""

        return self.validated_handoffs

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": VALIDATION_VERSION,
            "representation": self.representation.value,
            "validated_handoffs": [item.to_dict() for item in self.validated_handoffs],
            "issues": [item.to_dict() for item in self.issues],
        }

    @property
    def canonical_bytes(self) -> bytes:
        return canonical_json(self.to_dict())


class _IssueCollector:
    def __init__(self) -> None:
        self._issues: set[ValidationIssue] = set()

    def add(
        self,
        reason_code: str,
        *,
        interaction_id: str | None = None,
        source_message_ids: Iterable[str] = (),
    ) -> None:
        self._issues.add(
            ValidationIssue(
                reason_code=reason_code,
                interaction_id=interaction_id,
                source_message_ids=tuple(source_message_ids),
            )
        )

    def result(self) -> tuple[ValidationIssue, ...]:
        return tuple(self._issues)

    def has(self, reason_code: str) -> bool:
        return any(issue.reason_code == reason_code for issue in self._issues)


@dataclass(slots=True)
class _EndpointAggregate:
    record: EndpointRecord
    deliveries: dict[str, SourceDelivery]


@dataclass(slots=True)
class _ReceiptAggregate:
    receipt: dict[str, Any]
    record_id: str
    proposal: dict[str, Any]
    decision: ReceiverDecision
    decided_at: str
    deliveries: dict[str, SourceDelivery]


@dataclass(frozen=True, slots=True)
class _Candidate:
    handoff: NeutralHandoff
    decision: ReceiverDecision
    decided_at: str
    source_record_ids: tuple[str, ...]
    source_deliveries: tuple[SourceDelivery, ...]
    binding_facts: Mapping[str, Any]

    @property
    def interaction_id(self) -> str:
        return self.handoff.to_dict()["interaction_id"]

    @property
    def source_message_ids(self) -> tuple[str, ...]:
        return tuple(delivery.message_id for delivery in self.source_deliveries)


def _source_delivery(
    message: DeliveredMessage,
    *,
    source_record_id: str,
    principal_id: str,
    role: EndpointRole,
) -> SourceDelivery:
    return SourceDelivery(
        message_id=message.message_id,
        delivery_slot_id=message.delivery_slot_id,
        origin_store_id=message.origin_store_id,
        source_record_id=source_record_id,
        holder_principal_id=principal_id,
        holder_role=role,
    )


def _cutoff(observation: LocalObservation | AuditObservation) -> datetime:
    if isinstance(observation, LocalObservation):
        return observation.decision_time
    return observation.cutoff


def _exceeds_with_skew(
    value: datetime,
    reference: datetime,
    clock_skew: timedelta,
) -> bool:
    """Return whether value is later than reference plus skew, without overflow."""

    return value > reference and value - reference > clock_skew


def _unique_messages(
    observation: LocalObservation | AuditObservation,
) -> tuple[DeliveredMessage, ...]:
    # Sprint 1 deliberately makes this collapse transmission duplicates by
    # message_id while preserving independently addressed holder copies.
    return observation.unique_evidence()


def _profile_messages(
    observation: LocalObservation | AuditObservation,
    representation: EvidenceRepresentation,
    issues: _IssueCollector,
) -> tuple[DeliveredMessage, ...]:
    expected = _EXPECTED_PAYLOAD_KIND[representation]
    selected: list[DeliveredMessage] = []
    for message in _unique_messages(observation):
        if message.payload_kind is expected:
            selected.append(message)
        elif message.payload_kind in _HANDOFF_PAYLOAD_KINDS:
            issues.add(
                "PAYLOAD_KIND_MISMATCH",
                source_message_ids=(message.message_id,),
            )
        # Authority-status and protocol-signal messages may coexist in a view,
        # but neither is interpreted as handoff evidence here.
    return tuple(selected)


def _validate_endpoint_messages(
    messages: tuple[DeliveredMessage, ...],
    *,
    representation: EvidenceRepresentation,
    key_registry: KeyRegistry,
    store_registry: StoreRegistry,
    cutoff: datetime,
    clock_skew: timedelta,
    issues: _IssueCollector,
) -> tuple[dict[str, _Candidate], set[str]]:
    aggregates: dict[str, _EndpointAggregate] = {}
    profile_violation_interactions: set[str] = set()

    for message in messages:
        try:
            record = EndpointRecord.from_dict(message.payload)
        except (EvidenceError, ProtocolError, TypeError, ValueError):
            issues.add("MALFORMED_EVIDENCE", source_message_ids=(message.message_id,))
            continue

        body = record.body
        interaction_id = body["handoff"]["interaction_id"]
        role = EndpointRole(body["role"])
        if representation is EvidenceRepresentation.SL:
            profile_ok = body["sender_record_id"] is None
        else:
            profile_ok = (
                body["sender_record_id"] is None
                if role is EndpointRole.SENDER
                else body["sender_record_id"] is not None
            )
        created_at = _parse_timestamp(body["handoff"]["created_at"], "created_at")
        holder = body["holder"]
        try:
            public_key = key_registry.resolve(
                principal_id=holder["principal_id"],
                key_id=holder["key_id"],
                required_role="receipt",
            )
        except KeyError:
            issues.add(
                "UNKNOWN_SIGNER",
                interaction_id=interaction_id,
                source_message_ids=(message.message_id,),
            )
            continue
        attestation = record.attestation
        attestation_body = {
            "algorithm": attestation["algorithm"],
            "key_id": attestation["key_id"],
            "body_id": attestation["body_id"],
        }
        try:
            verify_endpoint_attestation(
                attestation_body,
                attestation["signature"],
                public_key,
            )
        except (InvalidSignature, ProtocolError, TypeError, ValueError):
            issues.add(
                "SIGNATURE_INVALID",
                interaction_id=interaction_id,
                source_message_ids=(message.message_id,),
            )
            continue
        try:
            store_registry.resolve(
                store_id=message.origin_store_id,
                principal_id=holder["principal_id"],
                role=role,
            )
        except KeyError:
            issues.add(
                "STORE_BINDING_INVALID",
                interaction_id=interaction_id,
                source_message_ids=(message.message_id,),
            )
            continue
        # Profile checks become authoritative only after signature and declared
        # store binding have been established. An authenticated out-of-profile
        # record poisons the whole interaction; it cannot be discarded while a
        # convenient in-profile pair is used.
        if not profile_ok:
            profile_violation_interactions.add(interaction_id)
            issues.add(
                "PROFILE_VIOLATION",
                interaction_id=interaction_id,
                source_message_ids=(message.message_id,),
            )
            continue
        if _exceeds_with_skew(created_at, message.sent_at, clock_skew):
            issues.add(
                "TEMPORAL_INCONSISTENCY",
                interaction_id=interaction_id,
                source_message_ids=(message.message_id,),
            )
            continue
        if role is EndpointRole.RECEIVER:
            decided_at = _parse_timestamp(body["decided_at"], "decided_at")
            if _exceeds_with_skew(decided_at, message.sent_at, clock_skew):
                issues.add(
                    "TEMPORAL_INCONSISTENCY",
                    interaction_id=interaction_id,
                    source_message_ids=(message.message_id,),
                )
                continue
            if _exceeds_with_skew(decided_at, cutoff, clock_skew):
                issues.add(
                    "FUTURE_DECISION",
                    interaction_id=interaction_id,
                    source_message_ids=(message.message_id,),
                )
                continue

        delivery = _source_delivery(
            message,
            source_record_id=record.record_id,
            principal_id=holder["principal_id"],
            role=role,
        )
        aggregate = aggregates.setdefault(
            record.record_id,
            _EndpointAggregate(record=record, deliveries={}),
        )
        aggregate.deliveries.setdefault(message.message_id, delivery)

    grouped: dict[str, dict[EndpointRole, dict[str, _EndpointAggregate]]] = defaultdict(
        lambda: defaultdict(dict)
    )
    sequence_groups: dict[tuple[str, str, int], dict[str, list[_EndpointAggregate]]] = (
        defaultdict(lambda: defaultdict(list))
    )
    for record_id, aggregate in aggregates.items():
        body = aggregate.record.body
        interaction_id = body["handoff"]["interaction_id"]
        role = EndpointRole(body["role"])
        grouped[interaction_id][role][record_id] = aggregate
        if role is EndpointRole.SENDER:
            sequence_key = (
                body["handoff"]["sender"]["principal_id"],
                body["handoff"]["sender"]["key_id"],
                body["handoff"]["sender_sequence"],
            )
            sequence_groups[sequence_key][interaction_id].append(aggregate)

    sequence_conflicts: set[str] = set()
    for by_interaction in sequence_groups.values():
        if len(by_interaction) <= 1:
            continue
        sequence_conflicts.update(by_interaction)
        all_messages = tuple(
            delivery.message_id
            for candidates in by_interaction.values()
            for aggregate in candidates
            for delivery in aggregate.deliveries.values()
        )
        for interaction_id in by_interaction:
            issues.add(
                "EQUIVOCATION",
                interaction_id=interaction_id,
                source_message_ids=all_messages,
            )

    candidates: dict[str, _Candidate] = {}
    invalid_interactions: set[str] = set(profile_violation_interactions)
    for interaction_id in sorted(grouped):
        roles = grouped[interaction_id]
        sender_records = roles.get(EndpointRole.SENDER, {})
        receiver_records = roles.get(EndpointRole.RECEIVER, {})
        visible_messages = tuple(
            delivery.message_id
            for records in roles.values()
            for aggregate in records.values()
            for delivery in aggregate.deliveries.values()
        )
        if interaction_id in profile_violation_interactions:
            continue
        if len(sender_records) > 1 or len(receiver_records) > 1:
            invalid_interactions.add(interaction_id)
            issues.add(
                "EQUIVOCATION",
                interaction_id=interaction_id,
                source_message_ids=visible_messages,
            )
            continue
        if len(sender_records) != 1 or len(receiver_records) != 1:
            invalid_interactions.add(interaction_id)
            issues.add(
                "ENDPOINT_MISSING",
                interaction_id=interaction_id,
                source_message_ids=visible_messages,
            )
            continue
        if interaction_id in sequence_conflicts:
            invalid_interactions.add(interaction_id)
            continue

        sender = next(iter(sender_records.values()))
        receiver = next(iter(receiver_records.values()))
        sender_handoff = sender.record.neutral_handoff
        receiver_handoff = receiver.record.neutral_handoff
        if sender_handoff.canonical_bytes != receiver_handoff.canonical_bytes:
            invalid_interactions.add(interaction_id)
            issues.add(
                "ENDPOINT_MISMATCH",
                interaction_id=interaction_id,
                source_message_ids=visible_messages,
            )
            continue
        receiver_body = receiver.record.body
        if (
            representation is EvidenceRepresentation.CR
            and receiver_body["sender_record_id"] != sender.record.record_id
        ):
            invalid_interactions.add(interaction_id)
            issues.add(
                "CROSS_REFERENCE_INVALID",
                interaction_id=interaction_id,
                source_message_ids=visible_messages,
            )
            continue

        handoff_body = sender_handoff.to_dict()
        if representation is EvidenceRepresentation.SL:
            binding_facts: dict[str, Any] = {
                "binding_type": "INDEPENDENT_ENDPOINT_SIGNATURES",
                "sender_body_id": sender.record.body_id,
                "receiver_body_id": receiver.record.body_id,
                "receiver_binds_sender_record": False,
                "parent_reference_type": "SEMANTIC_INTERACTION_ID",
                "encoded_parent_reference": handoff_body["previous_interaction_id"],
            }
        else:
            binding_facts = {
                "binding_type": "CROSS_REFERENCED_ENDPOINT_SIGNATURES",
                "sender_body_id": sender.record.body_id,
                "receiver_body_id": receiver.record.body_id,
                "receiver_binds_sender_record": True,
                "receiver_bound_sender_record_id": receiver_body["sender_record_id"],
                "parent_reference_type": "SEMANTIC_INTERACTION_ID",
                "encoded_parent_reference": handoff_body["previous_interaction_id"],
            }
        deliveries = tuple(
            list(sender.deliveries.values()) + list(receiver.deliveries.values())
        )
        candidates[interaction_id] = _Candidate(
            handoff=sender_handoff,
            decision=ReceiverDecision(receiver_body["decision"]),
            decided_at=receiver_body["decided_at"],
            source_record_ids=(sender.record.record_id, receiver.record.record_id),
            source_deliveries=deliveries,
            binding_facts=binding_facts,
        )

    invalid_interactions.update(set(grouped) - set(candidates))
    return candidates, invalid_interactions


def _validate_p0_proposal(value: Any) -> dict[str, Any]:
    proposal = dict(
        _require_exact_fields(
            value,
            frozenset(
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
                }
            ),
            "P0 proposal",
        )
    )
    if (
        proposal["protocol_version"] != PROTOCOL_VERSION
        or proposal["type"] != "handoff_proposal"
        or proposal["scope_profile"] != SCOPE_PROFILE
    ):
        raise EvidenceError("P0 proposal is outside the frozen P0 profile")
    rebuilt = make_proposal(
        interaction_id=proposal["interaction_id"],
        event_type=proposal["event_type"],
        created_at=proposal["created_at"],
        nonce=proposal["nonce"],
        sender=proposal["sender"],
        receiver=proposal["receiver"],
        sender_sequence=proposal["sender_sequence"],
        previous_receipt_id=proposal["previous_receipt_id"],
        scope=proposal["scope"],
        authority=proposal["authority"],
        request_hash=proposal["request_hash"],
    )
    if rebuilt != proposal:
        raise EvidenceError("P0 proposal is not in the exact frozen profile")
    return proposal


def _parse_p0_receipt(value: Any) -> tuple[
    dict[str, Any],
    dict[str, Any],
    dict[str, Any],
    dict[str, Any],
    ReceiverDecision,
    str,
]:
    receipt = dict(
        _require_exact_fields(
            value,
            frozenset(
                {
                    "proposal",
                    "proposal_hash",
                    "sender_attestation",
                    "receiver_attestation",
                }
            ),
            "P0 receipt",
        )
    )
    proposal = _validate_p0_proposal(receipt["proposal"])
    expected_hash = content_id("PROPOSAL", proposal)
    if receipt["proposal_hash"] != expected_hash:
        raise EvidenceError("P0 proposal_hash does not match proposal")
    sender = dict(
        _require_exact_fields(
            receipt["sender_attestation"],
            frozenset({"algorithm", "key_id", "proposal_hash", "signature"}),
            "P0 sender attestation",
        )
    )
    receiver = dict(
        _require_exact_fields(
            receipt["receiver_attestation"],
            frozenset(
                {
                    "algorithm",
                    "key_id",
                    "proposal_hash",
                    "sender_attestation",
                    "decision",
                    "reason_code",
                    "decided_at",
                    "signature",
                }
            ),
            "P0 receiver attestation",
        )
    )
    if (
        sender["algorithm"] != "Ed25519"
        or sender["key_id"] != proposal["sender"]["key_id"]
        or sender["proposal_hash"] != expected_hash
    ):
        raise EvidenceError("P0 sender attestation metadata is inconsistent")
    if (
        receiver["algorithm"] != "Ed25519"
        or receiver["key_id"] != proposal["receiver"]["key_id"]
        or receiver["proposal_hash"] != expected_hash
        or receiver["sender_attestation"] != sender
    ):
        raise EvidenceError("P0 receiver attestation does not bind the sender")
    try:
        decision = ReceiverDecision(receiver["decision"])
    except (TypeError, ValueError) as exc:
        raise EvidenceError("P0 receiver decision is unsupported") from exc
    decided_at = receiver["decided_at"]
    decided_time = _parse_timestamp(decided_at, "P0 decided_at")
    if decided_time < _parse_timestamp(proposal["created_at"], "P0 created_at"):
        raise EvidenceError("P0 receiver decision precedes proposal creation")
    if decision is ReceiverDecision.ACCEPT:
        if receiver["reason_code"] is not None:
            raise EvidenceError("accepted P0 receipt must have no reason_code")
    else:
        _require_identifier(receiver["reason_code"], "P0 rejection reason_code")
    return receipt, proposal, sender, receiver, decision, decided_at


def _receipt_store_role(
    message: DeliveredMessage,
    proposal: Mapping[str, Any],
    store_registry: StoreRegistry,
) -> tuple[str, EndpointRole]:
    matches: list[tuple[str, EndpointRole]] = []
    for party_name, role in (
        ("sender", EndpointRole.SENDER),
        ("receiver", EndpointRole.RECEIVER),
    ):
        principal_id = proposal[party_name]["principal_id"]
        try:
            store_registry.resolve(
                store_id=message.origin_store_id,
                principal_id=principal_id,
                role=role,
            )
        except KeyError:
            continue
        matches.append((principal_id, role))
    if len(matches) != 1:
        raise KeyError(message.origin_store_id)
    return matches[0]


def _validate_receipt_messages(
    messages: tuple[DeliveredMessage, ...],
    *,
    key_registry: KeyRegistry,
    store_registry: StoreRegistry,
    cutoff: datetime,
    clock_skew: timedelta,
    issues: _IssueCollector,
) -> tuple[dict[str, _Candidate], set[str]]:
    aggregates: dict[str, _ReceiptAggregate] = {}
    profile_violation_interactions: set[str] = set()

    for message in messages:
        try:
            receipt, proposal, sender, receiver, decision, decided_at = (
                _parse_p0_receipt(message.payload)
            )
        except (EvidenceError, ProtocolError, TypeError, ValueError):
            issues.add("MALFORMED_EVIDENCE", source_message_ids=(message.message_id,))
            continue
        interaction_id = proposal["interaction_id"]
        profile_ok = proposal["nonce"] == interaction_id
        created_time = _parse_timestamp(proposal["created_at"], "P0 created_at")
        decided_time = _parse_timestamp(decided_at, "P0 decided_at")
        try:
            sender_key = key_registry.resolve(
                principal_id=proposal["sender"]["principal_id"],
                key_id=proposal["sender"]["key_id"],
                required_role="receipt",
            )
            receiver_key = key_registry.resolve(
                principal_id=proposal["receiver"]["principal_id"],
                key_id=proposal["receiver"]["key_id"],
                required_role="receipt",
            )
        except KeyError:
            issues.add(
                "UNKNOWN_SIGNER",
                interaction_id=interaction_id,
                source_message_ids=(message.message_id,),
            )
            continue
        sender_body = {
            "algorithm": sender["algorithm"],
            "key_id": sender["key_id"],
            "proposal_hash": sender["proposal_hash"],
        }
        receiver_body = {
            "algorithm": receiver["algorithm"],
            "key_id": receiver["key_id"],
            "proposal_hash": receiver["proposal_hash"],
            "sender_attestation": receiver["sender_attestation"],
            "decision": receiver["decision"],
            "reason_code": receiver["reason_code"],
            "decided_at": receiver["decided_at"],
        }
        try:
            verify_p0_sender_attestation(sender_body, sender["signature"], sender_key)
            verify_p0_receiver_attestation(
                receiver_body,
                receiver["signature"],
                receiver_key,
            )
        except (InvalidSignature, ProtocolError, TypeError, ValueError):
            issues.add(
                "SIGNATURE_INVALID",
                interaction_id=interaction_id,
                source_message_ids=(message.message_id,),
            )
            continue
        try:
            holder_principal, holder_role = _receipt_store_role(
                message,
                proposal,
                store_registry,
            )
        except KeyError:
            issues.add(
                "STORE_BINDING_INVALID",
                interaction_id=interaction_id,
                source_message_ids=(message.message_id,),
            )
            continue
        # As with endpoint records, only authenticated, store-bound evidence
        # establishes a profile violation. Once established, the violation
        # taints the interaction even if a separate fair-profile receipt exists.
        if not profile_ok:
            profile_violation_interactions.add(interaction_id)
            issues.add(
                "PROFILE_VIOLATION",
                interaction_id=interaction_id,
                source_message_ids=(message.message_id,),
            )
            continue
        if _exceeds_with_skew(
            created_time, message.sent_at, clock_skew
        ) or _exceeds_with_skew(
            decided_time,
            message.sent_at,
            clock_skew,
        ):
            issues.add(
                "TEMPORAL_INCONSISTENCY",
                interaction_id=interaction_id,
                source_message_ids=(message.message_id,),
            )
            continue
        if _exceeds_with_skew(decided_time, cutoff, clock_skew):
            issues.add(
                "FUTURE_DECISION",
                interaction_id=interaction_id,
                source_message_ids=(message.message_id,),
            )
            continue

        record_id = receipt_id(receipt)
        delivery = _source_delivery(
            message,
            source_record_id=record_id,
            principal_id=holder_principal,
            role=holder_role,
        )
        aggregate = aggregates.setdefault(
            record_id,
            _ReceiptAggregate(
                receipt=receipt,
                record_id=record_id,
                proposal=proposal,
                decision=decision,
                decided_at=decided_at,
                deliveries={},
            ),
        )
        aggregate.deliveries.setdefault(message.message_id, delivery)

    grouped: dict[str, dict[str, _ReceiptAggregate]] = defaultdict(dict)
    sequence_groups: dict[tuple[str, str, int], dict[str, list[_ReceiptAggregate]]] = (
        defaultdict(lambda: defaultdict(list))
    )
    for record_id, aggregate in aggregates.items():
        interaction_id = aggregate.proposal["interaction_id"]
        grouped[interaction_id][record_id] = aggregate
        sequence_key = (
            aggregate.proposal["sender"]["principal_id"],
            aggregate.proposal["sender"]["key_id"],
            aggregate.proposal["sender_sequence"],
        )
        sequence_groups[sequence_key][interaction_id].append(aggregate)

    sequence_conflicts: set[str] = set()
    for by_interaction in sequence_groups.values():
        if len(by_interaction) <= 1:
            continue
        sequence_conflicts.update(by_interaction)
        message_ids = tuple(
            delivery.message_id
            for candidates in by_interaction.values()
            for aggregate in candidates
            for delivery in aggregate.deliveries.values()
        )
        for interaction_id in by_interaction:
            issues.add(
                "EQUIVOCATION",
                interaction_id=interaction_id,
                source_message_ids=message_ids,
            )

    selected: dict[str, _ReceiptAggregate] = {}
    invalid_interactions: set[str] = set(profile_violation_interactions)
    for interaction_id in sorted(grouped):
        records = grouped[interaction_id]
        message_ids = tuple(
            delivery.message_id
            for aggregate in records.values()
            for delivery in aggregate.deliveries.values()
        )
        if interaction_id in profile_violation_interactions:
            continue
        if len(records) != 1:
            invalid_interactions.add(interaction_id)
            issues.add(
                "EQUIVOCATION",
                interaction_id=interaction_id,
                source_message_ids=message_ids,
            )
            continue
        if interaction_id in sequence_conflicts:
            invalid_interactions.add(interaction_id)
            continue
        selected[interaction_id] = next(iter(records.values()))

    selected_record_ids = {
        aggregate.record_id: interaction_id
        for interaction_id, aggregate in selected.items()
    }
    candidates: dict[str, _Candidate] = {}
    for interaction_id, aggregate in selected.items():
        proposal = aggregate.proposal
        encoded_parent = proposal["previous_receipt_id"]
        previous_interaction: str | None = None
        if encoded_parent is not None:
            previous_interaction = selected_record_ids.get(encoded_parent)
            if previous_interaction is None:
                reason = (
                    "PARENT_INVALID"
                    if encoded_parent in aggregates
                    else "PARENT_MISSING"
                )
                issues.add(
                    reason,
                    interaction_id=interaction_id,
                    source_message_ids=aggregate.deliveries,
                )
                invalid_interactions.add(interaction_id)
                continue
        authority = proposal["authority"]
        handoff = NeutralHandoff.from_dict(
            {
                "interaction_id": interaction_id,
                "sender": proposal["sender"],
                "receiver": proposal["receiver"],
                "event_type": proposal["event_type"],
                "sender_sequence": proposal["sender_sequence"],
                "previous_interaction_id": previous_interaction,
                "scope": proposal["scope"],
                "authority_lineage": {
                    "issuer_principal_id": authority["issuer_principal_id"],
                    "subject_principal_id": authority["subject_principal_id"],
                    "subject_key_id": authority["subject_key_id"],
                },
                "authority_version": authority["authority_version"],
                "referenced_status_id": authority["revocation_status_id"],
                "created_at": proposal["created_at"],
                "request_hash": proposal["request_hash"],
            }
        )
        candidates[interaction_id] = _Candidate(
            handoff=handoff,
            decision=aggregate.decision,
            decided_at=aggregate.decided_at,
            source_record_ids=(aggregate.record_id,),
            source_deliveries=tuple(aggregate.deliveries.values()),
            binding_facts={
                "binding_type": "NESTED_DUAL_ATTESTATION",
                "proposal_hash": aggregate.receipt["proposal_hash"],
                "nested_sender_attestation_bound": True,
                "parent_reference_type": "COMPLETED_RECEIPT_ID",
                "encoded_parent_reference": encoded_parent,
                "resolved_parent_receipt_id": encoded_parent,
            },
        )

    invalid_interactions.update(set(grouped) - set(candidates))
    return candidates, invalid_interactions


def _cycle_nodes(candidates: Mapping[str, _Candidate]) -> set[str]:
    cycles: set[str] = set()
    finished: set[str] = set()
    for start in sorted(candidates):
        if start in finished:
            continue
        path: list[str] = []
        local_index: dict[str, int] = {}
        current: str | None = start
        while (
            current is not None
            and current in candidates
            and current not in finished
            and current not in local_index
        ):
            local_index[current] = len(path)
            path.append(current)
            current = candidates[current].handoff.to_dict()["previous_interaction_id"]
        if current is not None and current in local_index:
            cycles.update(path[local_index[current] :])
        finished.update(path)
    return cycles


def _emit_validated(
    candidates: Mapping[str, _Candidate],
    *,
    representation: EvidenceRepresentation,
    invalid_interactions: set[str],
    clock_skew: timedelta,
    issues: _IssueCollector,
) -> tuple[ValidatedHandoff, ...]:
    cycles = _cycle_nodes(candidates)
    relation_memo: dict[str, str | None] = {
        interaction_id: "PARENT_CYCLE" for interaction_id in cycles
    }

    def relation_failure(interaction_id: str) -> str | None:
        chain: list[str] = []
        current = interaction_id
        while current not in relation_memo:
            body = candidates[current].handoff.to_dict()
            previous = body["previous_interaction_id"]
            if previous is None:
                relation_memo[current] = (
                    None if body["event_type"] == "delegation" else "ROOT_INVALID"
                )
            elif previous not in candidates:
                relation_memo[current] = (
                    "PARENT_INVALID"
                    if previous in invalid_interactions
                    else "PARENT_MISSING"
                )
            else:
                chain.append(current)
                current = previous

        for child_id in reversed(chain):
            candidate = candidates[child_id]
            body = candidate.handoff.to_dict()
            previous = body["previous_interaction_id"]
            assert previous is not None and previous in candidates
            parent_failure = relation_memo[previous]
            if parent_failure is not None:
                failure = "PARENT_INVALID"
            else:
                parent = candidates[previous]
                parent_body = parent.handoff.to_dict()
                if (
                    parent.decision is not ReceiverDecision.ACCEPT
                    or parent_body["event_type"] != "delegation"
                ):
                    failure = "PARENT_INVALID"
                elif _exceeds_with_skew(
                    _parse_timestamp(parent.decided_at, "parent decided_at"),
                    _parse_timestamp(body["created_at"], "child created_at"),
                    clock_skew,
                ):
                    failure = "PARENT_TIME_INVALID"
                elif parent_body["receiver"] != body["sender"]:
                    failure = "PARTY_CONTINUITY_INVALID"
                else:
                    failure = None
            relation_memo[child_id] = failure
        return relation_memo[interaction_id]

    result: list[ValidatedHandoff] = []
    for interaction_id in sorted(candidates):
        candidate = candidates[interaction_id]
        failure = relation_failure(interaction_id)
        if failure is not None:
            issues.add(
                failure,
                interaction_id=interaction_id,
                source_message_ids=candidate.source_message_ids,
            )
            continue
        reasons = (
            ()
            if candidate.decision is ReceiverDecision.ACCEPT
            else ("RECEIVER_REJECTED",)
        )
        result.append(
            ValidatedHandoff._build_from_validator(
                _validator_token=_VALIDATOR_TOKEN,
                representation=representation,
                handoff=candidate.handoff,
                sender_authenticated=True,
                receiver_authenticated=True,
                bilateral_agreement=candidate.decision is ReceiverDecision.ACCEPT,
                receiver_decision=candidate.decision,
                receiver_decided_at=candidate.decided_at,
                parent_relation_valid=True,
                conflict_free=True,
                source_record_ids=candidate.source_record_ids,
                source_deliveries=candidate.source_deliveries,
                validation_reasons=reasons,
                binding_facts=candidate.binding_facts,
            )
        )
    return tuple(result)


def validate_observation(
    observation: LocalObservation | AuditObservation,
    *,
    representation: EvidenceRepresentation,
    key_registry: KeyRegistry,
    store_registry: StoreRegistry,
    max_clock_skew_seconds: int = 0,
) -> ValidationReport:
    """Validate exactly the evidence visible in one immutable observation."""

    if not isinstance(observation, (LocalObservation, AuditObservation)):
        raise EvidenceError(
            "observation must be a LocalObservation or AuditObservation"
        )
    if not isinstance(representation, EvidenceRepresentation):
        raise EvidenceError("representation must be an EvidenceRepresentation")
    if not isinstance(key_registry, KeyRegistry):
        raise EvidenceError("key_registry must be a KeyRegistry")
    if not isinstance(store_registry, StoreRegistry):
        raise EvidenceError("store_registry must be a StoreRegistry")
    if type(max_clock_skew_seconds) is not int or max_clock_skew_seconds < 0:
        raise EvidenceError("max_clock_skew_seconds must be a non-negative integer")
    try:
        clock_skew = timedelta(seconds=max_clock_skew_seconds)
    except OverflowError as exc:
        raise EvidenceError(
            "max_clock_skew_seconds exceeds the datetime range"
        ) from exc

    issues = _IssueCollector()
    messages = _profile_messages(observation, representation, issues)
    if not messages:
        issues.add("EVIDENCE_MISSING")
    if representation in {EvidenceRepresentation.SL, EvidenceRepresentation.CR}:
        candidates, invalid_interactions = _validate_endpoint_messages(
            messages,
            representation=representation,
            key_registry=key_registry,
            store_registry=store_registry,
            cutoff=_cutoff(observation),
            clock_skew=clock_skew,
            issues=issues,
        )
    else:
        candidates, invalid_interactions = _validate_receipt_messages(
            messages,
            key_registry=key_registry,
            store_registry=store_registry,
            cutoff=_cutoff(observation),
            clock_skew=clock_skew,
            issues=issues,
        )
    validated = (
        ()
        if issues.has("PAYLOAD_KIND_MISMATCH")
        else _emit_validated(
            candidates,
            representation=representation,
            invalid_interactions=invalid_interactions,
            clock_skew=clock_skew,
            issues=issues,
        )
    )
    return ValidationReport(
        representation=representation,
        validated_handoffs=validated,
        issues=issues.result(),
    )


def encode_receipt_handoff(
    handoff: NeutralHandoff,
    *,
    parent_receipt: Mapping[str, Any] | None,
    sender_private_key: Ed25519PrivateKey,
    receiver_private_key: Ed25519PrivateKey,
    receiver_decision: ReceiverDecision,
    decided_at: str,
    reason_code: str | None = None,
) -> dict[str, Any]:
    """Encode one neutral handoff as the frozen P0 paired-receipt profile.

    ``interaction_id`` is deliberately reused as P0's otherwise redundant
    nonce.  A child requires the exact complete parent receipt so its semantic
    parent can be encoded as that receipt's content identifier.
    """

    if not isinstance(handoff, NeutralHandoff):
        raise EvidenceError("handoff must be a NeutralHandoff")
    if not isinstance(receiver_decision, ReceiverDecision):
        raise EvidenceError("receiver_decision must be a ReceiverDecision")
    if not isinstance(sender_private_key, Ed25519PrivateKey):
        raise EvidenceError("sender_private_key must be an Ed25519PrivateKey")
    if not isinstance(receiver_private_key, Ed25519PrivateKey):
        raise EvidenceError("receiver_private_key must be an Ed25519PrivateKey")
    body = handoff.to_dict()
    previous_interaction = body["previous_interaction_id"]
    if previous_interaction is None:
        if parent_receipt is not None:
            raise EvidenceError("a root handoff cannot encode a parent receipt")
        parent_record_id = None
    else:
        if parent_receipt is None:
            raise EvidenceError("a child handoff requires the complete parent receipt")
        parent, parent_proposal, *_ = _parse_p0_receipt(parent_receipt)
        if parent_proposal["nonce"] != parent_proposal["interaction_id"]:
            raise EvidenceError("parent receipt is outside the neutral receipt profile")
        if parent_proposal["interaction_id"] != previous_interaction:
            raise EvidenceError("parent receipt does not match previous_interaction_id")
        parent_record_id = receipt_id(parent)
    lineage = body["authority_lineage"]
    authority = {
        "issuer_principal_id": lineage["issuer_principal_id"],
        "subject_principal_id": lineage["subject_principal_id"],
        "subject_key_id": lineage["subject_key_id"],
        "authority_version": body["authority_version"],
        "revocation_status_id": body["referenced_status_id"],
    }
    proposal = make_proposal(
        interaction_id=body["interaction_id"],
        event_type=body["event_type"],
        created_at=body["created_at"],
        nonce=body["interaction_id"],
        sender=body["sender"],
        receiver=body["receiver"],
        sender_sequence=body["sender_sequence"],
        previous_receipt_id=parent_record_id,
        scope=body["scope"],
        authority=authority,
        request_hash=body["request_hash"],
    )
    encoded = sign_receipt(
        proposal,
        sender_private_key=sender_private_key,
        receiver_private_key=receiver_private_key,
        receiver_decision=receiver_decision.value,
        decided_at=decided_at,
        reason_code=reason_code,
    )
    # P0's constructor validates timestamp syntax but not its relationship to
    # proposal creation; the Sprint 2 mapping requires the stronger invariant.
    _parse_p0_receipt(encoded)
    return encoded
