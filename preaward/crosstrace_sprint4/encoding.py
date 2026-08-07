"""Representation encoders and neutral delivery-bundle construction."""

from __future__ import annotations

from typing import Any, Mapping

from preaward.crosstrace_sprint1.delivery import (
    PayloadKind,
    compile_schedule,
    empty_permit_state,
    make_evidence_message,
    project_audit,
    project_local,
)
from preaward.crosstrace_sprint2.model import (
    EndpointRecord,
    EndpointRole,
    EvidenceRepresentation,
    ReceiverDecision,
    sign_endpoint_record,
)
from preaward.crosstrace_sprint2.validation import encode_receipt_handoff

from .fixtures import (
    AUDIT_DELTA,
    AUDIT_STORE_ID,
    DECISION_TIME,
    DELIVERY_SEED,
    EPISODE_END,
    LOCAL_STORE_ID,
    PERMIT_STORE_ID,
    VERIFIER_ID,
    BuiltCase,
)
from .model import (
    HARNESS_VERSION,
    HolderRole,
    RepresentationBundle,
    SlotAssignment,
    object_hash,
)


def build_representation_bundle(
    case: BuiltCase,
    representation: EvidenceRepresentation,
    *,
    reverse_input_order: bool = False,
) -> RepresentationBundle:
    """Encode one case and compile one bundle shared by AUDIT and GATE."""

    encoded, sender_bytes = _encode_handoffs(case, representation)
    messages = []
    for assignment in case.slot_assignments:
        payload, kind = _payload_for_slot(
            case,
            assignment,
            representation=representation,
            encoded=encoded,
        )
        messages.append(
            make_evidence_message(
                delivery_slot_id=assignment.slot_id,
                origin_store_id=assignment.origin_store_id,
                destination_store_id=assignment.destination_store_id,
                sent_at=assignment.sent_at,
                payload_kind=kind,
                payload=payload,
            )
        )
    if reverse_input_order:
        messages.reverse()
    schedule = compile_schedule(
        messages,
        policy=case.delivery_policy,
        seed=DELIVERY_SEED,
        overrides=(
            reversed(case.delivery_overrides)
            if reverse_input_order
            else case.delivery_overrides
        ),
    )
    local = project_local(
        schedule,
        verifier_id=VERIFIER_ID,
        evidence_store_id=LOCAL_STORE_ID,
        permit_store_id=PERMIT_STORE_ID,
        decision_time=DECISION_TIME,
        permit_state=empty_permit_state(
            permit_store_id=PERMIT_STORE_ID,
            captured_at=DECISION_TIME,
        ),
    )
    audit = project_audit(
        schedule,
        audit_store_id=AUDIT_STORE_ID,
        episode_end=EPISODE_END,
        delta_audit=AUDIT_DELTA,
    )
    slot_dicts = [item.to_dict() for item in case.slot_assignments]
    projection = _transport_projection(schedule)
    neutral_trace = {
        "handoffs": [item.to_dict() for item in case.handoffs],
        "action": dict(case.action),
        "presented_attempt_count": case.config.attempt_count,
        "delivered_status_ids": [item["status_id"] for item in case.statuses],
    }
    neutral_trace_hash = object_hash("SPRINT4_NEUTRAL_TRACE", neutral_trace)
    action_hash = object_hash("SPRINT4_ACTION", dict(case.action))
    slot_manifest_hash = object_hash("SPRINT4_SLOT_MANIFEST", slot_dicts)
    projection_hash = object_hash("SPRINT4_TRANSPORT_PROJECTION", list(projection))
    bundle_body = {
        "version": HARNESS_VERSION,
        "representation": representation.value,
        "neutral_trace_hash": neutral_trace_hash,
        "action_hash": action_hash,
        "slot_manifest_hash": slot_manifest_hash,
        "transport_projection_hash": projection_hash,
        "schedule": schedule.to_dict(),
        "local_observation": local.to_dict(),
        "audit_observation": audit.to_dict(),
    }
    return RepresentationBundle(
        case_id=case.config.case_id,
        representation=representation,
        neutral_trace_hash=neutral_trace_hash,
        action_hash=action_hash,
        slot_manifest_hash=slot_manifest_hash,
        transport_projection_hash=projection_hash,
        bundle_id=object_hash("SPRINT4_REPRESENTATION_BUNDLE", bundle_body),
        neutral_handoffs=case.handoffs,
        slot_assignments=case.slot_assignments,
        schedule=schedule,
        local_observation=local,
        audit_observation=audit,
        transport_projection=projection,
        endpoint_sender_bytes=sender_bytes,
        pr_copy_pairs_equal=(
            _pr_copy_pairs_equal(schedule)
            if representation is EvidenceRepresentation.PR
            else None
        ),
    )


def _encode_handoffs(
    case: BuiltCase,
    representation: EvidenceRepresentation,
) -> tuple[dict[str, Any], tuple[bytes, ...]]:
    item_ids = ["item.root", "item.leaf"]
    if len(case.handoffs) == 3:
        item_ids.append("item.leaf.alt")
    encoded: dict[str, Any] = {}
    sender_bytes: list[bytes] = []
    if representation in {EvidenceRepresentation.SL, EvidenceRepresentation.CR}:
        for item_id, handoff in zip(item_ids, case.handoffs, strict=True):
            body = handoff.to_dict()
            sender = sign_endpoint_record(
                handoff,
                role=EndpointRole.SENDER,
                private_key=case.private_keys[body["sender"]["key_id"]],
            )
            receiver = sign_endpoint_record(
                handoff,
                role=EndpointRole.RECEIVER,
                private_key=case.private_keys[body["receiver"]["key_id"]],
                sender_record_id=(
                    sender.record_id
                    if representation is EvidenceRepresentation.CR
                    else None
                ),
                decision=ReceiverDecision.ACCEPT,
                reason_code=None,
                decided_at=case.decided_at[body["interaction_id"]],
            )
            encoded[item_id] = (sender, receiver)
            sender_bytes.append(sender.canonical_bytes)
        return encoded, tuple(sender_bytes)

    root_receipt = encode_receipt_handoff(
        case.handoffs[0],
        parent_receipt=None,
        sender_private_key=case.private_keys[
            case.handoffs[0].to_dict()["sender"]["key_id"]
        ],
        receiver_private_key=case.private_keys[
            case.handoffs[0].to_dict()["receiver"]["key_id"]
        ],
        receiver_decision=ReceiverDecision.ACCEPT,
        decided_at=case.decided_at[case.handoffs[0].to_dict()["interaction_id"]],
    )
    encoded["item.root"] = root_receipt
    for item_id, handoff in zip(item_ids[1:], case.handoffs[1:], strict=True):
        body = handoff.to_dict()
        encoded[item_id] = encode_receipt_handoff(
            handoff,
            parent_receipt=root_receipt,
            sender_private_key=case.private_keys[body["sender"]["key_id"]],
            receiver_private_key=case.private_keys[body["receiver"]["key_id"]],
            receiver_decision=ReceiverDecision.ACCEPT,
            decided_at=case.decided_at[body["interaction_id"]],
        )
    return encoded, ()


def _payload_for_slot(
    case: BuiltCase,
    assignment: SlotAssignment,
    *,
    representation: EvidenceRepresentation,
    encoded: Mapping[str, Any],
) -> tuple[Mapping[str, Any], PayloadKind]:
    if assignment.holder_role is HolderRole.AUTHORITY:
        return (
            case.status_by_item(assignment.semantic_item_id),
            PayloadKind.AUTHORITY_STATUS,
        )
    evidence = encoded[assignment.semantic_item_id]
    if representation is EvidenceRepresentation.PR:
        return evidence, PayloadKind.RECEIPT
    records: tuple[EndpointRecord, EndpointRecord] = evidence
    record = records[0] if assignment.holder_role is HolderRole.SENDER else records[1]
    kind = (
        PayloadKind.SIGNED_ENDPOINT_RECORD
        if representation is EvidenceRepresentation.SL
        else PayloadKind.CROSS_REFERENCED_RECORD
    )
    return record.to_dict(), kind


def _transport_projection(schedule) -> tuple[dict[str, Any], ...]:
    messages = {item.message_id: item for item in schedule.messages}
    result = []
    for transmission in schedule.transmissions:
        message = messages[transmission.message_id]
        result.append(
            {
                "delivery_slot_id": transmission.delivery_slot_id,
                "copy_index": transmission.copy_index,
                "origin_store_id": message.origin_store_id,
                "destination_store_id": message.destination_store_id,
                "sent_at": message.to_dict()["sent_at"],
                "disposition": transmission.disposition.value,
                "delivered_at": transmission.to_dict()["delivered_at"],
                "fault_tags": list(transmission.fault_tags),
            }
        )
    return tuple(
        sorted(result, key=lambda item: (item["delivery_slot_id"], item["copy_index"]))
    )


def _pr_copy_pairs_equal(schedule) -> bool:
    messages = list(schedule.messages)
    groups: dict[tuple[str, str], list[bytes]] = {}
    for message in messages:
        if message.payload_kind is not PayloadKind.RECEIPT:
            continue
        tokens = message.delivery_slot_id.split(".")
        if len(tokens) < 5:
            return False
        # Omit holder role while preserving trace, semantic item, and destination.
        group = (".".join(tokens[:3]), tokens[-1])
        groups.setdefault(group, []).append(message.payload_bytes)
    return bool(groups) and all(
        len(values) == 2 and values[0] == values[1] for values in groups.values()
    )
