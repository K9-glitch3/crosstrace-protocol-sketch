"""Adversarial development tests for the Sprint 2 evidence profiles.

These tests exercise only synthetic, deterministic fixtures.  They are not
research outcomes and they do not call models or external services.
"""

from __future__ import annotations

import json
from copy import deepcopy
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from jsonschema import Draft202012Validator, ValidationError

from crosstrace_sketch.demo import build_fixture
from crosstrace_sketch.protocol import (
    KeyRegistry,
    content_id,
    make_proposal,
    receipt_id,
    sign_receipt,
)
from preaward.crosstrace_sprint1.delivery import (
    DeliveryError,
    DeliveryPolicy,
    Disposition,
    PayloadKind,
    TransmissionOverride,
    compile_schedule,
    empty_permit_state,
    make_evidence_message,
    project_audit,
    project_local,
)
from preaward.crosstrace_sprint2.model import (
    EndpointRecord,
    EndpointRole,
    EvidenceError,
    EvidenceRepresentation,
    NeutralHandoff,
    PolicyView,
    ReceiverDecision,
    ValidatedHandoff,
    evaluate_common_evidence_policy,
    make_neutral_handoff,
    sign_endpoint_record,
)
from preaward.crosstrace_sprint2.validation import (
    StoreRegistry,
    encode_receipt_handoff,
    validate_observation,
)

NOW = datetime(2026, 8, 7, 10, 0, 0, tzinfo=UTC)
SEED = b"crosstrace-sprint2-test-seed"
DESTINATION = "store.verifier"


def _schema(name: str) -> dict:
    root = Path(__file__).resolve().parents[1]
    return json.loads((root / "schema" / name).read_text(encoding="utf-8"))


def _lineage(case: dict) -> dict:
    authority = case["authority"]
    return {
        "issuer_principal_id": authority["issuer_principal_id"],
        "subject_principal_id": authority["subject_principal_id"],
        "subject_key_id": authority["subject_key_id"],
    }


def _handoffs(case: dict) -> tuple[NeutralHandoff, NeutralHandoff]:
    root_proposal = case["root_receipt"]["proposal"]
    leaf_proposal = case["leaf_receipt"]["proposal"]
    root = make_neutral_handoff(
        interaction_id=root_proposal["interaction_id"],
        sender=case["parties"]["buyer"],
        receiver=case["parties"]["broker"],
        event_type="delegation",
        sender_sequence=1,
        previous_interaction_id=None,
        scope=case["root_scope"],
        authority_lineage=_lineage(case),
        authority_version=case["authority"]["authority_version"],
        referenced_status_id=case["authority"]["revocation_status_id"],
        created_at="2026-08-05T14:00:00Z",
        request_hash=root_proposal["request_hash"],
    )
    leaf = make_neutral_handoff(
        interaction_id=leaf_proposal["interaction_id"],
        sender=case["parties"]["broker"],
        receiver=case["parties"]["payment"],
        event_type="action_intent",
        sender_sequence=1,
        previous_interaction_id=root_proposal["interaction_id"],
        scope=case["leaf_scope"],
        authority_lineage=_lineage(case),
        authority_version=case["authority"]["authority_version"],
        referenced_status_id=case["authority"]["revocation_status_id"],
        created_at="2026-08-05T14:01:00Z",
        request_hash=leaf_proposal["request_hash"],
    )
    return root, leaf


def _store_registry() -> StoreRegistry:
    registry = StoreRegistry()
    registry.add(
        store_id="store.buyer",
        principal_id="buyer.example",
        roles={EndpointRole.SENDER},
    )
    registry.add(
        store_id="store.buyer.backup",
        principal_id="buyer.example",
        roles={EndpointRole.SENDER},
    )
    registry.add(
        store_id="store.broker",
        principal_id="broker.example",
        roles={EndpointRole.SENDER, EndpointRole.RECEIVER},
    )
    registry.add(
        store_id="store.payment",
        principal_id="payment.example",
        roles={EndpointRole.RECEIVER},
    )
    return registry


def _message(
    payload: dict,
    *,
    kind: PayloadKind,
    origin: str,
    slot: str,
    sent_at: datetime = NOW,
):
    return make_evidence_message(
        delivery_slot_id=slot,
        origin_store_id=origin,
        destination_store_id=DESTINATION,
        sent_at=sent_at,
        payload_kind=kind,
        payload=payload,
    )


def _observation(
    messages,
    *,
    decision_time: datetime = NOW,
    policy: DeliveryPolicy | None = None,
    overrides=(),
):
    schedule = compile_schedule(
        tuple(messages),
        policy=policy or DeliveryPolicy(),
        seed=SEED,
        overrides=tuple(overrides),
    )
    return project_local(
        schedule,
        verifier_id="verifier.sprint2",
        evidence_store_id=DESTINATION,
        permit_store_id="store.permits.sprint2",
        decision_time=decision_time,
        permit_state=empty_permit_state(
            permit_store_id="store.permits.sprint2",
            captured_at=decision_time,
        ),
    )


def _validate(
    messages,
    *,
    representation: EvidenceRepresentation,
    case: dict,
    stores: StoreRegistry | None = None,
    decision_time: datetime = NOW,
    policy: DeliveryPolicy | None = None,
    overrides=(),
):
    return validate_observation(
        _observation(
            messages,
            decision_time=decision_time,
            policy=policy,
            overrides=overrides,
        ),
        representation=representation,
        key_registry=case["registry"],
        store_registry=stores or _store_registry(),
    )


def _endpoint_records(
    handoff: NeutralHandoff,
    *,
    representation: EvidenceRepresentation,
    sender_key: Ed25519PrivateKey,
    receiver_key: Ed25519PrivateKey,
    decision: ReceiverDecision = ReceiverDecision.ACCEPT,
    reason_code: str | None = None,
    decided_at: str = "2026-08-05T14:00:05Z",
    sender_reference: str | None = None,
) -> tuple[EndpointRecord, EndpointRecord]:
    sender = sign_endpoint_record(
        handoff,
        role=EndpointRole.SENDER,
        private_key=sender_key,
    )
    if representation is EvidenceRepresentation.CR:
        reference = sender.record_id if sender_reference is None else sender_reference
    else:
        reference = None
    receiver = sign_endpoint_record(
        handoff,
        role=EndpointRole.RECEIVER,
        private_key=receiver_key,
        sender_record_id=reference,
        decision=decision,
        reason_code=reason_code,
        decided_at=decided_at,
    )
    return sender, receiver


def _endpoint_messages(
    handoff: NeutralHandoff,
    records: tuple[EndpointRecord, EndpointRecord],
    representation: EvidenceRepresentation,
    *,
    suffix: str,
) -> tuple:
    kind = (
        PayloadKind.SIGNED_ENDPOINT_RECORD
        if representation is EvidenceRepresentation.SL
        else PayloadKind.CROSS_REFERENCED_RECORD
    )
    body = handoff.to_dict()
    origins = {
        "buyer.example": "store.buyer",
        "broker.example": "store.broker",
        "payment.example": "store.payment",
    }
    sender_origin = origins[body["sender"]["principal_id"]]
    receiver_origin = origins[body["receiver"]["principal_id"]]
    return (
        _message(
            records[0].to_dict(),
            kind=kind,
            origin=sender_origin,
            slot=f"slot.{suffix}.sender",
        ),
        _message(
            records[1].to_dict(),
            kind=kind,
            origin=receiver_origin,
            slot=f"slot.{suffix}.receiver",
        ),
    )


def _encode_pr_without_parent_time_guard(
    handoff: NeutralHandoff,
    *,
    parent_receipt: dict | None,
    sender_private_key: Ed25519PrivateKey,
    receiver_private_key: Ed25519PrivateKey,
    decided_at: str,
) -> dict:
    """Build a signed P0 receipt while deliberately bypassing Sprint 2 encoding.

    This is used only to feed a cryptographically valid, temporally invalid
    child into the validator.  Production callers must use
    ``encode_receipt_handoff``.
    """

    body = handoff.to_dict()
    lineage = body["authority_lineage"]
    proposal = make_proposal(
        interaction_id=body["interaction_id"],
        event_type=body["event_type"],
        created_at=body["created_at"],
        nonce=body["interaction_id"],
        sender=body["sender"],
        receiver=body["receiver"],
        sender_sequence=body["sender_sequence"],
        previous_receipt_id=(
            None if parent_receipt is None else receipt_id(parent_receipt)
        ),
        scope=body["scope"],
        authority={
            "issuer_principal_id": lineage["issuer_principal_id"],
            "subject_principal_id": lineage["subject_principal_id"],
            "subject_key_id": lineage["subject_key_id"],
            "authority_version": body["authority_version"],
            "revocation_status_id": body["referenced_status_id"],
        },
        request_hash=body["request_hash"],
    )
    return sign_receipt(
        proposal,
        sender_private_key=sender_private_key,
        receiver_private_key=receiver_private_key,
        receiver_decision="ACCEPT",
        decided_at=decided_at,
    )


def _issue_codes(report) -> set[str]:
    return {issue.reason_code for issue in report.issues}


def _by_interaction(report) -> dict[str, ValidatedHandoff]:
    return {
        item.handoff.to_dict()["interaction_id"]: item
        for item in report.validated_handoffs
    }


@pytest.fixture
def case() -> dict:
    return build_fixture()


@pytest.fixture
def handoffs(case: dict) -> tuple[NeutralHandoff, NeutralHandoff]:
    return _handoffs(case)


def test_schemas_canonical_round_trips_and_shared_sender_bytes(
    case: dict,
    handoffs: tuple[NeutralHandoff, NeutralHandoff],
) -> None:
    root, _ = handoffs
    for schema_name in (
        "neutral-handoff.schema.json",
        "signed-endpoint-record.schema.json",
        "cross-referenced-record.schema.json",
        "validated-handoff.schema.json",
    ):
        Draft202012Validator.check_schema(_schema(schema_name))
    sl_sender, sl_receiver = _endpoint_records(
        root,
        representation=EvidenceRepresentation.SL,
        sender_key=case["keys"]["buyer"],
        receiver_key=case["keys"]["broker"],
    )
    cr_sender, cr_receiver = _endpoint_records(
        root,
        representation=EvidenceRepresentation.CR,
        sender_key=case["keys"]["buyer"],
        receiver_key=case["keys"]["broker"],
    )

    assert cr_sender.record_id == sl_sender.record_id
    assert cr_sender.canonical_bytes == sl_sender.canonical_bytes
    assert NeutralHandoff.from_dict(root.to_dict()) == root
    assert NeutralHandoff.from_bytes(root.canonical_bytes) == root
    assert EndpointRecord.from_dict(sl_sender.to_dict()) == sl_sender
    assert EndpointRecord.from_bytes(sl_sender.canonical_bytes) == sl_sender

    Draft202012Validator(_schema("neutral-handoff.schema.json")).validate(
        root.to_dict()
    )
    sl_schema = Draft202012Validator(_schema("signed-endpoint-record.schema.json"))
    cr_schema = Draft202012Validator(_schema("cross-referenced-record.schema.json"))
    for record in (sl_sender, sl_receiver):
        sl_schema.validate(record.to_dict())
    for record in (cr_sender, cr_receiver):
        cr_schema.validate(record.to_dict())
    # The sender is deliberately the same record in both representations.
    cr_schema.validate(sl_sender.to_dict())

    noncanonical = json.dumps(root.to_dict(), indent=2).encode("ascii")
    with pytest.raises(EvidenceError, match="canonical"):
        NeutralHandoff.from_bytes(noncanonical)
    with pytest.raises(ValidationError):
        sl_schema.validate(cr_receiver.to_dict())


def test_neutral_handoff_rejects_self_handoff_between_one_principal(
    handoffs: tuple[NeutralHandoff, NeutralHandoff],
) -> None:
    root, _ = handoffs
    self_handoff = root.to_dict()
    self_handoff["receiver"] = {
        **self_handoff["receiver"],
        "principal_id": self_handoff["sender"]["principal_id"],
    }

    with pytest.raises(
        EvidenceError,
        match="sender and receiver.*different principals",
    ):
        NeutralHandoff.from_dict(self_handoff)


def test_golden_root_child_normalize_to_identical_policy_views(
    case: dict,
    handoffs: tuple[NeutralHandoff, NeutralHandoff],
) -> None:
    root, leaf = handoffs
    reports = {}
    for representation in (EvidenceRepresentation.SL, EvidenceRepresentation.CR):
        root_records = _endpoint_records(
            root,
            representation=representation,
            sender_key=case["keys"]["buyer"],
            receiver_key=case["keys"]["broker"],
        )
        leaf_records = _endpoint_records(
            leaf,
            representation=representation,
            sender_key=case["keys"]["broker"],
            receiver_key=case["keys"]["payment"],
            decided_at="2026-08-05T14:01:05Z",
        )
        messages = (
            *_endpoint_messages(
                root,
                root_records,
                representation,
                suffix=f"{representation.value}.root",
            ),
            *_endpoint_messages(
                leaf,
                leaf_records,
                representation,
                suffix=f"{representation.value}.leaf",
            ),
        )
        reports[representation] = _validate(
            messages,
            representation=representation,
            case=case,
        )

    root_receipt = encode_receipt_handoff(
        root,
        parent_receipt=None,
        sender_private_key=case["keys"]["buyer"],
        receiver_private_key=case["keys"]["broker"],
        receiver_decision=ReceiverDecision.ACCEPT,
        decided_at="2026-08-05T14:00:05Z",
    )
    leaf_receipt = encode_receipt_handoff(
        leaf,
        parent_receipt=root_receipt,
        sender_private_key=case["keys"]["broker"],
        receiver_private_key=case["keys"]["payment"],
        receiver_decision=ReceiverDecision.ACCEPT,
        decided_at="2026-08-05T14:01:05Z",
    )
    pr_messages = (
        _message(
            root_receipt,
            kind=PayloadKind.RECEIPT,
            origin="store.broker",
            slot="slot.PR.root",
        ),
        _message(
            leaf_receipt,
            kind=PayloadKind.RECEIPT,
            origin="store.payment",
            slot="slot.PR.leaf",
        ),
    )
    reports[EvidenceRepresentation.PR] = _validate(
        pr_messages,
        representation=EvidenceRepresentation.PR,
        case=case,
    )

    for report in reports.values():
        assert report.issues == ()
        assert len(report.validated_handoffs) == 2
        for validated in report.validated_handoffs:
            assert evaluate_common_evidence_policy(validated.policy_view()).allowed
            Draft202012Validator(_schema("validated-handoff.schema.json")).validate(
                validated.to_dict()
            )
            decoded = ValidatedHandoff.from_dict(validated.to_dict())
            decoded_bytes = ValidatedHandoff.from_bytes(validated.canonical_bytes)
            assert decoded == validated
            assert decoded_bytes == validated
            assert not decoded.validator_issued
            with pytest.raises(EvidenceError, match="revalidated"):
                decoded.policy_view()
            decoded_view = PolicyView.from_bytes(
                validated.policy_view().canonical_bytes
            )
            assert not decoded_view.validator_issued
            with pytest.raises(EvidenceError, match="issued directly"):
                evaluate_common_evidence_policy(decoded_view)

    policy_views = {
        representation: {
            interaction_id: item.policy_view()
            for interaction_id, item in _by_interaction(report).items()
        }
        for representation, report in reports.items()
    }
    assert (
        policy_views[EvidenceRepresentation.SL]
        == policy_views[EvidenceRepresentation.CR]
    )
    assert (
        policy_views[EvidenceRepresentation.SL]
        == policy_views[EvidenceRepresentation.PR]
    )

    pr_results = _by_interaction(reports[EvidenceRepresentation.PR])
    assert len(pr_results[root.to_dict()["interaction_id"]].source_deliveries) == 1
    assert len(pr_results[leaf.to_dict()["interaction_id"]].source_deliveries) == 1


@pytest.mark.parametrize(
    "representation", [EvidenceRepresentation.SL, EvidenceRepresentation.CR]
)
def test_endpoint_representation_requires_both_endpoint_records(
    representation: EvidenceRepresentation,
    case: dict,
    handoffs: tuple[NeutralHandoff, NeutralHandoff],
) -> None:
    root, _ = handoffs
    records = _endpoint_records(
        root,
        representation=representation,
        sender_key=case["keys"]["buyer"],
        receiver_key=case["keys"]["broker"],
    )
    messages = _endpoint_messages(root, records, representation, suffix="missing")
    for lone_message in messages:
        report = _validate(
            (lone_message,),
            representation=representation,
            case=case,
        )
        assert report.validated_handoffs == ()
        assert report.issues


def test_mismatched_handoff_and_wrong_cross_reference_fail_closed(
    case: dict,
    handoffs: tuple[NeutralHandoff, NeutralHandoff],
) -> None:
    root, _ = handoffs
    different = root.to_dict()
    different["request_hash"] = "sha256:" + "9" * 64
    different_handoff = NeutralHandoff.from_dict(different)

    sender = sign_endpoint_record(
        root,
        role=EndpointRole.SENDER,
        private_key=case["keys"]["buyer"],
    )
    mismatched_receiver = sign_endpoint_record(
        different_handoff,
        role=EndpointRole.RECEIVER,
        private_key=case["keys"]["broker"],
        decision=ReceiverDecision.ACCEPT,
        decided_at="2026-08-05T14:00:05Z",
    )
    mismatch_messages = _endpoint_messages(
        root,
        (sender, mismatched_receiver),
        EvidenceRepresentation.SL,
        suffix="mismatch",
    )
    mismatch = _validate(
        mismatch_messages,
        representation=EvidenceRepresentation.SL,
        case=case,
    )
    assert mismatch.validated_handoffs == ()
    assert mismatch.issues

    cr_records = _endpoint_records(
        root,
        representation=EvidenceRepresentation.CR,
        sender_key=case["keys"]["buyer"],
        receiver_key=case["keys"]["broker"],
        sender_reference="sha256:" + "8" * 64,
    )
    wrong_reference = _validate(
        _endpoint_messages(
            root,
            cr_records,
            EvidenceRepresentation.CR,
            suffix="wrong-ref",
        ),
        representation=EvidenceRepresentation.CR,
        case=case,
    )
    assert wrong_reference.validated_handoffs == ()
    assert wrong_reference.issues


def test_mutation_invalid_signature_unknown_key_and_unknown_store_are_rejected(
    case: dict,
    handoffs: tuple[NeutralHandoff, NeutralHandoff],
) -> None:
    root, _ = handoffs
    sender, receiver = _endpoint_records(
        root,
        representation=EvidenceRepresentation.SL,
        sender_key=case["keys"]["buyer"],
        receiver_key=case["keys"]["broker"],
    )
    tampered = deepcopy(sender.to_dict())
    signature = tampered["attestation"]["signature"]
    tampered["attestation"]["signature"] = (
        "A" if signature[0] != "A" else "B"
    ) + signature[1:]
    core = {
        "body": tampered["body"],
        "body_id": tampered["body_id"],
        "attestation": tampered["attestation"],
    }
    tampered["record_id"] = content_id("SIGNED_ENDPOINT_RECORD", core)
    EndpointRecord.from_dict(tampered)  # Structurally sound, cryptographically false.
    tampered_messages = (
        _message(
            tampered,
            kind=PayloadKind.SIGNED_ENDPOINT_RECORD,
            origin="store.buyer",
            slot="slot.bad-signature.sender",
        ),
        _message(
            receiver.to_dict(),
            kind=PayloadKind.SIGNED_ENDPOINT_RECORD,
            origin="store.broker",
            slot="slot.bad-signature.receiver",
        ),
    )
    bad_signature = _validate(
        tampered_messages,
        representation=EvidenceRepresentation.SL,
        case=case,
    )
    assert bad_signature.validated_handoffs == ()
    assert bad_signature.issues

    unknown_sender_body = root.to_dict()
    unknown_sender_body["sender"] = {
        **unknown_sender_body["sender"],
        "key_id": "buyer-agent-key-unknown",
    }
    unknown_handoff = NeutralHandoff.from_dict(unknown_sender_body)
    unknown_records = _endpoint_records(
        unknown_handoff,
        representation=EvidenceRepresentation.SL,
        sender_key=case["keys"]["buyer"],
        receiver_key=case["keys"]["broker"],
    )
    unknown_key = _validate(
        _endpoint_messages(
            unknown_handoff,
            unknown_records,
            EvidenceRepresentation.SL,
            suffix="unknown-key",
        ),
        representation=EvidenceRepresentation.SL,
        case=case,
    )
    assert unknown_key.validated_handoffs == ()
    assert unknown_key.issues

    unregistered = (
        _message(
            sender.to_dict(),
            kind=PayloadKind.SIGNED_ENDPOINT_RECORD,
            origin="store.unregistered",
            slot="slot.unknown-store.sender",
        ),
        _message(
            receiver.to_dict(),
            kind=PayloadKind.SIGNED_ENDPOINT_RECORD,
            origin="store.broker",
            slot="slot.unknown-store.receiver",
        ),
    )
    unknown_store = _validate(
        unregistered,
        representation=EvidenceRepresentation.SL,
        case=case,
    )
    assert unknown_store.validated_handoffs == ()
    assert unknown_store.issues


def test_authenticated_rejection_is_retained_but_never_allowed(
    case: dict,
    handoffs: tuple[NeutralHandoff, NeutralHandoff],
) -> None:
    root, _ = handoffs
    records = _endpoint_records(
        root,
        representation=EvidenceRepresentation.SL,
        sender_key=case["keys"]["buyer"],
        receiver_key=case["keys"]["broker"],
        decision=ReceiverDecision.REJECT,
        reason_code="OUT_OF_POLICY",
    )
    report = _validate(
        _endpoint_messages(root, records, EvidenceRepresentation.SL, suffix="reject"),
        representation=EvidenceRepresentation.SL,
        case=case,
    )
    assert report.issues == ()
    assert len(report.validated_handoffs) == 1
    validated = report.validated_handoffs[0]
    assert validated.receiver_decision is ReceiverDecision.REJECT
    assert not validated.bilateral_agreement
    assert validated.validation_reasons == ("RECEIVER_REJECTED",)
    policy = evaluate_common_evidence_policy(validated.policy_view())
    assert policy.verdict == "PAUSE"
    assert "RECEIVER_REJECTED" in policy.reasons

    with pytest.raises(EvidenceError, match="policy_view"):
        evaluate_common_evidence_policy(validated)
    representation_leak = {
        **validated.policy_view().to_dict(),
        "representation": validated.representation.value,
    }
    with pytest.raises(EvidenceError, match="policy_view"):
        evaluate_common_evidence_policy(representation_leak)


def test_conflicting_authenticated_records_are_not_selected_by_sort_order(
    case: dict,
    handoffs: tuple[NeutralHandoff, NeutralHandoff],
) -> None:
    root, _ = handoffs
    first_sender, receiver = _endpoint_records(
        root,
        representation=EvidenceRepresentation.SL,
        sender_key=case["keys"]["buyer"],
        receiver_key=case["keys"]["broker"],
    )
    fork_body = root.to_dict()
    fork_body["request_hash"] = "sha256:" + "7" * 64
    fork = NeutralHandoff.from_dict(fork_body)
    second_sender = sign_endpoint_record(
        fork,
        role=EndpointRole.SENDER,
        private_key=case["keys"]["buyer"],
    )
    messages = (
        _message(
            first_sender.to_dict(),
            kind=PayloadKind.SIGNED_ENDPOINT_RECORD,
            origin="store.buyer",
            slot="slot.fork.sender.one",
        ),
        _message(
            second_sender.to_dict(),
            kind=PayloadKind.SIGNED_ENDPOINT_RECORD,
            origin="store.buyer",
            slot="slot.fork.sender.two",
        ),
        _message(
            receiver.to_dict(),
            kind=PayloadKind.SIGNED_ENDPOINT_RECORD,
            origin="store.broker",
            slot="slot.fork.receiver",
        ),
    )
    forward = _validate(
        messages,
        representation=EvidenceRepresentation.SL,
        case=case,
    )
    reverse = _validate(
        tuple(reversed(messages)),
        representation=EvidenceRepresentation.SL,
        case=case,
    )
    assert forward.validated_handoffs == ()
    assert reverse.validated_handoffs == ()
    assert "EQUIVOCATION" in _issue_codes(forward)
    assert forward.to_dict() == reverse.to_dict()


def test_transport_duplicates_collapse_but_independent_holder_copies_survive(
    case: dict,
    handoffs: tuple[NeutralHandoff, NeutralHandoff],
) -> None:
    root, _ = handoffs
    records = _endpoint_records(
        root,
        representation=EvidenceRepresentation.SL,
        sender_key=case["keys"]["buyer"],
        receiver_key=case["keys"]["broker"],
    )
    sender_message, receiver_message = _endpoint_messages(
        root,
        records,
        EvidenceRepresentation.SL,
        suffix="provenance",
    )
    retained_copy = _message(
        records[0].to_dict(),
        kind=PayloadKind.SIGNED_ENDPOINT_RECORD,
        origin="store.buyer.backup",
        slot="slot.provenance.sender.backup",
    )
    report = _validate(
        (receiver_message, retained_copy, sender_message),
        representation=EvidenceRepresentation.SL,
        case=case,
        policy=DeliveryPolicy(duplicate_rate_ppm=1_000_000),
    )
    assert report.issues == ()
    validated = report.validated_handoffs[0]
    assert len(validated.source_record_ids) == 2
    assert len(validated.source_message_ids) == 3
    assert len(validated.source_deliveries) == 3
    assert {item.message_id for item in validated.source_deliveries} == set(
        validated.source_message_ids
    )
    assert {item.source_record_id for item in validated.source_deliveries} == set(
        validated.source_record_ids
    )
    assert (
        sum(
            item.source_record_id == records[0].record_id
            for item in validated.source_deliveries
        )
        == 2
    )
    assert (
        sum(
            item.source_record_id == records[1].record_id
            for item in validated.source_deliveries
        )
        == 1
    )


def test_delayed_receiver_record_changes_only_the_later_local_view(
    case: dict,
    handoffs: tuple[NeutralHandoff, NeutralHandoff],
) -> None:
    root, _ = handoffs
    records = _endpoint_records(
        root,
        representation=EvidenceRepresentation.SL,
        sender_key=case["keys"]["buyer"],
        receiver_key=case["keys"]["broker"],
    )
    messages = _endpoint_messages(
        root,
        records,
        EvidenceRepresentation.SL,
        suffix="delayed",
    )
    overrides = (
        TransmissionOverride(
            messages[0].delivery_slot_id,
            0,
            Disposition.DELIVER,
            0,
        ),
        TransmissionOverride(
            messages[1].delivery_slot_id,
            0,
            Disposition.DELIVER,
            20,
        ),
    )
    schedule = compile_schedule(
        messages,
        policy=DeliveryPolicy(),
        seed=SEED,
        overrides=overrides,
    )

    def view(at: datetime):
        return project_local(
            schedule,
            verifier_id="verifier.sprint2",
            evidence_store_id=DESTINATION,
            permit_store_id="store.permits.sprint2",
            decision_time=at,
            permit_state=empty_permit_state(
                permit_store_id="store.permits.sprint2",
                captured_at=at,
            ),
        )

    early_view = view(NOW + timedelta(seconds=10))
    early_bytes = early_view.canonical_bytes
    late_view = view(NOW + timedelta(seconds=20))
    early = validate_observation(
        early_view,
        representation=EvidenceRepresentation.SL,
        key_registry=case["registry"],
        store_registry=_store_registry(),
    )
    late = validate_observation(
        late_view,
        representation=EvidenceRepresentation.SL,
        key_registry=case["registry"],
        store_registry=_store_registry(),
    )
    assert early.validated_handoffs == ()
    assert len(late.validated_handoffs) == 1
    assert early_view.canonical_bytes == early_bytes


def test_endpoint_child_requires_delivered_parent_and_party_continuity(
    case: dict,
    handoffs: tuple[NeutralHandoff, NeutralHandoff],
) -> None:
    root, leaf = handoffs
    leaf_records = _endpoint_records(
        leaf,
        representation=EvidenceRepresentation.SL,
        sender_key=case["keys"]["broker"],
        receiver_key=case["keys"]["payment"],
        decided_at="2026-08-05T14:01:05Z",
    )
    leaf_messages = _endpoint_messages(
        leaf,
        leaf_records,
        EvidenceRepresentation.SL,
        suffix="parent-missing",
    )
    missing = _validate(
        leaf_messages,
        representation=EvidenceRepresentation.SL,
        case=case,
    )
    assert missing.validated_handoffs == ()
    assert "PARENT_MISSING" in _issue_codes(missing)

    root_records = _endpoint_records(
        root,
        representation=EvidenceRepresentation.SL,
        sender_key=case["keys"]["buyer"],
        receiver_key=case["keys"]["broker"],
    )
    discontinuous_body = leaf.to_dict()
    discontinuous_body["sender"] = case["parties"]["buyer"]
    discontinuous_body["sender_sequence"] = 2
    discontinuous = NeutralHandoff.from_dict(discontinuous_body)
    discontinuous_records = _endpoint_records(
        discontinuous,
        representation=EvidenceRepresentation.SL,
        sender_key=case["keys"]["buyer"],
        receiver_key=case["keys"]["payment"],
        decided_at="2026-08-05T14:01:05Z",
    )
    combined = (
        *_endpoint_messages(
            root,
            root_records,
            EvidenceRepresentation.SL,
            suffix="continuity-root",
        ),
        *_endpoint_messages(
            discontinuous,
            discontinuous_records,
            EvidenceRepresentation.SL,
            suffix="continuity-child",
        ),
    )
    report = _validate(
        combined,
        representation=EvidenceRepresentation.SL,
        case=case,
    )
    assert tuple(
        item.handoff.to_dict()["interaction_id"] for item in report.validated_handoffs
    ) == (root.to_dict()["interaction_id"],)
    assert report.issues


def test_sender_sequence_equivocation_across_interaction_ids_fails_closed(
    case: dict,
    handoffs: tuple[NeutralHandoff, NeutralHandoff],
) -> None:
    root, _ = handoffs
    fork_body = root.to_dict()
    fork_body["interaction_id"] = "handoff-buyer-broker-fork-002"
    fork_body["request_hash"] = "sha256:" + "6" * 64
    fork = NeutralHandoff.from_dict(fork_body)
    root_records = _endpoint_records(
        root,
        representation=EvidenceRepresentation.SL,
        sender_key=case["keys"]["buyer"],
        receiver_key=case["keys"]["broker"],
    )
    fork_records = _endpoint_records(
        fork,
        representation=EvidenceRepresentation.SL,
        sender_key=case["keys"]["buyer"],
        receiver_key=case["keys"]["broker"],
    )
    messages = (
        *_endpoint_messages(
            root,
            root_records,
            EvidenceRepresentation.SL,
            suffix="sequence-root",
        ),
        *_endpoint_messages(
            fork,
            fork_records,
            EvidenceRepresentation.SL,
            suffix="sequence-fork",
        ),
    )
    report = _validate(
        messages,
        representation=EvidenceRepresentation.SL,
        case=case,
    )
    assert report.validated_handoffs == ()
    assert "EQUIVOCATION" in _issue_codes(report)


def test_future_receiver_decision_is_not_admitted_at_an_earlier_cutoff(
    case: dict,
    handoffs: tuple[NeutralHandoff, NeutralHandoff],
) -> None:
    root, _ = handoffs
    records = _endpoint_records(
        root,
        representation=EvidenceRepresentation.SL,
        sender_key=case["keys"]["buyer"],
        receiver_key=case["keys"]["broker"],
        decided_at="2026-08-07T10:00:01Z",
    )
    report = _validate(
        _endpoint_messages(
            root,
            records,
            EvidenceRepresentation.SL,
            suffix="future-decision",
        ),
        representation=EvidenceRepresentation.SL,
        case=case,
        decision_time=NOW,
    )
    assert report.validated_handoffs == ()
    assert report.issues


@pytest.mark.parametrize(
    ("sender_sent_at", "receiver_sent_at"),
    [
        (
            datetime(2026, 8, 5, 13, 59, 59, tzinfo=UTC),
            datetime(2026, 8, 5, 14, 0, 5, tzinfo=UTC),
        ),
        (
            datetime(2026, 8, 5, 14, 0, 0, tzinfo=UTC),
            datetime(2026, 8, 5, 14, 0, 4, tzinfo=UTC),
        ),
    ],
    ids=("sender-before-creation", "receiver-before-decision"),
)
def test_endpoint_record_cannot_be_sent_before_its_signed_event_time(
    sender_sent_at: datetime,
    receiver_sent_at: datetime,
    case: dict,
    handoffs: tuple[NeutralHandoff, NeutralHandoff],
) -> None:
    root, _ = handoffs
    sender, receiver = _endpoint_records(
        root,
        representation=EvidenceRepresentation.SL,
        sender_key=case["keys"]["buyer"],
        receiver_key=case["keys"]["broker"],
    )
    messages = (
        _message(
            sender.to_dict(),
            kind=PayloadKind.SIGNED_ENDPOINT_RECORD,
            origin="store.buyer",
            slot="slot.temporal.sender",
            sent_at=sender_sent_at,
        ),
        _message(
            receiver.to_dict(),
            kind=PayloadKind.SIGNED_ENDPOINT_RECORD,
            origin="store.broker",
            slot="slot.temporal.receiver",
            sent_at=receiver_sent_at,
        ),
    )
    report = _validate(
        messages,
        representation=EvidenceRepresentation.SL,
        case=case,
    )
    assert report.validated_handoffs == ()
    assert report.issues


def test_complete_receipt_cannot_be_sent_before_receiver_decides(
    case: dict,
    handoffs: tuple[NeutralHandoff, NeutralHandoff],
) -> None:
    root, _ = handoffs
    receipt = encode_receipt_handoff(
        root,
        parent_receipt=None,
        sender_private_key=case["keys"]["buyer"],
        receiver_private_key=case["keys"]["broker"],
        receiver_decision=ReceiverDecision.ACCEPT,
        decided_at="2026-08-05T14:00:05Z",
    )
    message = _message(
        receipt,
        kind=PayloadKind.RECEIPT,
        origin="store.broker",
        slot="slot.PR.premature-send",
        sent_at=datetime(2026, 8, 5, 14, 0, 4, tzinfo=UTC),
    )
    report = _validate(
        (message,),
        representation=EvidenceRepresentation.PR,
        case=case,
    )
    assert report.validated_handoffs == ()
    assert report.issues


@pytest.mark.parametrize(
    "representation",
    (EvidenceRepresentation.SL, EvidenceRepresentation.CR),
)
def test_endpoint_child_cannot_predate_parent_receiver_decision(
    representation: EvidenceRepresentation,
    case: dict,
    handoffs: tuple[NeutralHandoff, NeutralHandoff],
) -> None:
    root, leaf = handoffs
    child_body = leaf.to_dict()
    child_body["created_at"] = "2026-08-05T14:00:04Z"
    child = NeutralHandoff.from_dict(child_body)
    root_records = _endpoint_records(
        root,
        representation=representation,
        sender_key=case["keys"]["buyer"],
        receiver_key=case["keys"]["broker"],
    )
    child_records = _endpoint_records(
        child,
        representation=representation,
        sender_key=case["keys"]["broker"],
        receiver_key=case["keys"]["payment"],
        decided_at="2026-08-05T14:00:06Z",
    )
    messages = (
        *_endpoint_messages(
            root,
            root_records,
            representation,
            suffix=f"{representation.value}.temporal-parent",
        ),
        *_endpoint_messages(
            child,
            child_records,
            representation,
            suffix=f"{representation.value}.temporal-child",
        ),
    )
    report = _validate(
        messages,
        representation=representation,
        case=case,
    )
    assert tuple(
        item.handoff.to_dict()["interaction_id"] for item in report.validated_handoffs
    ) == (root.to_dict()["interaction_id"],)
    assert report.issues


def test_pr_child_cannot_predate_parent_receiver_decision(
    case: dict,
    handoffs: tuple[NeutralHandoff, NeutralHandoff],
) -> None:
    root, leaf = handoffs
    child_body = leaf.to_dict()
    child_body["created_at"] = "2026-08-05T14:00:04Z"
    child = NeutralHandoff.from_dict(child_body)
    root_receipt = encode_receipt_handoff(
        root,
        parent_receipt=None,
        sender_private_key=case["keys"]["buyer"],
        receiver_private_key=case["keys"]["broker"],
        receiver_decision=ReceiverDecision.ACCEPT,
        decided_at="2026-08-05T14:00:05Z",
    )
    child_receipt = _encode_pr_without_parent_time_guard(
        child,
        parent_receipt=root_receipt,
        sender_private_key=case["keys"]["broker"],
        receiver_private_key=case["keys"]["payment"],
        decided_at="2026-08-05T14:00:06Z",
    )
    messages = (
        _message(
            root_receipt,
            kind=PayloadKind.RECEIPT,
            origin="store.broker",
            slot="slot.PR.temporal-parent",
        ),
        _message(
            child_receipt,
            kind=PayloadKind.RECEIPT,
            origin="store.payment",
            slot="slot.PR.temporal-child",
        ),
    )
    report = _validate(
        messages,
        representation=EvidenceRepresentation.PR,
        case=case,
    )
    assert tuple(
        item.handoff.to_dict()["interaction_id"] for item in report.validated_handoffs
    ) == (root.to_dict()["interaction_id"],)
    assert report.issues


def test_receipt_encoder_rejects_impossible_time_and_wrong_key_types(
    case: dict,
    handoffs: tuple[NeutralHandoff, NeutralHandoff],
) -> None:
    root, _ = handoffs
    with pytest.raises(
        EvidenceError,
        match="precedes proposal creation|decided_at",
    ):
        encode_receipt_handoff(
            root,
            parent_receipt=None,
            sender_private_key=case["keys"]["buyer"],
            receiver_private_key=case["keys"]["broker"],
            receiver_decision=ReceiverDecision.ACCEPT,
            decided_at="2026-08-05T13:59:59Z",
        )

    for field_name in ("sender_private_key", "receiver_private_key"):
        arguments = {
            "parent_receipt": None,
            "sender_private_key": case["keys"]["buyer"],
            "receiver_private_key": case["keys"]["broker"],
            "receiver_decision": ReceiverDecision.ACCEPT,
            "decided_at": "2026-08-05T14:00:05Z",
        }
        arguments[field_name] = object()
        with pytest.raises(EvidenceError, match=field_name):
            encode_receipt_handoff(root, **arguments)


def test_audit_observation_is_an_explicit_supported_validation_input(
    case: dict,
    handoffs: tuple[NeutralHandoff, NeutralHandoff],
) -> None:
    root, _ = handoffs
    records = _endpoint_records(
        root,
        representation=EvidenceRepresentation.SL,
        sender_key=case["keys"]["buyer"],
        receiver_key=case["keys"]["broker"],
    )
    messages = (
        make_evidence_message(
            delivery_slot_id="slot.audit.sender",
            origin_store_id="store.buyer",
            destination_store_id="store.audit",
            sent_at=NOW,
            payload_kind=PayloadKind.SIGNED_ENDPOINT_RECORD,
            payload=records[0].to_dict(),
        ),
        make_evidence_message(
            delivery_slot_id="slot.audit.receiver",
            origin_store_id="store.broker",
            destination_store_id="store.audit",
            sent_at=NOW,
            payload_kind=PayloadKind.SIGNED_ENDPOINT_RECORD,
            payload=records[1].to_dict(),
        ),
    )
    schedule = compile_schedule(messages, policy=DeliveryPolicy(), seed=SEED)
    audit = project_audit(
        schedule,
        audit_store_id="store.audit",
        episode_end=NOW,
        delta_audit=timedelta(0),
    )
    report = validate_observation(
        audit,
        representation=EvidenceRepresentation.SL,
        key_registry=case["registry"],
        store_registry=_store_registry(),
    )
    assert report.issues == ()
    assert len(report.validated_handoffs) == 1


def test_pr_one_complete_copy_validates_but_missing_parent_and_nested_tamper_fail(
    case: dict,
    handoffs: tuple[NeutralHandoff, NeutralHandoff],
) -> None:
    root, leaf = handoffs
    root_receipt = encode_receipt_handoff(
        root,
        parent_receipt=None,
        sender_private_key=case["keys"]["buyer"],
        receiver_private_key=case["keys"]["broker"],
        receiver_decision=ReceiverDecision.ACCEPT,
        decided_at="2026-08-05T14:00:05Z",
    )
    leaf_receipt = encode_receipt_handoff(
        leaf,
        parent_receipt=root_receipt,
        sender_private_key=case["keys"]["broker"],
        receiver_private_key=case["keys"]["payment"],
        receiver_decision=ReceiverDecision.ACCEPT,
        decided_at="2026-08-05T14:01:05Z",
    )
    root_message = _message(
        root_receipt,
        kind=PayloadKind.RECEIPT,
        origin="store.broker",
        slot="slot.PR.single-root",
    )
    root_only = _validate(
        (root_message,),
        representation=EvidenceRepresentation.PR,
        case=case,
    )
    assert root_only.issues == ()
    assert len(root_only.validated_handoffs) == 1
    assert len(root_only.validated_handoffs[0].source_deliveries) == 1

    leaf_message = _message(
        leaf_receipt,
        kind=PayloadKind.RECEIPT,
        origin="store.payment",
        slot="slot.PR.missing-parent",
    )
    missing_parent = _validate(
        (leaf_message,),
        representation=EvidenceRepresentation.PR,
        case=case,
    )
    assert missing_parent.validated_handoffs == ()
    assert "PARENT_MISSING" in _issue_codes(missing_parent)

    tampered = deepcopy(root_receipt)
    nested = tampered["receiver_attestation"]["sender_attestation"]
    nested_signature = nested["signature"]
    nested["signature"] = (
        "A" if nested_signature[0] != "A" else "B"
    ) + nested_signature[1:]
    tampered_message = _message(
        tampered,
        kind=PayloadKind.RECEIPT,
        origin="store.broker",
        slot="slot.PR.nested-tamper",
    )
    bad_nested = _validate(
        (tampered_message,),
        representation=EvidenceRepresentation.PR,
        case=case,
    )
    assert bad_nested.validated_handoffs == ()
    assert bad_nested.issues


def test_payload_kind_dispatch_and_evaluator_oracle_fields_are_strict(
    case: dict,
    handoffs: tuple[NeutralHandoff, NeutralHandoff],
) -> None:
    root, _ = handoffs
    records = _endpoint_records(
        root,
        representation=EvidenceRepresentation.SL,
        sender_key=case["keys"]["buyer"],
        receiver_key=case["keys"]["broker"],
    )
    wrong_kind_messages = (
        _message(
            records[0].to_dict(),
            kind=PayloadKind.CROSS_REFERENCED_RECORD,
            origin="store.buyer",
            slot="slot.kind.sender",
        ),
        _message(
            records[1].to_dict(),
            kind=PayloadKind.CROSS_REFERENCED_RECORD,
            origin="store.broker",
            slot="slot.kind.receiver",
        ),
    )
    report = _validate(
        wrong_kind_messages,
        representation=EvidenceRepresentation.SL,
        case=case,
    )
    assert report.validated_handoffs == ()
    assert "PAYLOAD_KIND_MISMATCH" in _issue_codes(report)

    with pytest.raises(DeliveryError, match="evaluator-only"):
        _message(
            {**records[0].to_dict(), "ground_truth": "safe"},
            kind=PayloadKind.SIGNED_ENDPOINT_RECORD,
            origin="store.buyer",
            slot="slot.oracle",
        )

    extra = records[0].to_dict()
    extra["unrecognised"] = "value"
    with pytest.raises(EvidenceError, match="fields mismatch"):
        EndpointRecord.from_dict(extra)


def test_mixed_kind_conflict_cannot_be_hidden_from_sl_validation(
    case: dict,
    handoffs: tuple[NeutralHandoff, NeutralHandoff],
) -> None:
    root, _ = handoffs
    records = _endpoint_records(
        root,
        representation=EvidenceRepresentation.SL,
        sender_key=case["keys"]["buyer"],
        receiver_key=case["keys"]["broker"],
    )
    valid_pair = _endpoint_messages(
        root,
        records,
        EvidenceRepresentation.SL,
        suffix="mixed-kind.valid",
    )
    conflict_body = root.to_dict()
    conflict_body["request_hash"] = "sha256:" + "5" * 64
    conflict = NeutralHandoff.from_dict(conflict_body)
    conflicting_sender = sign_endpoint_record(
        conflict,
        role=EndpointRole.SENDER,
        private_key=case["keys"]["buyer"],
    )
    mislabeled_conflict = _message(
        conflicting_sender.to_dict(),
        kind=PayloadKind.CROSS_REFERENCED_RECORD,
        origin="store.buyer",
        slot="slot.mixed-kind.conflict",
    )
    report = _validate(
        (*valid_pair, mislabeled_conflict),
        representation=EvidenceRepresentation.SL,
        case=case,
    )
    assert report.validated_handoffs == ()
    assert "PAYLOAD_KIND_MISMATCH" in _issue_codes(report)


def test_cr_style_receiver_poisons_an_otherwise_valid_sl_interaction(
    case: dict,
    handoffs: tuple[NeutralHandoff, NeutralHandoff],
) -> None:
    root, _ = handoffs
    sender, sl_receiver = _endpoint_records(
        root,
        representation=EvidenceRepresentation.SL,
        sender_key=case["keys"]["buyer"],
        receiver_key=case["keys"]["broker"],
    )
    cr_receiver = sign_endpoint_record(
        root,
        role=EndpointRole.RECEIVER,
        private_key=case["keys"]["broker"],
        sender_record_id=sender.record_id,
        decision=ReceiverDecision.ACCEPT,
        decided_at="2026-08-05T14:00:05Z",
    )
    messages = (
        _message(
            sender.to_dict(),
            kind=PayloadKind.SIGNED_ENDPOINT_RECORD,
            origin="store.buyer",
            slot="slot.profile-poison.sender",
        ),
        _message(
            sl_receiver.to_dict(),
            kind=PayloadKind.SIGNED_ENDPOINT_RECORD,
            origin="store.broker",
            slot="slot.profile-poison.sl-receiver",
        ),
        _message(
            cr_receiver.to_dict(),
            kind=PayloadKind.SIGNED_ENDPOINT_RECORD,
            origin="store.broker",
            slot="slot.profile-poison.cr-receiver",
        ),
    )
    report = _validate(
        messages,
        representation=EvidenceRepresentation.SL,
        case=case,
    )
    assert report.validated_handoffs == ()
    assert "PROFILE_VIOLATION" in _issue_codes(report)


def test_unfair_nonce_receipt_poisons_same_interaction_fair_pr(
    case: dict,
    handoffs: tuple[NeutralHandoff, NeutralHandoff],
) -> None:
    root, _ = handoffs
    fair = encode_receipt_handoff(
        root,
        parent_receipt=None,
        sender_private_key=case["keys"]["buyer"],
        receiver_private_key=case["keys"]["broker"],
        receiver_decision=ReceiverDecision.ACCEPT,
        decided_at="2026-08-05T14:00:05Z",
    )
    fair_proposal = fair["proposal"]
    unfair_proposal = make_proposal(
        interaction_id=fair_proposal["interaction_id"],
        event_type=fair_proposal["event_type"],
        created_at=fair_proposal["created_at"],
        nonce="unfair-nonce-002",
        sender=fair_proposal["sender"],
        receiver=fair_proposal["receiver"],
        sender_sequence=fair_proposal["sender_sequence"],
        previous_receipt_id=fair_proposal["previous_receipt_id"],
        scope=fair_proposal["scope"],
        authority=fair_proposal["authority"],
        request_hash=fair_proposal["request_hash"],
    )
    unfair = sign_receipt(
        unfair_proposal,
        sender_private_key=case["keys"]["buyer"],
        receiver_private_key=case["keys"]["broker"],
        receiver_decision="ACCEPT",
        decided_at="2026-08-05T14:00:05Z",
    )
    messages = (
        _message(
            fair,
            kind=PayloadKind.RECEIPT,
            origin="store.broker",
            slot="slot.PR.profile-poison.fair",
        ),
        _message(
            unfair,
            kind=PayloadKind.RECEIPT,
            origin="store.broker",
            slot="slot.PR.profile-poison.unfair",
        ),
    )
    report = _validate(
        messages,
        representation=EvidenceRepresentation.PR,
        case=case,
    )
    assert report.validated_handoffs == ()
    assert "PROFILE_VIOLATION" in _issue_codes(report)


def test_policy_view_subclass_cannot_forge_validator_issuance(
    case: dict,
    handoffs: tuple[NeutralHandoff, NeutralHandoff],
) -> None:
    root, _ = handoffs
    records = _endpoint_records(
        root,
        representation=EvidenceRepresentation.SL,
        sender_key=case["keys"]["buyer"],
        receiver_key=case["keys"]["broker"],
    )
    report = _validate(
        _endpoint_messages(
            root,
            records,
            EvidenceRepresentation.SL,
            suffix="policy-subclass",
        ),
        representation=EvidenceRepresentation.SL,
        case=case,
    )
    genuine = report.validated_handoffs[0].policy_view()

    class ForgedPolicyView(PolicyView):
        @property
        def validator_issued(self) -> bool:
            return True

    forged = ForgedPolicyView.from_dict(genuine.to_dict())
    assert forged.validator_issued
    with pytest.raises(EvidenceError, match="issued directly"):
        evaluate_common_evidence_policy(forged)


def test_parent_cycle_and_parentless_action_root_are_rejected(
    case: dict,
    handoffs: tuple[NeutralHandoff, NeutralHandoff],
) -> None:
    root, leaf = handoffs
    cycle_a_body = root.to_dict()
    cycle_a_body.update(
        {
            "interaction_id": "cycle-a",
            "sender_sequence": 11,
            "previous_interaction_id": "cycle-b",
        }
    )
    cycle_b_body = leaf.to_dict()
    cycle_b_body.update(
        {
            "interaction_id": "cycle-b",
            "event_type": "delegation",
            "sender_sequence": 12,
            "previous_interaction_id": "cycle-a",
        }
    )
    cycle_a = NeutralHandoff.from_dict(cycle_a_body)
    cycle_b = NeutralHandoff.from_dict(cycle_b_body)
    cycle_a_records = _endpoint_records(
        cycle_a,
        representation=EvidenceRepresentation.SL,
        sender_key=case["keys"]["buyer"],
        receiver_key=case["keys"]["broker"],
    )
    cycle_b_records = _endpoint_records(
        cycle_b,
        representation=EvidenceRepresentation.SL,
        sender_key=case["keys"]["broker"],
        receiver_key=case["keys"]["payment"],
        decided_at="2026-08-05T14:01:05Z",
    )
    cycle_report = _validate(
        (
            *_endpoint_messages(
                cycle_a,
                cycle_a_records,
                EvidenceRepresentation.SL,
                suffix="cycle-a",
            ),
            *_endpoint_messages(
                cycle_b,
                cycle_b_records,
                EvidenceRepresentation.SL,
                suffix="cycle-b",
            ),
        ),
        representation=EvidenceRepresentation.SL,
        case=case,
    )
    assert cycle_report.validated_handoffs == ()
    assert "PARENT_CYCLE" in _issue_codes(cycle_report)

    invalid_root_body = root.to_dict()
    invalid_root_body.update(
        {
            "interaction_id": "parentless-action-root",
            "event_type": "action_intent",
            "sender_sequence": 13,
        }
    )
    invalid_root = NeutralHandoff.from_dict(invalid_root_body)
    invalid_root_records = _endpoint_records(
        invalid_root,
        representation=EvidenceRepresentation.SL,
        sender_key=case["keys"]["buyer"],
        receiver_key=case["keys"]["broker"],
    )
    root_report = _validate(
        _endpoint_messages(
            invalid_root,
            invalid_root_records,
            EvidenceRepresentation.SL,
            suffix="root-invalid",
        ),
        representation=EvidenceRepresentation.SL,
        case=case,
    )
    assert root_report.validated_handoffs == ()
    assert "ROOT_INVALID" in _issue_codes(root_report)


@pytest.mark.parametrize(
    "representation",
    tuple(EvidenceRepresentation),
)
def test_empty_observation_reports_evidence_missing(
    representation: EvidenceRepresentation,
    case: dict,
) -> None:
    report = _validate(
        (),
        representation=representation,
        case=case,
    )
    assert report.validated_handoffs == ()
    assert _issue_codes(report) == {"EVIDENCE_MISSING"}


def test_unknown_public_key_registry_never_falls_back_to_trust(
    case: dict,
    handoffs: tuple[NeutralHandoff, NeutralHandoff],
) -> None:
    root, _ = handoffs
    records = _endpoint_records(
        root,
        representation=EvidenceRepresentation.SL,
        sender_key=case["keys"]["buyer"],
        receiver_key=case["keys"]["broker"],
    )
    empty_registry = KeyRegistry()
    observation = _observation(
        _endpoint_messages(
            root, records, EvidenceRepresentation.SL, suffix="empty-keys"
        )
    )
    report = validate_observation(
        observation,
        representation=EvidenceRepresentation.SL,
        key_registry=empty_registry,
        store_registry=_store_registry(),
    )
    assert report.validated_handoffs == ()
    assert report.issues
