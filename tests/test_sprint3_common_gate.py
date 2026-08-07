"""Adversarial development tests for the Sprint 3 common gate.

These synthetic fixtures are engineering conformance checks, not trials or
evidence that CrossTrace improves safety.
"""

from __future__ import annotations

import json
import threading
from copy import deepcopy
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from crosstrace_sketch.demo import build_fixture
from crosstrace_sketch.protocol import (
    action_id,
    content_id,
    receipt_id,
    sign_authority_status,
)
from preaward.crosstrace_sprint1.delivery import (
    DeliveryPolicy,
    PayloadKind,
    PermitLifecycle as LegacyPermitLifecycle,
    PermitStateRecord,
    PermitStateSnapshot,
    compile_schedule,
    empty_permit_state,
    make_evidence_message,
    project_audit,
    project_local,
)
from preaward.crosstrace_sprint2.model import (
    EndpointRole,
    EvidenceRepresentation,
    ReceiverDecision,
    make_neutral_handoff,
    sign_endpoint_record,
)
from preaward.crosstrace_sprint2.validation import (
    StoreRegistry,
    encode_receipt_handoff,
)
from preaward.crosstrace_sprint3 import (
    CommonActionGate,
    CommonGateInput,
    GateError,
    NeutralObservationRecord,
    NeutralPermitStore,
    ObservationKind,
    StatusStoreRegistry,
    VerifierRegistry,
    prepare_common_gate_input,
)
from preaward.crosstrace_sprint3.permit import ReplayDetected

DECISION_TIME = datetime(2026, 8, 5, 14, 5, 0, tzinfo=UTC)
VERIFIER_ID = "verifier.local"
EVIDENCE_STORE_ID = "store.verifier"
PERMIT_STORE_ID = "store.permits"
STATUS_STORE_ID = "store.authority"
TOOL_ID = "simulated-payment-adapter"
SEED = b"crosstrace-sprint3-development-fixture"


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


def _handoffs(
    case: dict,
    *,
    status_id: str | None = None,
    root_scope: dict | None = None,
    leaf_scope: dict | None = None,
    leaf_lineage: dict | None = None,
    leaf_request_hash: str | None = None,
    root_event_type: str = "delegation",
    leaf_sender: dict | None = None,
    leaf_receiver: dict | None = None,
    previous_interaction_id: str = "handoff-buyer-broker-001",
    leaf_created_at: str = "2026-08-05T14:01:00Z",
    leaf_sender_sequence: int = 1,
):
    status_id = status_id or case["active_status"]["status_id"]
    lineage = _lineage(case)
    root = make_neutral_handoff(
        interaction_id="handoff-buyer-broker-001",
        sender=case["parties"]["buyer"],
        receiver=case["parties"]["broker"],
        event_type=root_event_type,
        sender_sequence=1,
        previous_interaction_id=None,
        scope=root_scope or case["root_scope"],
        authority_lineage=lineage,
        authority_version=case["authority"]["authority_version"],
        referenced_status_id=status_id,
        created_at="2026-08-05T14:00:00Z",
        request_hash=case["root_receipt"]["proposal"]["request_hash"],
    )
    leaf = make_neutral_handoff(
        interaction_id="handoff-broker-payment-001",
        sender=leaf_sender or case["parties"]["broker"],
        receiver=leaf_receiver or case["parties"]["payment"],
        event_type="action_intent",
        sender_sequence=leaf_sender_sequence,
        previous_interaction_id=previous_interaction_id,
        scope=leaf_scope or case["leaf_scope"],
        authority_lineage=leaf_lineage or lineage,
        authority_version=case["authority"]["authority_version"],
        referenced_status_id=status_id,
        created_at=leaf_created_at,
        request_hash=leaf_request_hash or action_id(case["valid_action"]),
    )
    return root, leaf


def _endpoint_stores() -> StoreRegistry:
    stores = StoreRegistry()
    stores.add(
        store_id="store.buyer",
        principal_id="buyer.example",
        roles={EndpointRole.SENDER},
    )
    stores.add(
        store_id="store.broker",
        principal_id="broker.example",
        roles={EndpointRole.SENDER, EndpointRole.RECEIVER},
    )
    stores.add(
        store_id="store.payment",
        principal_id="payment.example",
        roles={EndpointRole.RECEIVER},
    )
    return stores


def _verifiers() -> VerifierRegistry:
    registry = VerifierRegistry()
    registry.add(
        verifier_id=VERIFIER_ID,
        evidence_store_id=EVIDENCE_STORE_ID,
        permit_store_id=PERMIT_STORE_ID,
        tool_ids=(TOOL_ID,),
    )
    return registry


def _status_stores() -> StatusStoreRegistry:
    registry = StatusStoreRegistry()
    registry.add(
        store_id=STATUS_STORE_ID,
        issuer_principal_id="buyer.example",
    )
    return registry


def _message(payload, *, kind: PayloadKind, origin: str, slot: str):
    return make_evidence_message(
        delivery_slot_id=slot,
        origin_store_id=origin,
        destination_store_id=EVIDENCE_STORE_ID,
        sent_at=datetime(2026, 8, 5, 14, 2, 0, tzinfo=UTC),
        payload_kind=kind,
        payload=payload,
    )


def _representation_messages(
    representation: EvidenceRepresentation,
    case: dict,
    handoffs,
):
    root, leaf = handoffs
    key_by_principal = {
        "buyer.example": case["keys"]["buyer"],
        "broker.example": case["keys"]["broker"],
        "payment.example": case["keys"]["payment"],
    }
    store_by_principal = {
        "buyer.example": "store.buyer",
        "broker.example": "store.broker",
        "payment.example": "store.payment",
    }
    if representation in {EvidenceRepresentation.SL, EvidenceRepresentation.CR}:
        kind = (
            PayloadKind.SIGNED_ENDPOINT_RECORD
            if representation is EvidenceRepresentation.SL
            else PayloadKind.CROSS_REFERENCED_RECORD
        )
        result = []
        for suffix, handoff, decided_at in (
            (
                "root",
                root,
                "2026-08-05T14:00:05Z",
            ),
            (
                "leaf",
                leaf,
                "2026-08-05T14:01:05Z",
            ),
        ):
            handoff_body = handoff.to_dict()
            sender_principal = handoff_body["sender"]["principal_id"]
            receiver_principal = handoff_body["receiver"]["principal_id"]
            sender = sign_endpoint_record(
                handoff,
                role=EndpointRole.SENDER,
                private_key=key_by_principal[sender_principal],
            )
            receiver = sign_endpoint_record(
                handoff,
                role=EndpointRole.RECEIVER,
                private_key=key_by_principal[receiver_principal],
                sender_record_id=(
                    sender.record_id
                    if representation is EvidenceRepresentation.CR
                    else None
                ),
                decision=ReceiverDecision.ACCEPT,
                decided_at=decided_at,
            )
            result.extend(
                (
                    _message(
                        sender.to_dict(),
                        kind=kind,
                        origin=store_by_principal[sender_principal],
                        slot=f"slot.{suffix}.sender",
                    ),
                    _message(
                        receiver.to_dict(),
                        kind=kind,
                        origin=store_by_principal[receiver_principal],
                        slot=f"slot.{suffix}.receiver",
                    ),
                )
            )
        return tuple(result)

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
    return (
        _message(
            root_receipt,
            kind=PayloadKind.RECEIPT,
            origin="store.buyer",
            slot="slot.root.sender",
        ),
        _message(
            leaf_receipt,
            kind=PayloadKind.RECEIPT,
            origin="store.broker",
            slot="slot.leaf.sender",
        ),
    )


def _observation(
    representation: EvidenceRepresentation,
    case: dict,
    handoffs,
    *,
    statuses: tuple[dict, ...] | None = None,
    status_origins: tuple[str, ...] | None = None,
    decision_time: datetime = DECISION_TIME,
    legacy_state: PermitStateSnapshot | None = None,
):
    if statuses is None:
        statuses = (case["active_status"],)
    if status_origins is None:
        status_origins = tuple(STATUS_STORE_ID for _ in statuses)
    messages = list(_representation_messages(representation, case, handoffs))
    for index, (status, origin) in enumerate(
        zip(statuses, status_origins, strict=True)
    ):
        messages.append(
            _message(
                status,
                kind=PayloadKind.AUTHORITY_STATUS,
                origin=origin,
                slot=f"slot.status.{index}",
            )
        )
    schedule = compile_schedule(
        tuple(messages),
        policy=DeliveryPolicy(),
        seed=SEED,
    )
    return project_local(
        schedule,
        verifier_id=VERIFIER_ID,
        evidence_store_id=EVIDENCE_STORE_ID,
        permit_store_id=PERMIT_STORE_ID,
        decision_time=decision_time,
        permit_state=legacy_state
        or empty_permit_state(
            permit_store_id=PERMIT_STORE_ID,
            captured_at=decision_time,
        ),
    )


def _prepared(
    representation: EvidenceRepresentation,
    *,
    case: dict | None = None,
    handoffs=None,
    statuses: tuple[dict, ...] | None = None,
    status_origins: tuple[str, ...] | None = None,
    decision_time: datetime = DECISION_TIME,
    permit_store: NeutralPermitStore | None = None,
    verifier_registry: VerifierRegistry | None = None,
    status_registry: StatusStoreRegistry | None = None,
    legacy_state: PermitStateSnapshot | None = None,
):
    case = case or build_fixture()
    handoffs = handoffs or _handoffs(case)
    permit_store = permit_store or NeutralPermitStore(
        ":memory:",
        permit_store_id=PERMIT_STORE_ID,
        permit_id_factory=lambda: "permit.fixed",
    )
    observation = _observation(
        representation,
        case,
        handoffs,
        statuses=statuses,
        status_origins=status_origins,
        decision_time=decision_time,
        legacy_state=legacy_state,
    )
    snapshot = permit_store.snapshot(captured_at=decision_time)
    verifiers = verifier_registry or _verifiers()
    prepared = prepare_common_gate_input(
        observation=observation,
        representation=representation,
        key_registry=case["registry"],
        store_registry=_endpoint_stores(),
        verifier_registry=verifiers,
        status_store_registry=status_registry or _status_stores(),
        permit_state=snapshot,
    )
    gate = CommonActionGate(
        verifier_registry=verifiers,
        permit_store=permit_store,
        permit_ttl_seconds=60,
    )
    return case, permit_store, prepared, gate


@pytest.mark.parametrize("representation", tuple(EvidenceRepresentation))
def test_all_representations_authorize_and_bind_neutral_identity(representation):
    case, store, prepared, gate = _prepared(representation)
    decision = gate.authorize(prepared, action=case["valid_action"], tool_id=TOOL_ID)
    assert decision.allowed
    leaf_view = next(
        view
        for view in prepared.policy_views
        if view.to_dict()["handoff"]["event_type"] == "action_intent"
    )
    assert decision.leaf_neutral_handoff_id == leaf_view.to_dict()["neutral_handoff_id"]
    assert decision.permit_expires_at == "2026-08-05T14:06:00Z"
    snapshot = store.snapshot(captured_at=DECISION_TIME)
    assert snapshot.revision == 1
    assert (
        snapshot.records[0].leaf_neutral_handoff_id == decision.leaf_neutral_handoff_id
    )
    assert len(snapshot.observations) == 4
    store.close()


def test_representation_blind_inputs_and_decisions_are_identical():
    inputs = []
    decisions = []
    for representation in EvidenceRepresentation:
        case, store, prepared, gate = _prepared(representation)
        inputs.append(prepared.to_dict())
        decisions.append(
            gate.authorize(
                prepared,
                action=case["valid_action"],
                tool_id=TOOL_ID,
            ).to_dict()
        )
        store.close()
    assert inputs[0] == inputs[1] == inputs[2]
    assert decisions[0] == decisions[1] == decisions[2]
    assert "representation" not in inputs[0]
    assert "representation" not in decisions[0]


def test_consume_before_adapter_finish_and_replay():
    case, store, prepared, gate = _prepared(EvidenceRepresentation.PR)
    decision = gate.authorize(prepared, action=case["valid_action"], tool_id=TOOL_ID)
    naive = gate.consume(
        permit_id=decision.permit_id,
        action=case["valid_action"],
        tool_id=TOOL_ID,
        now=datetime(2026, 8, 5, 14, 5, 1),
    )
    assert naive.to_dict()["reason"] == "PERMIT_TIME_INVALID"
    assert store.snapshot(captured_at=DECISION_TIME).revision == 1
    microseconds = gate.consume(
        permit_id=decision.permit_id,
        action=case["valid_action"],
        tool_id=TOOL_ID,
        now=DECISION_TIME + timedelta(microseconds=1),
    )
    assert microseconds.reason == "PERMIT_TIME_INVALID"
    assert store.snapshot(captured_at=DECISION_TIME).revision == 1
    first = gate.consume(
        permit_id=decision.permit_id,
        action=case["valid_action"],
        tool_id=TOOL_ID,
        now=DECISION_TIME + timedelta(seconds=10),
    )
    second = gate.consume(
        permit_id=decision.permit_id,
        action=case["valid_action"],
        tool_id=TOOL_ID,
        now=DECISION_TIME + timedelta(seconds=11),
    )
    assert first.allowed
    assert second.to_dict()["reason"] == "REPLAY_DETECTED"
    assert gate.finish(permit_id=decision.permit_id, succeeded=True)
    assert not gate.finish(permit_id=decision.permit_id, succeeded=True)
    assert (
        store.snapshot(captured_at=DECISION_TIME + timedelta(seconds=12)).revision == 3
    )
    store.close()


def test_cross_representation_replay_is_one_neutral_replay_key():
    case = build_fixture()
    store = NeutralPermitStore(":memory:", permit_store_id=PERMIT_STORE_ID)
    _, _, first_input, first_gate = _prepared(
        EvidenceRepresentation.SL,
        case=case,
        permit_store=store,
    )
    assert first_gate.authorize(
        first_input,
        action=case["valid_action"],
        tool_id=TOOL_ID,
    ).allowed
    _, _, second_input, second_gate = _prepared(
        EvidenceRepresentation.PR,
        case=case,
        permit_store=store,
    )
    second = second_gate.authorize(
        second_input,
        action=case["valid_action"],
        tool_id=TOOL_ID,
    )
    assert second.reasons == ("REPLAY_DETECTED",)
    store.close()


def test_stale_revision_and_concurrent_reservation_fail_closed():
    case = build_fixture()
    store = NeutralPermitStore(":memory:", permit_store_id=PERMIT_STORE_ID)
    _, _, prepared, gate = _prepared(
        EvidenceRepresentation.CR,
        case=case,
        permit_store=store,
    )
    results = []

    def authorise():
        results.append(
            gate.authorize(
                prepared,
                action=case["valid_action"],
                tool_id=TOOL_ID,
            )
        )

    threads = (threading.Thread(target=authorise), threading.Thread(target=authorise))
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert sum(item.allowed for item in results) == 1
    assert {reason for item in results for reason in item.reasons} == {"STATE_CHANGED"}
    store.close()


def test_deterministic_id_collision_rolls_back_observations_and_revision():
    store = NeutralPermitStore(
        ":memory:",
        permit_store_id=PERMIT_STORE_ID,
        permit_id_factory=lambda: "permit.fixed",
    )
    first_observation = NeutralObservationRecord(
        observation_kind=ObservationKind.INTERACTION,
        observation_key=content_id("TEST_KEY", {"value": 1}),
        neutral_handoff_id=content_id("TEST_HANDOFF", {"value": 1}),
    )
    common = {
        "leaf_neutral_handoff_id": content_id("TEST_LEAF", {"value": 1}),
        "neutral_chain_id": content_id("TEST_CHAIN", {"value": 1}),
        "controlling_status_id": content_id("TEST_STATUS", {"value": 1}),
        "replay_scope_id": content_id("TEST_SCOPE", {"value": 1}),
        "request_hash": content_id("TEST_ACTION", {"value": 1}),
        "tool_id": TOOL_ID,
        "issued_at": DECISION_TIME,
        "expires_at": DECISION_TIME + timedelta(seconds=60),
    }
    store.reserve(
        expected_revision=0,
        observations=(first_observation,),
        action_nonce="nonce.one",
        **common,
    )
    second_observation = NeutralObservationRecord(
        observation_kind=ObservationKind.INTERACTION,
        observation_key=content_id("TEST_KEY", {"value": 2}),
        neutral_handoff_id=content_id("TEST_HANDOFF", {"value": 2}),
    )
    with pytest.raises(ReplayDetected):
        store.reserve(
            expected_revision=1,
            observations=(second_observation,),
            action_nonce="nonce.two",
            **common,
        )
    snapshot = store.snapshot(captured_at=DECISION_TIME)
    assert snapshot.revision == 1
    assert snapshot.observations == (first_observation,)
    assert len(snapshot.records) == 1
    store.close()


@pytest.mark.parametrize(
    ("status_mode", "expected"),
    (("revoked", "AUTHORITY_REVOKED"), ("stale", "STATUS_STALE")),
)
def test_revoked_and_stale_statuses_pause(status_mode, expected):
    case = build_fixture()
    if status_mode == "revoked":
        status = case["revoked_status"]
    else:
        status = sign_authority_status(
            issuer_principal_id="buyer.example",
            issuer_key_id="buyer-root-key-1",
            subject_principal_id="broker.example",
            subject_key_id="broker-agent-key-1",
            authority_version=7,
            state="ACTIVE",
            issued_at="2026-08-05T13:55:00Z",
            fresh_until="2026-08-05T14:04:59Z",
            issuer_private_key=case["keys"]["buyer_root"],
        )
    handoffs = _handoffs(case, status_id=status["status_id"])
    _, store, prepared, gate = _prepared(
        EvidenceRepresentation.PR,
        case=case,
        handoffs=handoffs,
        statuses=(status,),
    )
    decision = gate.authorize(prepared, action=case["valid_action"], tool_id=TOOL_ID)
    assert expected in decision.reasons
    assert decision.permit_id is None
    store.close()


def test_same_version_status_conflict_never_selects_active_candidate():
    case = build_fixture()
    conflicting = sign_authority_status(
        issuer_principal_id="buyer.example",
        issuer_key_id="buyer-root-key-1",
        subject_principal_id="broker.example",
        subject_key_id="broker-agent-key-1",
        authority_version=7,
        state="REVOKED",
        issued_at="2026-08-05T13:56:00Z",
        fresh_until="2026-08-05T14:09:00Z",
        issuer_private_key=case["keys"]["buyer_root"],
    )
    _, store, prepared, gate = _prepared(
        EvidenceRepresentation.SL,
        case=case,
        statuses=(case["active_status"], conflicting),
    )
    decision = gate.authorize(prepared, action=case["valid_action"], tool_id=TOOL_ID)
    assert "STATUS_CONFLICT" in decision.reasons
    store.close()


@pytest.mark.parametrize("fault", ("signature", "store"))
def test_invalid_status_signature_and_origin_store_pause_during_preparation(fault):
    case = build_fixture()
    status = deepcopy(case["active_status"])
    origins = (STATUS_STORE_ID,)
    if fault == "signature":
        signature = status["attestation"]["signature"]
        status["attestation"]["signature"] = (
            "A" if signature[0] != "A" else "B"
        ) + signature[1:]
    else:
        origins = ("store.untrusted-status",)
    _, store, prepared, gate = _prepared(
        EvidenceRepresentation.CR,
        case=case,
        statuses=(status,),
        status_origins=origins,
    )
    assert "STATUS_INVALID" in prepared.preparation_reasons
    decision = gate.authorize(prepared, action=case["valid_action"], tool_id=TOOL_ID)
    assert "STATUS_INVALID" in decision.reasons
    store.close()


def test_scope_expansion_action_out_of_scope_and_action_hash_change_pause():
    case = build_fixture()
    expanded = deepcopy(case["leaf_scope"])
    expanded["max_amount_minor"] = case["root_scope"]["max_amount_minor"] + 1
    handoffs = _handoffs(case, leaf_scope=expanded)
    _, store, prepared, gate = _prepared(
        EvidenceRepresentation.PR,
        case=case,
        handoffs=handoffs,
    )
    assert (
        "SCOPE_EXPANSION"
        in gate.authorize(
            prepared,
            action=case["valid_action"],
            tool_id=TOOL_ID,
        ).reasons
    )
    store.close()

    over_limit_handoffs = _handoffs(
        case,
        leaf_request_hash=action_id(case["over_limit_action"]),
    )
    _, store, prepared, gate = _prepared(
        EvidenceRepresentation.SL,
        case=case,
        handoffs=over_limit_handoffs,
    )
    assert (
        "ACTION_OUT_OF_SCOPE"
        in gate.authorize(
            prepared,
            action=case["over_limit_action"],
            tool_id=TOOL_ID,
        ).reasons
    )
    changed = deepcopy(case["valid_action"])
    changed["action_nonce"] = "another-attempt"
    assert gate.authorize(prepared, action=changed, tool_id=TOOL_ID).reasons == (
        "LEAF_MISSING",
    )
    store.close()


def test_lineage_root_role_and_scope_time_fail_closed():
    case = build_fixture()
    wrong_lineage = _lineage(case)
    wrong_lineage["subject_key_id"] = "different-broker-key"
    handoffs = _handoffs(case, leaf_lineage=wrong_lineage)
    _, store, prepared, gate = _prepared(
        EvidenceRepresentation.CR,
        case=case,
        handoffs=handoffs,
    )
    assert (
        "AUTHORITY_CHAIN_MISMATCH"
        in gate.authorize(
            prepared,
            action=case["valid_action"],
            tool_id=TOOL_ID,
        ).reasons
    )
    store.close()

    root_invalid = _handoffs(case, root_event_type="action_intent")
    _, store, prepared, gate = _prepared(
        EvidenceRepresentation.SL,
        case=case,
        handoffs=root_invalid,
    )
    decision = gate.authorize(prepared, action=case["valid_action"], tool_id=TOOL_ID)
    assert "ROOT_INVALID" in decision.reasons
    store.close()

    expired_root = deepcopy(case["root_scope"])
    expired_leaf = deepcopy(case["leaf_scope"])
    expired_root["not_after"] = "2026-08-05T14:04:59Z"
    expired_leaf["not_after"] = "2026-08-05T14:04:58Z"
    expired = _handoffs(case, root_scope=expired_root, leaf_scope=expired_leaf)
    _, store, prepared, gate = _prepared(
        EvidenceRepresentation.PR,
        case=case,
        handoffs=expired,
    )
    assert (
        "EXPIRED"
        in gate.authorize(
            prepared,
            action=case["valid_action"],
            tool_id=TOOL_ID,
        ).reasons
    )
    store.close()


def test_deserialized_input_unknown_tool_and_string_registries_are_rejected():
    case, store, prepared, gate = _prepared(EvidenceRepresentation.PR)
    decoded = CommonGateInput.from_bytes(prepared.canonical_bytes)
    assert not decoded.preparer_issued
    with pytest.raises(GateError):
        gate.authorize(decoded, action=case["valid_action"], tool_id=TOOL_ID)
    assert gate.authorize(
        prepared,
        action=case["valid_action"],
        tool_id="unregistered-adapter",
    ).reasons == ("TOOL_UNAUTHORISED",)
    with pytest.raises(GateError):
        VerifierRegistry().add(
            verifier_id=VERIFIER_ID,
            evidence_store_id=EVIDENCE_STORE_ID,
            permit_store_id=PERMIT_STORE_ID,
            tool_ids=TOOL_ID,
        )
    with pytest.raises(GateError):
        StatusStoreRegistry().add(
            store_id=STATUS_STORE_ID,
            issuer_principal_ids="buyer.example",
        )
    store.close()


def test_nonempty_legacy_permit_snapshot_and_closed_state_pause():
    case = build_fixture()
    legacy = PermitStateSnapshot(
        permit_store_id=PERMIT_STORE_ID,
        captured_at=DECISION_TIME,
        records=(
            PermitStateRecord(
                permit_id="legacy.permit",
                leaf_receipt_id=receipt_id(case["leaf_receipt"]),
                replay_scope=content_id("LEGACY_SCOPE", {}),
                request_hash=action_id(case["valid_action"]),
                action_nonce="legacy-nonce",
                tool_id=TOOL_ID,
                state=LegacyPermitLifecycle.RESERVED,
                issued_at=DECISION_TIME - timedelta(seconds=1),
                expires_at=DECISION_TIME + timedelta(seconds=60),
            ),
        ),
        observations=(),
    )
    _, store, prepared, gate = _prepared(
        EvidenceRepresentation.SL,
        case=case,
        legacy_state=legacy,
    )
    assert gate.authorize(
        prepared,
        action=case["valid_action"],
        tool_id=TOOL_ID,
    ).reasons == ("LEGACY_PERMIT_STATE_NONEMPTY",)
    store.close()

    _, store, prepared, gate = _prepared(EvidenceRepresentation.PR, case=case)
    store.close()
    assert gate.authorize(
        prepared,
        action=case["valid_action"],
        tool_id=TOOL_ID,
    ).reasons == ("STATE_UNAVAILABLE",)


def test_audit_observation_and_store_binding_mismatches_are_rejected():
    case = build_fixture()
    handoffs = _handoffs(case)
    messages = list(_representation_messages(EvidenceRepresentation.SL, case, handoffs))
    messages.append(
        _message(
            case["active_status"],
            kind=PayloadKind.AUTHORITY_STATUS,
            origin=STATUS_STORE_ID,
            slot="slot.status.audit",
        )
    )
    schedule = compile_schedule(
        tuple(messages),
        policy=DeliveryPolicy(),
        seed=SEED,
    )
    audit = project_audit(
        schedule,
        audit_store_id=EVIDENCE_STORE_ID,
        episode_end=DECISION_TIME,
        delta_audit=timedelta(0),
    )
    store = NeutralPermitStore(":memory:", permit_store_id=PERMIT_STORE_ID)
    with pytest.raises(GateError):
        prepare_common_gate_input(
            observation=audit,
            representation=EvidenceRepresentation.SL,
            key_registry=case["registry"],
            store_registry=_endpoint_stores(),
            verifier_registry=_verifiers(),
            status_store_registry=_status_stores(),
            permit_state=store.snapshot(captured_at=DECISION_TIME),
        )
    mismatched = VerifierRegistry()
    mismatched.add(
        verifier_id=VERIFIER_ID,
        evidence_store_id="store.other-evidence",
        permit_store_id=PERMIT_STORE_ID,
        tool_ids=(TOOL_ID,),
    )
    _, _, prepared, gate = _prepared(
        EvidenceRepresentation.SL,
        case=case,
        permit_store=store,
        verifier_registry=mismatched,
    )
    assert gate.authorize(
        prepared,
        action=case["valid_action"],
        tool_id=TOOL_ID,
    ).reasons == ("VERIFIER_STORE_MISMATCH",)
    other_store = NeutralPermitStore(":memory:", permit_store_id="store.other-permits")
    observation = _observation(EvidenceRepresentation.SL, case, handoffs)
    with pytest.raises(GateError):
        prepare_common_gate_input(
            observation=observation,
            representation=EvidenceRepresentation.SL,
            key_registry=case["registry"],
            store_registry=_endpoint_stores(),
            verifier_registry=_verifiers(),
            status_store_registry=_status_stores(),
            permit_state=other_store.snapshot(captured_at=DECISION_TIME),
        )
    other_store.close()
    store.close()


def test_missing_and_future_authority_statuses_pause():
    case = build_fixture()
    _, store, prepared, gate = _prepared(
        EvidenceRepresentation.PR,
        case=case,
        statuses=(),
    )
    assert gate.authorize(
        prepared,
        action=case["valid_action"],
        tool_id=TOOL_ID,
    ).reasons == ("STATUS_MISSING",)
    store.close()

    future = sign_authority_status(
        issuer_principal_id="buyer.example",
        issuer_key_id="buyer-root-key-1",
        subject_principal_id="broker.example",
        subject_key_id="broker-agent-key-1",
        authority_version=7,
        state="ACTIVE",
        issued_at="2026-08-05T14:06:00Z",
        fresh_until="2026-08-05T14:10:00Z",
        issuer_private_key=case["keys"]["buyer_root"],
    )
    handoffs = _handoffs(case, status_id=future["status_id"])
    _, store, prepared, gate = _prepared(
        EvidenceRepresentation.CR,
        case=case,
        handoffs=handoffs,
        statuses=(future,),
    )
    reasons = gate.authorize(
        prepared,
        action=case["valid_action"],
        tool_id=TOOL_ID,
    ).reasons
    assert "STATUS_NOT_YET_VALID" in reasons
    assert "STATUS_CAUSAL_TIME_INVALID" in reasons
    store.close()


@pytest.mark.parametrize(
    ("mutation", "expected"),
    (
        ("parent", "PARENT_MISSING"),
        ("party", "PARTY_CONTINUITY_INVALID"),
        ("time", "PARENT_TIME_INVALID"),
    ),
)
def test_parent_party_and_causal_failures_never_reach_common_policy(
    mutation,
    expected,
):
    case = build_fixture()
    options = {}
    if mutation == "parent":
        options["previous_interaction_id"] = "handoff.absent"
    elif mutation == "party":
        options.update(
            leaf_sender=case["parties"]["buyer"],
            leaf_sender_sequence=2,
        )
    else:
        options["leaf_created_at"] = "2026-08-05T14:00:04Z"
    handoffs = _handoffs(case, **options)
    _, store, prepared, gate = _prepared(
        EvidenceRepresentation.SL,
        case=case,
        handoffs=handoffs,
    )
    assert (
        expected
        in gate.authorize(
            prepared,
            action=case["valid_action"],
            tool_id=TOOL_ID,
        ).reasons
    )
    store.close()


def test_consume_mismatches_expiry_and_attempted_crash_do_not_retry():
    case, store, prepared, gate = _prepared(EvidenceRepresentation.PR)
    decision = gate.authorize(prepared, action=case["valid_action"], tool_id=TOOL_ID)
    wrong_action = deepcopy(case["valid_action"])
    wrong_action["amount_minor"] -= 1
    assert (
        gate.consume(
            permit_id=decision.permit_id,
            action=wrong_action,
            tool_id=TOOL_ID,
            now=DECISION_TIME + timedelta(seconds=1),
        ).reason
        == "PERMIT_ACTION_MISMATCH"
    )
    assert (
        gate.consume(
            permit_id=decision.permit_id,
            action=case["valid_action"],
            tool_id="another-tool",
            now=DECISION_TIME + timedelta(seconds=1),
        ).reason
        == "PERMIT_INVALID"
    )
    assert (
        gate.consume(
            permit_id=decision.permit_id,
            action=case["valid_action"],
            tool_id=TOOL_ID,
            now=DECISION_TIME + timedelta(seconds=60),
        ).reason
        == "PERMIT_EXPIRED"
    )
    attempted = gate.consume(
        permit_id=decision.permit_id,
        action=case["valid_action"],
        tool_id=TOOL_ID,
        now=DECISION_TIME + timedelta(seconds=1),
    )
    assert attempted.allowed
    assert (
        store.snapshot(captured_at=DECISION_TIME + timedelta(seconds=2))
        .records[0]
        .state.value
        == "ATTEMPTED"
    )
    _, _, retry_input, retry_gate = _prepared(
        EvidenceRepresentation.SL,
        case=case,
        permit_store=store,
    )
    assert retry_gate.authorize(
        retry_input,
        action=case["valid_action"],
        tool_id=TOOL_ID,
    ).reasons == ("REPLAY_DETECTED",)
    assert not gate.finish(permit_id="permit.unknown", succeeded=False)
    assert gate.finish(permit_id=decision.permit_id, succeeded=False)
    assert (
        gate.consume(
            permit_id=decision.permit_id,
            action=case["valid_action"],
            tool_id=TOOL_ID,
            now=DECISION_TIME + timedelta(seconds=2),
        ).reason
        == "REPLAY_DETECTED"
    )
    store.close()


def test_malformed_permit_id_is_rejected_without_state_mutation():
    case, store, prepared, gate = _prepared(EvidenceRepresentation.PR)
    decision = gate.authorize(prepared, action=case["valid_action"], tool_id=TOOL_ID)
    before = store.snapshot(captured_at=DECISION_TIME + timedelta(seconds=1))

    with pytest.raises(GateError, match="permit_id"):
        gate.consume(
            permit_id="not a valid permit id",
            action=case["valid_action"],
            tool_id=TOOL_ID,
            now=DECISION_TIME + timedelta(seconds=1),
        )

    after = store.snapshot(captured_at=DECISION_TIME + timedelta(seconds=1))
    assert after.revision == before.revision
    assert after.records == before.records
    assert after.observations == before.observations
    assert decision.permit_id == before.records[0].permit_id
    store.close()


def test_stored_neutral_interaction_conflict_rolls_back_gate_reservation():
    case = build_fixture()
    handoffs = _handoffs(case)
    root_id = handoffs[0].neutral_handoff_id
    store = NeutralPermitStore(":memory:", permit_store_id=PERMIT_STORE_ID)
    conflicting = NeutralObservationRecord(
        observation_kind=ObservationKind.INTERACTION,
        observation_key=content_id(
            "NEUTRAL_INTERACTION_KEY",
            {"interaction_id": "handoff-buyer-broker-001"},
        ),
        neutral_handoff_id=content_id("OTHER_HANDOFF", {}),
    )
    assert conflicting.neutral_handoff_id != root_id
    store.reserve(
        expected_revision=0,
        observations=(conflicting,),
        leaf_neutral_handoff_id=content_id("OTHER_LEAF", {}),
        neutral_chain_id=content_id("OTHER_CHAIN", {}),
        controlling_status_id=case["active_status"]["status_id"],
        replay_scope_id=content_id("OTHER_SCOPE", {}),
        request_hash=content_id("OTHER_ACTION", {}),
        action_nonce="different-nonce",
        tool_id=TOOL_ID,
        issued_at=DECISION_TIME,
        expires_at=DECISION_TIME + timedelta(seconds=60),
    )
    _, _, prepared, gate = _prepared(
        EvidenceRepresentation.PR,
        case=case,
        handoffs=handoffs,
        permit_store=store,
    )
    decision = gate.authorize(prepared, action=case["valid_action"], tool_id=TOOL_ID)
    assert decision.reasons == ("CONFLICTING_HANDOFF",)
    snapshot = store.snapshot(captured_at=DECISION_TIME)
    assert snapshot.revision == 1
    assert len(snapshot.records) == 1
    store.close()


def test_unexpected_evaluation_error_on_trusted_input_returns_internal_error(
    monkeypatch,
):
    case, store, prepared, gate = _prepared(EvidenceRepresentation.PR)

    def fail(*args, **kwargs):
        raise RuntimeError("synthetic evaluator failure")

    monkeypatch.setattr(gate, "evaluate", fail)
    decision = gate.authorize(prepared, action=case["valid_action"], tool_id=TOOL_ID)
    assert decision.reasons == ("INTERNAL_ERROR",)
    assert store.snapshot(captured_at=DECISION_TIME).revision == 0
    store.close()


def test_sprint3_schemas_validate_exact_objects():
    for name in (
        "common-gate-input.schema.json",
        "common-gate-decision.schema.json",
        "neutral-permit-state.schema.json",
    ):
        Draft202012Validator.check_schema(_schema(name))
    case, store, prepared, gate = _prepared(EvidenceRepresentation.PR)
    decision = gate.authorize(prepared, action=case["valid_action"], tool_id=TOOL_ID)
    Draft202012Validator(_schema("common-gate-input.schema.json")).validate(
        prepared.to_dict()
    )
    Draft202012Validator(_schema("common-gate-decision.schema.json")).validate(
        decision.to_dict()
    )
    Draft202012Validator(_schema("neutral-permit-state.schema.json")).validate(
        store.snapshot(captured_at=DECISION_TIME).to_dict()
    )
    store.close()
