"""Development-only tests for the Sprint 1 evidence-delivery boundary."""

from __future__ import annotations

import json
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, ValidationError

from preaward.crosstrace_sprint1.delivery import (
    AuditObservation,
    DeliveryError,
    DeliveryPolicy,
    DeliverySchedule,
    Disposition,
    EvidenceMessage,
    LocalObservation,
    PermitLifecycle,
    PermitObservationRecord,
    PermitStateRecord,
    PermitStateSnapshot,
    PartitionWindow,
    PayloadKind,
    TransmissionOverride,
    compile_schedule,
    empty_permit_state,
    make_evidence_message,
    project_audit,
    project_local,
)


T0 = datetime(2026, 8, 7, 9, 0, 0, tzinfo=UTC)
SEED = b"crosstrace-sprint1-development-seed"


def _message(
    record_id: str,
    *,
    origin: str = "store.sender",
    destination: str = "store.gate",
    sent_at: datetime = T0,
    kind: PayloadKind = PayloadKind.RECEIPT,
    extra: dict | None = None,
    slot: str | None = None,
):
    payload = {"record_id": record_id}
    if extra:
        payload.update(extra)
    return make_evidence_message(
        delivery_slot_id=slot or f"slot.{origin}.{destination}.{record_id}",
        origin_store_id=origin,
        destination_store_id=destination,
        sent_at=sent_at,
        payload_kind=kind,
        payload=payload,
    )


def _local_view(
    schedule,
    *,
    verifier_id: str,
    evidence_store_id: str,
    decision_time: datetime,
):
    return project_local(
        schedule,
        verifier_id=verifier_id,
        evidence_store_id=evidence_store_id,
        permit_store_id=f"{verifier_id}.permits",
        decision_time=decision_time,
        permit_state=empty_permit_state(
            permit_store_id=f"{verifier_id}.permits",
            captured_at=decision_time,
        ),
    )


def _schema(name: str) -> dict:
    root = Path(__file__).resolve().parents[1]
    return json.loads((root / "schema" / name).read_text(encoding="utf-8"))


def test_message_is_content_bound_immutable_and_schema_valid() -> None:
    payload = {"record_id": "receipt-1", "nested": {"amount_minor": 100}}
    message = make_evidence_message(
        delivery_slot_id="slot.receipt-1.sender-gate",
        origin_store_id="store.sender",
        destination_store_id="store.gate",
        sent_at=T0,
        payload_kind=PayloadKind.RECEIPT,
        payload=payload,
    )
    payload["nested"]["amount_minor"] = 999

    assert message.payload["nested"]["amount_minor"] == 100
    assert message.payload_bytes == b'{"nested":{"amount_minor":100},"record_id":"receipt-1"}'
    Draft202012Validator(_schema("evidence-message.schema.json")).validate(message.to_dict())
    assert EvidenceMessage.from_dict(message.to_dict()) == message


@pytest.mark.parametrize("field", ["payload_hash", "message_id", "payload_size_bytes"])
def test_message_decoder_rejects_derived_field_tampering(field: str) -> None:
    serialised = _message("tamper-check").to_dict()
    if field == "payload_size_bytes":
        serialised[field] += 1
    else:
        serialised[field] = "sha256:" + "0" * 64

    with pytest.raises(DeliveryError, match="does not match"):
        EvidenceMessage.from_dict(serialised)


def test_message_decoder_rejects_noncanonical_base64url_and_extra_fields() -> None:
    serialised = _message("strict-decoder").to_dict()
    serialised["payload_b64"] += "="
    with pytest.raises(DeliveryError, match="unpadded base64url"):
        EvidenceMessage.from_dict(serialised)

    serialised = _message("strict-fields").to_dict()
    serialised["unexpected"] = True
    with pytest.raises(DeliveryError, match="fields mismatch"):
        EvidenceMessage.from_dict(serialised)


def test_raw_message_decoder_requires_canonical_unique_key_json() -> None:
    message = _message("raw-decoder")
    assert EvidenceMessage.from_bytes(message.canonical_bytes) == message

    noncanonical = json.dumps(message.to_dict()).encode("ascii")
    with pytest.raises(DeliveryError, match="canonical JSON encoding"):
        EvidenceMessage.from_bytes(noncanonical)

    duplicate_key = message.canonical_bytes.replace(
        b"{",
        b'{"delivery_slot_id":"slot.duplicate",',
        1,
    )
    with pytest.raises(DeliveryError, match="canonical-profile JSON"):
        EvidenceMessage.from_bytes(duplicate_key)


def test_payload_profile_errors_are_reported_as_delivery_errors() -> None:
    with pytest.raises(DeliveryError, match="canonical-profile JSON values"):
        _message("float-payload", extra={"unsupported": 1.5})


def test_independently_retained_copies_share_payload_identity_not_message_identity() -> None:
    sender_copy = _message("same-receipt", origin="store.sender")
    receiver_copy = _message("same-receipt", origin="store.receiver")

    assert sender_copy.payload_hash == receiver_copy.payload_hash
    assert sender_copy.payload_bytes == receiver_copy.payload_bytes
    assert sender_copy.message_id != receiver_copy.message_id

    schedule = compile_schedule(
        (sender_copy, receiver_copy),
        policy=DeliveryPolicy(),
        seed=SEED,
    )
    view = _local_view(
        schedule,
        verifier_id="verifier.gate",
        evidence_store_id="store.gate",
        decision_time=T0,
    )
    assert len(view.delivered_messages) == 2
    assert len(view.unique_evidence()) == 2


@pytest.mark.parametrize(
    "reserved",
    [
        "oracle",
        "oracle_graph",
        "oracleLabel",
        "ground_truth",
        "expected-fault",
        "scenario_label",
    ],
)
def test_evaluator_only_fields_cannot_enter_evidence(reserved: str) -> None:
    with pytest.raises(DeliveryError, match="evaluator-only"):
        _message("bad", extra={"nested": {reserved: "secret"}})


def test_schedule_is_reproducible_and_input_order_independent() -> None:
    messages = tuple(_message(f"record-{index}") for index in range(8))
    policy = DeliveryPolicy(
        min_delay_seconds=1,
        max_delay_seconds=20,
        loss_rate_ppm=250_000,
        duplicate_rate_ppm=500_000,
    )
    forward = compile_schedule(messages, policy=policy, seed=SEED)
    reverse = compile_schedule(tuple(reversed(messages)), policy=policy, seed=SEED)

    assert forward.canonical_bytes == reverse.canonical_bytes
    assert forward.content_hash == reverse.content_hash
    Draft202012Validator(_schema("delivery-schedule.schema.json")).validate(forward.to_dict())
    assert DeliverySchedule.from_dict(forward.to_dict()) == forward
    assert DeliverySchedule.from_bytes(forward.canonical_bytes) == forward

    reordered = forward.to_dict()
    reordered["messages"] = list(reversed(reordered["messages"]))
    reordered_bytes = json.dumps(
        reordered,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")
    with pytest.raises(DeliveryError, match="object order is not canonical"):
        DeliverySchedule.from_bytes(reordered_bytes)


def test_schedule_snapshots_one_shot_iterables_before_validation() -> None:
    message = _message("one-shot-input")
    schedule = compile_schedule(
        (item for item in (message,)),
        policy=DeliveryPolicy(),
        seed=SEED,
        overrides=(
            item
            for item in (
                TransmissionOverride(
                    message.delivery_slot_id,
                    0,
                    Disposition.DELIVER,
                    3,
                ),
            )
        ),
    )

    assert schedule.messages == (message,)
    assert len(schedule.transmissions) == 1
    assert schedule.transmissions[0].delivered_at == T0 + timedelta(seconds=3)


def test_schedule_schema_and_decoder_reject_inconsistent_transport_outcomes() -> None:
    schedule = compile_schedule(
        (_message("serialized-schedule"),),
        policy=DeliveryPolicy(),
        seed=SEED,
    )
    schema = Draft202012Validator(_schema("delivery-schedule.schema.json"))

    inconsistent_disposition = json.loads(json.dumps(schedule.to_dict()))
    inconsistent_disposition["transmissions"][0]["disposition"] = "LOST"
    with pytest.raises(ValidationError):
        schema.validate(inconsistent_disposition)

    incomplete = json.loads(json.dumps(schedule.to_dict()))
    incomplete["transmissions"] = []
    with pytest.raises(DeliveryError, match="compiled schedule inputs"):
        DeliverySchedule.from_dict(incomplete)


def test_delivery_draws_are_representation_invariant_for_one_neutral_slot() -> None:
    receipt = _message(
        "neutral-receipt",
        kind=PayloadKind.RECEIPT,
        slot="slot.neutral-handoff.sender-gate",
    )
    signed_log = _message(
        "neutral-signed-log",
        kind=PayloadKind.SIGNED_ENDPOINT_RECORD,
        slot="slot.neutral-handoff.sender-gate",
    )
    policy = DeliveryPolicy(
        min_delay_seconds=0,
        max_delay_seconds=90,
        loss_rate_ppm=400_000,
        duplicate_rate_ppm=600_000,
    )
    receipt_schedule = compile_schedule((receipt,), policy=policy, seed=SEED)
    log_schedule = compile_schedule((signed_log,), policy=policy, seed=SEED)

    def neutral_outcomes(schedule):
        return [
            (
                item.transmission_id,
                item.delivery_slot_id,
                item.copy_index,
                item.disposition,
                item.delivered_at,
                item.fault_tags,
            )
            for item in schedule.transmissions
        ]

    assert receipt.message_id != signed_log.message_id
    assert neutral_outcomes(receipt_schedule) == neutral_outcomes(log_schedule)


def test_projection_hides_future_loss_withholding_other_stores_and_schedule_state() -> None:
    delivered = _message("delivered")
    duplicated = _message("duplicated")
    future = _message("future")
    lost = _message("lost")
    withheld = _message("withheld")
    other = _message("other", destination="store.other")
    policy = DeliveryPolicy(withheld_delivery_slot_ids=(withheld.delivery_slot_id,))
    overrides = (
        TransmissionOverride(delivered.delivery_slot_id, 0, Disposition.DELIVER, 0),
        TransmissionOverride(duplicated.delivery_slot_id, 0, Disposition.DELIVER, 0),
        TransmissionOverride(duplicated.delivery_slot_id, 1, Disposition.DELIVER, 2),
        TransmissionOverride(future.delivery_slot_id, 0, Disposition.DELIVER, 20),
        TransmissionOverride(lost.delivery_slot_id, 0, Disposition.LOST),
        TransmissionOverride(other.delivery_slot_id, 0, Disposition.DELIVER, 0),
    )
    schedule = compile_schedule(
        (delivered, duplicated, future, lost, withheld, other),
        policy=policy,
        seed=SEED,
        overrides=overrides,
    )
    view = _local_view(
        schedule,
        verifier_id="verifier.gate",
        evidence_store_id="store.gate",
        decision_time=T0 + timedelta(seconds=10),
    )

    visible_ids = [item.message_id for item in view.delivered_messages]
    assert delivered.message_id in visible_ids
    assert visible_ids.count(duplicated.message_id) == 2
    assert future.message_id not in visible_ids
    assert lost.message_id not in visible_ids
    assert withheld.message_id not in visible_ids
    assert other.message_id not in visible_ids
    assert len(view.unique_evidence()) == 2

    serialised = view.canonical_bytes.decode("ascii").casefold()
    for forbidden in (
        "seed",
        "partition",
        "disposition",
        "fault_tag",
        "scenario",
        "oracle",
        "missing_message",
        "future",
    ):
        assert forbidden not in serialised
    assert lost.message_id not in serialised
    assert withheld.message_id not in serialised


def test_permanent_withholding_cannot_be_defeated_by_a_delivery_override() -> None:
    message = _message("permanently-withheld")
    schedule = compile_schedule(
        (message,),
        policy=DeliveryPolicy(
            withheld_delivery_slot_ids=(message.delivery_slot_id,),
        ),
        seed=SEED,
        overrides=(
            TransmissionOverride(message.delivery_slot_id, 0, Disposition.DELIVER, 0),
        ),
    )
    assert schedule.transmissions[0].disposition is Disposition.WITHHELD
    assert "override_suppressed" in schedule.transmissions[0].fault_tags
    view = _local_view(
        schedule,
        verifier_id="verifier.gate",
        evidence_store_id="store.gate",
        decision_time=T0 + timedelta(days=1),
    )
    assert view.delivered_messages == ()


def test_transport_profile_limits_and_tuple_fields_fail_closed() -> None:
    message = _message("profile-limits")
    with pytest.raises(DeliveryError, match="between 0 and 31536000"):
        DeliveryPolicy(max_delay_seconds=31_536_001)
    with pytest.raises(DeliveryError, match="between 0 and 31536000"):
        TransmissionOverride(
            message.delivery_slot_id,
            0,
            Disposition.DELIVER,
            31_536_001,
        )

    schedule = compile_schedule((message,), policy=DeliveryPolicy(), seed=SEED)
    with pytest.raises(DeliveryError, match="fault_tags must be a tuple"):
        replace(schedule.transmissions[0], fault_tags="loss")

    last_second = datetime(9999, 12, 31, 23, 59, 59, tzinfo=UTC)
    late_message = _message("datetime-overflow", sent_at=last_second)
    with pytest.raises(DeliveryError, match="delivery time exceeds"):
        compile_schedule(
            (late_message,),
            policy=DeliveryPolicy(min_delay_seconds=1, max_delay_seconds=1),
            seed=SEED,
        )


def test_duplicate_transmissions_have_independent_fates() -> None:
    message = _message("duplicate-independent")
    schedule = compile_schedule(
        (message,),
        policy=DeliveryPolicy(duplicate_rate_ppm=1_000_000),
        seed=SEED,
        overrides=(
            TransmissionOverride(message.delivery_slot_id, 0, Disposition.LOST),
            TransmissionOverride(message.delivery_slot_id, 1, Disposition.DELIVER, 3),
        ),
    )
    assert {item.copy_index: item.disposition for item in schedule.transmissions} == {
        0: Disposition.LOST,
        1: Disposition.DELIVER,
    }
    view = _local_view(
        schedule,
        verifier_id="verifier.gate",
        evidence_store_id="store.gate",
        decision_time=T0 + timedelta(seconds=3),
    )
    assert [(item.copy_index, item.delivered_at) for item in view.delivered_messages] == [
        (1, T0 + timedelta(seconds=3))
    ]


def test_delivery_order_follows_arrival_not_send_order() -> None:
    first_sent = _message("first", sent_at=T0)
    second_sent = _message("second", sent_at=T0 + timedelta(seconds=1))
    schedule = compile_schedule(
        (first_sent, second_sent),
        policy=DeliveryPolicy(),
        seed=SEED,
        overrides=(
            TransmissionOverride(first_sent.delivery_slot_id, 0, Disposition.DELIVER, 10),
            TransmissionOverride(second_sent.delivery_slot_id, 0, Disposition.DELIVER, 0),
        ),
    )
    view = _local_view(
        schedule,
        verifier_id="verifier.gate",
        evidence_store_id="store.gate",
        decision_time=T0 + timedelta(seconds=10),
    )
    assert [item.payload["record_id"] for item in view.delivered_messages] == [
        "second",
        "first",
    ]


def test_directional_partition_buffers_until_exact_healing_time() -> None:
    outbound = _message("a-to-b", origin="store.a", destination="store.b")
    reverse = _message("b-to-a", origin="store.b", destination="store.a")
    partition = PartitionWindow(
        partition_id="partition-a-b",
        origin_store_id="store.a",
        destination_store_id="store.b",
        starts_at=T0,
        ends_at=T0 + timedelta(seconds=10),
    )
    schedule = compile_schedule(
        (outbound, reverse),
        policy=DeliveryPolicy(partitions=(partition,)),
        seed=SEED,
    )

    before = _local_view(
        schedule,
        verifier_id="verifier.b",
        evidence_store_id="store.b",
        decision_time=T0 + timedelta(seconds=9),
    )
    at_healing = _local_view(
        schedule,
        verifier_id="verifier.b",
        evidence_store_id="store.b",
        decision_time=T0 + timedelta(seconds=10),
    )
    reverse_view = _local_view(
        schedule,
        verifier_id="verifier.a",
        evidence_store_id="store.a",
        decision_time=T0,
    )

    assert before.delivered_messages == ()
    assert [item.payload["record_id"] for item in at_healing.delivered_messages] == ["a-to-b"]
    assert [item.payload["record_id"] for item in reverse_view.delivered_messages] == ["b-to-a"]


def test_late_revocation_creates_a_new_view_without_mutating_the_old_one() -> None:
    active_v7 = _message(
        "status-v7",
        kind=PayloadKind.AUTHORITY_STATUS,
        extra={"authority_version": 7, "state": "ACTIVE"},
    )
    revoked_v8 = _message(
        "status-v8",
        kind=PayloadKind.AUTHORITY_STATUS,
        extra={"authority_version": 8, "state": "REVOKED"},
    )
    schedule = compile_schedule(
        (active_v7, revoked_v8),
        policy=DeliveryPolicy(),
        seed=SEED,
        overrides=(
            TransmissionOverride(active_v7.delivery_slot_id, 0, Disposition.DELIVER, 0),
            TransmissionOverride(revoked_v8.delivery_slot_id, 0, Disposition.DELIVER, 20),
        ),
    )
    early = _local_view(
        schedule,
        verifier_id="verifier.gate",
        evidence_store_id="store.gate",
        decision_time=T0 + timedelta(seconds=10),
    )
    early_bytes = early.canonical_bytes
    late = _local_view(
        schedule,
        verifier_id="verifier.gate",
        evidence_store_id="store.gate",
        decision_time=T0 + timedelta(seconds=20),
    )

    assert [item.payload["authority_version"] for item in early.delivered_messages] == [7]
    assert [item.payload["authority_version"] for item in late.delivered_messages] == [7, 8]
    assert early.canonical_bytes == early_bytes
    assert {item.transmission_id for item in early.delivered_messages} < {
        item.transmission_id for item in late.delivered_messages
    }


def test_isolated_local_views_and_audit_inbox_are_not_a_global_union() -> None:
    only_a = _message("only-a", destination="store.gate-a")
    only_b = _message("only-b", destination="store.gate-b")
    audit_at_cutoff = _message("audit-now", destination="store.audit")
    audit_late = _message("audit-late", destination="store.audit")
    holder_only = _message("holder-only", destination="store.holder")
    schedule = compile_schedule(
        (only_a, only_b, audit_at_cutoff, audit_late, holder_only),
        policy=DeliveryPolicy(),
        seed=SEED,
        overrides=(
            TransmissionOverride(only_a.delivery_slot_id, 0, Disposition.DELIVER, 0),
            TransmissionOverride(only_b.delivery_slot_id, 0, Disposition.DELIVER, 0),
            TransmissionOverride(audit_at_cutoff.delivery_slot_id, 0, Disposition.DELIVER, 10),
            TransmissionOverride(audit_late.delivery_slot_id, 0, Disposition.DELIVER, 11),
            TransmissionOverride(holder_only.delivery_slot_id, 0, Disposition.DELIVER, 0),
        ),
    )
    view_a = _local_view(
        schedule,
        verifier_id="verifier.a",
        evidence_store_id="store.gate-a",
        decision_time=T0,
    )
    view_b = _local_view(
        schedule,
        verifier_id="verifier.b",
        evidence_store_id="store.gate-b",
        decision_time=T0,
    )
    audit = project_audit(
        schedule,
        audit_store_id="store.audit",
        episode_end=T0,
        delta_audit=timedelta(seconds=10),
    )

    assert [item.payload["record_id"] for item in view_a.delivered_messages] == ["only-a"]
    assert [item.payload["record_id"] for item in view_b.delivered_messages] == ["only-b"]
    assert [item.payload["record_id"] for item in audit.delivered_messages] == ["audit-now"]
    assert holder_only.message_id not in audit.canonical_bytes.decode("ascii")

    observation_schema = Draft202012Validator(_schema("delivery-observation.schema.json"))
    observation_schema.validate(view_a.to_dict())
    observation_schema.validate(audit.to_dict())
    assert LocalObservation.from_dict(view_a.to_dict()) == view_a
    assert AuditObservation.from_dict(audit.to_dict()) == audit
    assert LocalObservation.from_bytes(view_a.canonical_bytes) == view_a
    assert AuditObservation.from_bytes(audit.canonical_bytes) == audit

    tampered = json.loads(json.dumps(view_a.to_dict()))
    tampered["delivered_messages"][0]["payload_size_bytes"] += 1
    with pytest.raises(DeliveryError, match="payload_size_bytes does not match"):
        LocalObservation.from_dict(tampered)


def test_local_observation_binds_complete_permit_store_snapshot() -> None:
    hash_one = "sha256:" + "1" * 64
    hash_two = "sha256:" + "2" * 64
    hash_three = "sha256:" + "3" * 64
    permit_state = PermitStateSnapshot(
        permit_store_id="store.permits.gate",
        captured_at=T0,
        records=(
            PermitStateRecord(
                permit_id="permit.one",
                leaf_receipt_id=hash_one,
                replay_scope=hash_two,
                request_hash=hash_three,
                action_nonce="action.one",
                tool_id="tool.payment",
                state=PermitLifecycle.ATTEMPTED,
                issued_at=T0 - timedelta(seconds=1),
                expires_at=T0 + timedelta(seconds=30),
            ),
        ),
        observations=(
            PermitObservationRecord(
                observation_kind="interaction",
                observation_key="interaction.one",
                receipt_id=hash_one,
            ),
        ),
    )
    schedule = compile_schedule((), policy=DeliveryPolicy(), seed=SEED)
    view = project_local(
        schedule,
        verifier_id="verifier.gate",
        evidence_store_id="store.gate",
        permit_store_id="store.permits.gate",
        decision_time=T0,
        permit_state=permit_state,
    )
    assert LocalObservation.from_dict(view.to_dict()) == view

    with pytest.raises(DeliveryError, match="does not match permit_store_id"):
        replace(view, permit_store_id="store.permits.other")


def test_invalid_schedule_inputs_fail_closed() -> None:
    message = _message("one")
    with pytest.raises(DeliveryError, match="unique"):
        compile_schedule((message, message), policy=DeliveryPolicy(), seed=SEED)
    with pytest.raises(DeliveryError, match="unknown delivery slot"):
        compile_schedule(
            (message,),
            policy=DeliveryPolicy(withheld_delivery_slot_ids=("slot.unknown",)),
            seed=SEED,
        )
    with pytest.raises(DeliveryError, match="whole-second"):
        _local_view(
            compile_schedule((message,), policy=DeliveryPolicy(), seed=SEED),
            verifier_id="verifier.gate",
            evidence_store_id="store.gate",
            decision_time=T0 + timedelta(microseconds=1),
        )

    valid = compile_schedule((message,), policy=DeliveryPolicy(), seed=SEED)
    with pytest.raises(DeliveryError, match="compiled schedule inputs"):
        DeliverySchedule(
            seed=valid.seed,
            policy=valid.policy,
            messages=valid.messages,
            overrides=valid.overrides,
            transmissions=(),
        )


def test_delivery_schemas_are_valid_draft_2020_12() -> None:
    for name in (
        "evidence-message.schema.json",
        "delivery-observation.schema.json",
        "delivery-schedule.schema.json",
    ):
        Draft202012Validator.check_schema(_schema(name))
