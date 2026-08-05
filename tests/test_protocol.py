from __future__ import annotations

import json
import sqlite3
import base64
from copy import deepcopy
from datetime import UTC, datetime
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from crosstrace_sketch.demo import FIXED_NOW, TOOL_ID, build_fixture
from crosstrace_sketch.protocol import (
    ActionGate,
    KeyRegistry,
    PermitStore,
    ProtocolError,
    action_id,
    canonical_json,
    loads_strict,
    make_action,
    make_proposal,
    make_scope,
    receipt_id,
    sign_authority_status,
    sign_receipt,
)


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def case() -> dict:
    return build_fixture()


def make_gate(case: dict, path: Path) -> tuple[ActionGate, PermitStore]:
    store = PermitStore(path)
    return ActionGate(registry=case["registry"], permit_store=store), store


def resign_leaf(case: dict, proposal: dict, *, decision: str = "ACCEPT") -> dict:
    return sign_receipt(
        proposal,
        sender_private_key=case["keys"]["broker"],
        receiver_private_key=case["keys"]["payment"],
        receiver_decision=decision,
        reason_code=None if decision == "ACCEPT" else "POLICY_REJECT",
        decided_at="2026-08-05T14:01:05Z",
    )


def authorize_valid(case: dict, gate: ActionGate):
    return gate.authorize(
        receipt_chain=[case["root_receipt"], case["leaf_receipt"]],
        current_authority_status=case["active_status"],
        action=case["valid_action"],
        now=FIXED_NOW,
        tool_id=TOOL_ID,
    )


def test_canonical_profile_is_deterministic_and_rejects_floats_and_duplicates() -> None:
    assert canonical_json({"z": 1, "a": [True, None]}) == b'{"a":[true,null],"z":1}'
    with pytest.raises(ProtocolError, match="floating-point"):
        canonical_json({"amount": 1.5})
    with pytest.raises(ProtocolError, match="duplicate JSON key"):
        loads_strict('{"same":1,"same":2}')


def test_fixture_objects_conform_to_published_json_schemas(case: dict) -> None:
    schema_and_instances = (
        ("handoff-receipt.schema.json", [case["root_receipt"], case["leaf_receipt"]]),
        ("authority-status.schema.json", [case["active_status"], case["revoked_status"]]),
        ("payment-action.schema.json", [case["valid_action"], case["over_limit_action"]]),
    )
    for filename, instances in schema_and_instances:
        schema = json.loads((REPOSITORY_ROOT / "schema" / filename).read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
        validator = Draft202012Validator(schema)
        for instance in instances:
            validator.validate(instance)


def test_valid_chain_issues_and_consumes_exactly_one_local_attempt(case: dict, tmp_path: Path) -> None:
    gate, store = make_gate(case, tmp_path / "permits.sqlite3")
    decision = authorize_valid(case, gate)
    assert decision.verdict == "ALLOW"
    assert decision.reasons == ()
    assert decision.permit_id

    first = gate.consume(
        permit_id=decision.permit_id,
        tool_id=TOOL_ID,
        action=case["valid_action"],
        now=FIXED_NOW,
    )
    assert first.allowed
    assert store.finish(permit_id=decision.permit_id, succeeded=True)
    second = gate.consume(
        permit_id=decision.permit_id,
        tool_id=TOOL_ID,
        action=case["valid_action"],
        now=FIXED_NOW,
    )
    assert second.verdict == "PAUSE"
    assert second.reason == "REPLAY_DETECTED"
    store.close()


def test_permit_is_bound_to_the_exact_action(case: dict, tmp_path: Path) -> None:
    gate, store = make_gate(case, tmp_path / "permits.sqlite3")
    decision = authorize_valid(case, gate)
    altered_action = deepcopy(case["valid_action"])
    altered_action["amount_minor"] = 900_000
    consumed = gate.consume(
        permit_id=decision.permit_id,
        tool_id=TOOL_ID,
        action=altered_action,
        now=FIXED_NOW,
    )
    assert consumed.verdict == "PAUSE"
    assert consumed.reason == "PERMIT_ACTION_MISMATCH"
    store.close()


def test_same_receipt_cannot_reserve_a_second_permit(case: dict, tmp_path: Path) -> None:
    gate, store = make_gate(case, tmp_path / "permits.sqlite3")
    assert authorize_valid(case, gate).allowed
    replay = authorize_valid(case, gate)
    assert replay.verdict == "PAUSE"
    assert replay.reasons == ("REPLAY_DETECTED",)
    store.close()


def test_resigning_same_action_under_a_new_leaf_cannot_bypass_local_replay(
    case: dict, tmp_path: Path
) -> None:
    gate, store = make_gate(case, tmp_path / "permits.sqlite3")
    assert authorize_valid(case, gate).allowed

    proposal = deepcopy(case["leaf_receipt"]["proposal"])
    proposal["interaction_id"] = "handoff-broker-payment-resigned-002"
    proposal["nonce"] = "action-intent-resigned-nonce-002"
    proposal["sender_sequence"] = 2
    resigned_leaf = resign_leaf(case, proposal)
    decision = gate.authorize(
        receipt_chain=[case["root_receipt"], resigned_leaf],
        current_authority_status=case["active_status"],
        action=case["valid_action"],
        now=FIXED_NOW,
    )
    assert decision.verdict == "PAUSE"
    assert decision.reasons == ("REPLAY_DETECTED",)
    store.close()


def test_revoked_stale_version_and_over_limit_action_all_pause(case: dict, tmp_path: Path) -> None:
    gate, store = make_gate(case, tmp_path / "permits.sqlite3")
    decision = gate.authorize(
        receipt_chain=[case["root_receipt"], case["over_limit_receipt"]],
        current_authority_status=case["revoked_status"],
        action=case["over_limit_action"],
        now=FIXED_NOW,
        tool_id=TOOL_ID,
    )
    assert decision.verdict == "PAUSE"
    assert "AUTHORITY_VERSION_STALE" in decision.reasons
    assert "AUTHORITY_REVOKED" in decision.reasons
    assert "REVOCATION_STATUS_STALE" in decision.reasons
    assert "ACTION_OUT_OF_SCOPE" in decision.reasons
    assert decision.permit_id is None
    store.close()


def test_mutating_signed_scope_invalidates_the_receipt(case: dict, tmp_path: Path) -> None:
    tampered = deepcopy(case["leaf_receipt"])
    tampered["proposal"]["scope"]["max_amount_minor"] = 999_999
    gate, store = make_gate(case, tmp_path / "permits.sqlite3")
    decision = gate.authorize(
        receipt_chain=[case["root_receipt"], tampered],
        current_authority_status=case["active_status"],
        action=case["valid_action"],
        now=FIXED_NOW,
    )
    assert decision.verdict == "PAUSE"
    assert "DIGEST_MISMATCH" in decision.reasons
    assert "SENDER_ATTESTATION_MISMATCH" in decision.reasons
    store.close()


def test_wrong_sender_signature_pauses(case: dict, tmp_path: Path) -> None:
    tampered = deepcopy(case["leaf_receipt"])
    tampered["sender_attestation"]["signature"] = "A" * 86
    gate, store = make_gate(case, tmp_path / "permits.sqlite3")
    decision = gate.authorize(
        receipt_chain=[case["root_receipt"], tampered],
        current_authority_status=case["active_status"],
        action=case["valid_action"],
        now=FIXED_NOW,
    )
    assert "SENDER_SIGNATURE_INVALID" in decision.reasons
    assert not decision.allowed
    store.close()


def test_wrong_receiver_signature_pauses(case: dict, tmp_path: Path) -> None:
    tampered = deepcopy(case["leaf_receipt"])
    tampered["receiver_attestation"]["signature"] = "A" * 86
    gate, store = make_gate(case, tmp_path / "permits.sqlite3")
    decision = gate.authorize(
        receipt_chain=[case["root_receipt"], tampered],
        current_authority_status=case["active_status"],
        action=case["valid_action"],
        now=FIXED_NOW,
    )
    assert "RECEIVER_SIGNATURE_INVALID" in decision.reasons
    assert not decision.allowed
    store.close()


def test_noncanonical_signature_encoding_cannot_create_an_alternate_receipt_id(
    case: dict, tmp_path: Path
) -> None:
    tampered = deepcopy(case["leaf_receipt"])
    original = tampered["receiver_attestation"]["signature"]
    decoded = base64.urlsafe_b64decode(original + "==")
    alternate = None
    for character in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_":
        candidate = original[:-1] + character
        if candidate != original and base64.urlsafe_b64decode(candidate + "==") == decoded:
            alternate = candidate
            break
    assert alternate is not None
    tampered["receiver_attestation"]["signature"] = alternate
    assert receipt_id(tampered) != receipt_id(case["leaf_receipt"])

    gate, store = make_gate(case, tmp_path / "permits.sqlite3")
    decision = gate.authorize(
        receipt_chain=[case["root_receipt"], tampered],
        current_authority_status=case["active_status"],
        action=case["valid_action"],
        now=FIXED_NOW,
    )
    assert not decision.allowed
    assert "RECEIVER_SIGNATURE_INVALID" in decision.reasons
    store.close()


def test_receiver_rejection_is_signed_but_never_authorizes(case: dict, tmp_path: Path) -> None:
    rejected = resign_leaf(case, deepcopy(case["leaf_receipt"]["proposal"]), decision="REJECT")
    gate, store = make_gate(case, tmp_path / "permits.sqlite3")
    decision = gate.authorize(
        receipt_chain=[case["root_receipt"], rejected],
        current_authority_status=case["active_status"],
        action=case["valid_action"],
        now=FIXED_NOW,
    )
    assert decision.reasons == ("RECEIVER_REJECTED",)
    store.close()


def test_missing_chain_pauses(case: dict, tmp_path: Path) -> None:
    gate, store = make_gate(case, tmp_path / "permits.sqlite3")
    decision = gate.authorize(
        receipt_chain=[],
        current_authority_status=case["active_status"],
        action=case["valid_action"],
        now=FIXED_NOW,
    )
    assert decision.reasons == ("MISSING_RECEIPT",)
    store.close()


def test_broken_parent_link_pauses_even_when_resigned(case: dict, tmp_path: Path) -> None:
    proposal = deepcopy(case["leaf_receipt"]["proposal"])
    proposal["previous_receipt_id"] = "sha256:" + ("0" * 64)
    broken = resign_leaf(case, proposal)
    gate, store = make_gate(case, tmp_path / "permits.sqlite3")
    decision = gate.authorize(
        receipt_chain=[case["root_receipt"], broken],
        current_authority_status=case["active_status"],
        action=case["valid_action"],
        now=FIXED_NOW,
    )
    assert "PARENT_MISSING" in decision.reasons
    store.close()


def test_party_continuity_break_pauses_even_when_all_signatures_are_valid(case: dict, tmp_path: Path) -> None:
    proposal = deepcopy(case["leaf_receipt"]["proposal"])
    proposal["sender"] = deepcopy(case["parties"]["buyer"])
    mismatched = sign_receipt(
        proposal,
        sender_private_key=case["keys"]["buyer"],
        receiver_private_key=case["keys"]["payment"],
        receiver_decision="ACCEPT",
        decided_at="2026-08-05T14:01:05Z",
    )
    gate, store = make_gate(case, tmp_path / "permits.sqlite3")
    decision = gate.authorize(
        receipt_chain=[case["root_receipt"], mismatched],
        current_authority_status=case["active_status"],
        action=case["valid_action"],
        now=FIXED_NOW,
    )
    assert "PARTY_CONTINUITY_BROKEN" in decision.reasons
    store.close()


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("max_amount_minor", 1_000_001),
        ("resources", ["urn:crosstrace:payee:attacker"]),
        ("not_after", "2026-08-05T16:30:00Z"),
        ("redelegations_remaining", 1),
    ],
)
def test_scope_expansion_pauses(case: dict, tmp_path: Path, field: str, value) -> None:
    proposal = deepcopy(case["leaf_receipt"]["proposal"])
    proposal["scope"][field] = value
    expanded = resign_leaf(case, proposal)
    gate, store = make_gate(case, tmp_path / f"scope-{field}.sqlite3")
    decision = gate.authorize(
        receipt_chain=[case["root_receipt"], expanded],
        current_authority_status=case["active_status"],
        action=case["valid_action"],
        now=FIXED_NOW,
    )
    assert "SCOPE_EXPANSION" in decision.reasons
    store.close()


def test_action_must_match_the_leaf_request_hash(case: dict, tmp_path: Path) -> None:
    altered_action = deepcopy(case["valid_action"])
    altered_action["action_nonce"] = "different-payment-attempt"
    gate, store = make_gate(case, tmp_path / "permits.sqlite3")
    decision = gate.authorize(
        receipt_chain=[case["root_receipt"], case["leaf_receipt"]],
        current_authority_status=case["active_status"],
        action=altered_action,
        now=FIXED_NOW,
    )
    assert decision.reasons == ("REQUEST_HASH_MISMATCH",)
    store.close()


def test_expired_scope_and_status_pause(case: dict, tmp_path: Path) -> None:
    gate, store = make_gate(case, tmp_path / "permits.sqlite3")
    later = datetime(2026, 8, 5, 16, 1, 0, tzinfo=UTC)
    decision = gate.authorize(
        receipt_chain=[case["root_receipt"], case["leaf_receipt"]],
        current_authority_status=case["active_status"],
        action=case["valid_action"],
        now=later,
    )
    assert "STATUS_STALE" in decision.reasons
    assert "EXPIRED" in decision.reasons
    store.close()


def test_invalid_status_signature_pauses(case: dict, tmp_path: Path) -> None:
    status = deepcopy(case["active_status"])
    status["attestation"]["signature"] = "A" * 86
    gate, store = make_gate(case, tmp_path / "permits.sqlite3")
    decision = gate.authorize(
        receipt_chain=[case["root_receipt"], case["leaf_receipt"]],
        current_authority_status=status,
        action=case["valid_action"],
        now=FIXED_NOW,
    )
    assert "STATUS_SIGNATURE_INVALID" in decision.reasons
    store.close()


def test_receipt_signing_key_is_not_implicitly_a_status_issuer(case: dict, tmp_path: Path) -> None:
    forged_role_status = sign_authority_status(
        issuer_principal_id="buyer.example",
        issuer_key_id=case["parties"]["buyer"]["key_id"],
        subject_principal_id="broker.example",
        subject_key_id=case["parties"]["broker"]["key_id"],
        authority_version=7,
        state="ACTIVE",
        issued_at="2026-08-05T13:55:00Z",
        fresh_until="2026-08-05T14:10:00Z",
        issuer_private_key=case["keys"]["buyer"],
    )
    leaf_proposal = deepcopy(case["leaf_receipt"]["proposal"])
    leaf_proposal["authority"]["revocation_status_id"] = forged_role_status["status_id"]
    leaf = resign_leaf(case, leaf_proposal)
    root_proposal = deepcopy(case["root_receipt"]["proposal"])
    root_proposal["authority"]["revocation_status_id"] = forged_role_status["status_id"]
    root = sign_receipt(
        root_proposal,
        sender_private_key=case["keys"]["buyer"],
        receiver_private_key=case["keys"]["broker"],
        receiver_decision="ACCEPT",
        decided_at="2026-08-05T14:00:05Z",
    )
    leaf_proposal["previous_receipt_id"] = receipt_id(root)
    leaf = resign_leaf(case, leaf_proposal)

    gate, store = make_gate(case, tmp_path / "permits.sqlite3")
    decision = gate.authorize(
        receipt_chain=[root, leaf],
        current_authority_status=forged_role_status,
        action=case["valid_action"],
        now=FIXED_NOW,
    )
    assert not decision.allowed
    assert "UNTRUSTED_STATUS_KEY" in decision.reasons
    store.close()


def test_receipt_cannot_cite_authority_status_issued_after_its_proposal(
    case: dict, tmp_path: Path
) -> None:
    late_status = sign_authority_status(
        issuer_principal_id="buyer.example",
        issuer_key_id="buyer-root-key-1",
        subject_principal_id="broker.example",
        subject_key_id=case["parties"]["broker"]["key_id"],
        authority_version=7,
        state="ACTIVE",
        issued_at="2026-08-05T14:04:00Z",
        fresh_until="2026-08-05T14:10:00Z",
        issuer_private_key=case["keys"]["buyer_root"],
    )
    root_proposal = deepcopy(case["root_receipt"]["proposal"])
    root_proposal["authority"]["revocation_status_id"] = late_status["status_id"]
    root = sign_receipt(
        root_proposal,
        sender_private_key=case["keys"]["buyer"],
        receiver_private_key=case["keys"]["broker"],
        receiver_decision="ACCEPT",
        decided_at="2026-08-05T14:00:05Z",
    )
    leaf_proposal = deepcopy(case["leaf_receipt"]["proposal"])
    leaf_proposal["authority"]["revocation_status_id"] = late_status["status_id"]
    leaf_proposal["previous_receipt_id"] = receipt_id(root)
    leaf = resign_leaf(case, leaf_proposal)

    gate, store = make_gate(case, tmp_path / "permits.sqlite3")
    decision = gate.authorize(
        receipt_chain=[root, leaf],
        current_authority_status=late_status,
        action=case["valid_action"],
        now=FIXED_NOW,
    )
    assert not decision.allowed
    assert "STATUS_CAUSAL_TIME_INVALID" in decision.reasons
    store.close()


@pytest.mark.parametrize(
    "decided_at",
    ["2026-08-05T13:59:59Z", "2099-01-01T00:00:00Z"],
)
def test_receiver_decision_time_must_follow_proposal_and_not_be_in_the_future(
    case: dict, tmp_path: Path, decided_at: str
) -> None:
    leaf = sign_receipt(
        case["leaf_receipt"]["proposal"],
        sender_private_key=case["keys"]["broker"],
        receiver_private_key=case["keys"]["payment"],
        receiver_decision="ACCEPT",
        decided_at=decided_at,
    )
    gate, store = make_gate(case, tmp_path / "permits.sqlite3")
    decision = gate.authorize(
        receipt_chain=[case["root_receipt"], leaf],
        current_authority_status=case["active_status"],
        action=case["valid_action"],
        now=FIXED_NOW,
    )
    assert not decision.allowed
    assert "CAUSAL_TIME_INVALID" in decision.reasons
    store.close()


def test_conflicting_signed_receipt_is_detected_when_both_views_reach_one_store(
    case: dict, tmp_path: Path
) -> None:
    gate, store = make_gate(case, tmp_path / "permits.sqlite3")
    assert authorize_valid(case, gate).allowed

    root_proposal = deepcopy(case["root_receipt"]["proposal"])
    root_proposal["nonce"] = "conflicting-root-nonce"
    conflicting_root = sign_receipt(
        root_proposal,
        sender_private_key=case["keys"]["buyer"],
        receiver_private_key=case["keys"]["broker"],
        receiver_decision="ACCEPT",
        decided_at="2026-08-05T14:00:05Z",
    )
    leaf_proposal = deepcopy(case["leaf_receipt"]["proposal"])
    leaf_proposal["previous_receipt_id"] = receipt_id(conflicting_root)
    conflicting_leaf = resign_leaf(case, leaf_proposal)
    decision = gate.authorize(
        receipt_chain=[conflicting_root, conflicting_leaf],
        current_authority_status=case["active_status"],
        action=case["valid_action"],
        now=FIXED_NOW,
    )
    assert decision.reasons == ("CONFLICTING_RECEIPT",)
    store.close()


def test_two_partial_views_can_each_accept_a_valid_fork(case: dict, tmp_path: Path) -> None:
    """Executable limitation: isolated stores cannot detect a global fork."""

    second_action = make_action(
        action_nonce="payment-attempt-fork-002",
        operation="payment",
        resource="urn:crosstrace:payee:supplier-17",
        currency="USD",
        amount_minor=900_000,
    )
    second_proposal = make_proposal(
        interaction_id="handoff-broker-payment-fork-002",
        event_type="action_intent",
        created_at="2026-08-05T14:01:00Z",
        nonce="action-intent-fork-nonce-002",
        sender=case["parties"]["broker"],
        receiver=case["parties"]["payment"],
        sender_sequence=2,
        previous_receipt_id=receipt_id(case["root_receipt"]),
        scope=make_scope(
            operations=["payment"],
            resources=["urn:crosstrace:payee:supplier-17"],
            currency="USD",
            max_amount_minor=900_000,
            not_before="2026-08-05T14:00:00Z",
            not_after="2026-08-05T15:30:00Z",
            redelegations_remaining=0,
        ),
        authority=case["authority"],
        request_hash=action_id(second_action),
    )
    second_leaf = resign_leaf(case, second_proposal)

    gate_a, store_a = make_gate(case, tmp_path / "view-a.sqlite3")
    gate_b, store_b = make_gate(case, tmp_path / "view-b.sqlite3")
    first = authorize_valid(case, gate_a)
    second = gate_b.authorize(
        receipt_chain=[case["root_receipt"], second_leaf],
        current_authority_status=case["active_status"],
        action=second_action,
        now=FIXED_NOW,
    )
    assert first.allowed and second.allowed
    store_a.close()
    store_b.close()


def test_state_failure_never_falls_back_to_allow(case: dict) -> None:
    class BrokenStore:
        def reserve(self, **_kwargs):
            raise sqlite3.OperationalError("synthetic state failure")

    gate = ActionGate(registry=case["registry"], permit_store=BrokenStore())
    decision = authorize_valid(case, gate)
    assert decision.verdict == "PAUSE"
    assert decision.reasons == ("STATE_UNAVAILABLE",)


def test_unknown_signer_never_falls_back_to_allow(case: dict, tmp_path: Path) -> None:
    empty_registry = KeyRegistry()
    store = PermitStore(tmp_path / "permits.sqlite3")
    gate = ActionGate(registry=empty_registry, permit_store=store)
    decision = gate.authorize(
        receipt_chain=[case["root_receipt"], case["leaf_receipt"]],
        current_authority_status=case["active_status"],
        action=case["valid_action"],
        now=FIXED_NOW,
    )
    assert not decision.allowed
    assert "UNTRUSTED_SENDER_KEY" in decision.reasons
    assert "UNTRUSTED_RECEIVER_KEY" in decision.reasons
    store.close()
