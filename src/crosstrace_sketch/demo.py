"""Deterministic, offline buyer -> broker -> payment worked example."""

from __future__ import annotations

import json
import tempfile
from copy import deepcopy
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .protocol import (
    ActionGate,
    KeyRegistry,
    PermitStore,
    action_id,
    content_id,
    make_action,
    make_proposal,
    make_scope,
    receipt_id,
    sign_authority_status,
    sign_receipt,
)


FIXED_NOW = datetime(2026, 8, 5, 14, 5, 0, tzinfo=UTC)
TOOL_ID = "simulated-payment-adapter"


def _fixture_private_key(byte_value: int) -> Ed25519PrivateKey:
    # Public, deterministic test fixture. Never use these keys outside this demo.
    return Ed25519PrivateKey.from_private_bytes(bytes([byte_value]) * 32)


def build_fixture() -> dict[str, Any]:
    """Build signed synthetic evidence used by the demo and behaviour tests."""

    buyer_root_key = _fixture_private_key(0x11)
    buyer_agent_key = _fixture_private_key(0x22)
    broker_agent_key = _fixture_private_key(0x33)
    payment_agent_key = _fixture_private_key(0x44)

    parties = {
        "buyer": {
            "principal_id": "buyer.example",
            "agent_id": "buyer-agent-1",
            "key_id": "buyer-agent-key-1",
        },
        "broker": {
            "principal_id": "broker.example",
            "agent_id": "broker-agent-1",
            "key_id": "broker-agent-key-1",
        },
        "payment": {
            "principal_id": "payment.example",
            "agent_id": "payment-agent-1",
            "key_id": "payment-agent-key-1",
        },
    }

    registry = KeyRegistry()
    registry.add(
        principal_id="buyer.example",
        key_id="buyer-root-key-1",
        public_key=buyer_root_key.public_key(),
        roles={"status"},
    )
    registry.add(
        principal_id="buyer.example",
        key_id=parties["buyer"]["key_id"],
        public_key=buyer_agent_key.public_key(),
        roles={"receipt"},
    )
    registry.add(
        principal_id="broker.example",
        key_id=parties["broker"]["key_id"],
        public_key=broker_agent_key.public_key(),
        roles={"receipt"},
    )
    registry.add(
        principal_id="payment.example",
        key_id=parties["payment"]["key_id"],
        public_key=payment_agent_key.public_key(),
        roles={"receipt"},
    )

    active_status = sign_authority_status(
        issuer_principal_id="buyer.example",
        issuer_key_id="buyer-root-key-1",
        subject_principal_id="broker.example",
        subject_key_id=parties["broker"]["key_id"],
        authority_version=7,
        state="ACTIVE",
        issued_at="2026-08-05T13:55:00Z",
        fresh_until="2026-08-05T14:10:00Z",
        issuer_private_key=buyer_root_key,
    )
    authority = {
        "issuer_principal_id": "buyer.example",
        "subject_principal_id": "broker.example",
        "subject_key_id": parties["broker"]["key_id"],
        "authority_version": 7,
        "revocation_status_id": active_status["status_id"],
    }
    root_scope = make_scope(
        operations=["order", "payment"],
        resources=["urn:crosstrace:payee:supplier-17"],
        currency="USD",
        max_amount_minor=1_000_000,
        not_before="2026-08-05T14:00:00Z",
        not_after="2026-08-05T16:00:00Z",
        redelegations_remaining=1,
    )
    delegation_request = {
        "purpose": "delegate-payment-authority",
        "scope": root_scope,
        "subject_key_id": parties["broker"]["key_id"],
    }
    root_proposal = make_proposal(
        interaction_id="handoff-buyer-broker-001",
        event_type="delegation",
        created_at="2026-08-05T14:00:00Z",
        nonce="delegation-nonce-001",
        sender=parties["buyer"],
        receiver=parties["broker"],
        sender_sequence=1,
        previous_receipt_id=None,
        scope=root_scope,
        authority=authority,
        request_hash=content_id("DELEGATION_REQUEST", delegation_request),
    )
    root_receipt = sign_receipt(
        root_proposal,
        sender_private_key=buyer_agent_key,
        receiver_private_key=broker_agent_key,
        receiver_decision="ACCEPT",
        decided_at="2026-08-05T14:00:05Z",
    )

    valid_action = make_action(
        action_nonce="payment-attempt-001",
        operation="payment",
        resource="urn:crosstrace:payee:supplier-17",
        currency="USD",
        amount_minor=950_000,
    )
    leaf_scope = make_scope(
        operations=["payment"],
        resources=["urn:crosstrace:payee:supplier-17"],
        currency="USD",
        max_amount_minor=950_000,
        not_before="2026-08-05T14:00:00Z",
        not_after="2026-08-05T15:30:00Z",
        redelegations_remaining=0,
    )
    leaf_proposal = make_proposal(
        interaction_id="handoff-broker-payment-001",
        event_type="action_intent",
        created_at="2026-08-05T14:01:00Z",
        nonce="action-intent-nonce-001",
        sender=parties["broker"],
        receiver=parties["payment"],
        sender_sequence=1,
        previous_receipt_id=receipt_id(root_receipt),
        scope=leaf_scope,
        authority=authority,
        request_hash=action_id(valid_action),
    )
    leaf_receipt = sign_receipt(
        leaf_proposal,
        sender_private_key=broker_agent_key,
        receiver_private_key=payment_agent_key,
        receiver_decision="ACCEPT",
        decided_at="2026-08-05T14:01:05Z",
    )

    over_limit_action = make_action(
        action_nonce="payment-attempt-over-limit-001",
        operation="payment",
        resource="urn:crosstrace:payee:supplier-17",
        currency="USD",
        amount_minor=1_800_000,
    )
    over_limit_proposal = make_proposal(
        interaction_id="handoff-broker-payment-over-limit-001",
        event_type="action_intent",
        created_at="2026-08-05T14:04:00Z",
        nonce="action-intent-nonce-over-limit-001",
        sender=parties["broker"],
        receiver=parties["payment"],
        sender_sequence=2,
        previous_receipt_id=receipt_id(root_receipt),
        scope=deepcopy(leaf_scope),
        authority=deepcopy(authority),
        request_hash=action_id(over_limit_action),
    )
    over_limit_receipt = sign_receipt(
        over_limit_proposal,
        sender_private_key=broker_agent_key,
        receiver_private_key=payment_agent_key,
        receiver_decision="ACCEPT",
        decided_at="2026-08-05T14:04:05Z",
    )
    revoked_status = sign_authority_status(
        issuer_principal_id="buyer.example",
        issuer_key_id="buyer-root-key-1",
        subject_principal_id="broker.example",
        subject_key_id=parties["broker"]["key_id"],
        authority_version=8,
        state="REVOKED",
        issued_at="2026-08-05T14:03:00Z",
        fresh_until="2026-08-05T14:15:00Z",
        issuer_private_key=buyer_root_key,
    )

    return {
        "registry": registry,
        "keys": {
            "buyer_root": buyer_root_key,
            "buyer": buyer_agent_key,
            "broker": broker_agent_key,
            "payment": payment_agent_key,
        },
        "parties": parties,
        "active_status": active_status,
        "revoked_status": revoked_status,
        "root_receipt": root_receipt,
        "leaf_receipt": leaf_receipt,
        "over_limit_receipt": over_limit_receipt,
        "valid_action": valid_action,
        "over_limit_action": over_limit_action,
        "root_scope": root_scope,
        "leaf_scope": leaf_scope,
        "authority": authority,
    }


def _stable_decision(decision: Any) -> dict[str, Any]:
    return {
        "verdict": decision.verdict,
        "reasons": list(decision.reasons),
        "permit_issued": decision.permit_id is not None,
    }


def _stable_consumption(result: Any) -> dict[str, Any]:
    return {"verdict": result.verdict, "reason": result.reason}


def main() -> None:
    fixture = build_fixture()
    with tempfile.TemporaryDirectory(prefix="crosstrace_demo_") as temporary_directory:
        store = PermitStore(Path(temporary_directory) / "permit-state.sqlite3")
        gate = ActionGate(registry=fixture["registry"], permit_store=store)

        valid = gate.authorize(
            receipt_chain=[fixture["root_receipt"], fixture["leaf_receipt"]],
            current_authority_status=fixture["active_status"],
            action=fixture["valid_action"],
            now=FIXED_NOW,
            tool_id=TOOL_ID,
        )
        print("VALID_GATE", json.dumps(_stable_decision(valid), sort_keys=True))

        if valid.permit_id is None:
            raise RuntimeError("the valid fixture did not produce a permit")
        first_use = gate.consume(
            permit_id=valid.permit_id,
            tool_id=TOOL_ID,
            action=fixture["valid_action"],
            now=FIXED_NOW,
        )
        print("FIRST_CONSUME", json.dumps(_stable_consumption(first_use), sort_keys=True))
        if first_use.allowed:
            store.finish(permit_id=valid.permit_id, succeeded=True)
        replay = gate.consume(
            permit_id=valid.permit_id,
            tool_id=TOOL_ID,
            action=fixture["valid_action"],
            now=FIXED_NOW,
        )
        print("REPLAYED_CONSUME", json.dumps(_stable_consumption(replay), sort_keys=True))

        blocked = gate.authorize(
            receipt_chain=[fixture["root_receipt"], fixture["over_limit_receipt"]],
            current_authority_status=fixture["revoked_status"],
            action=fixture["over_limit_action"],
            now=FIXED_NOW,
            tool_id=TOOL_ID,
        )
        print("REVOKED_OVER_LIMIT_GATE", json.dumps(_stable_decision(blocked), sort_keys=True))
        store.close()


if __name__ == "__main__":
    main()
