"""Deterministic four-principal evidence fixtures and fault scenarios."""

from __future__ import annotations

import base64
from copy import deepcopy
from datetime import UTC, datetime, timedelta
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from crosstrace_sketch.protocol import (
    KeyRegistry,
    action_id,
    content_id,
    format_timestamp,
    make_action,
    make_proposal,
    make_scope,
    receipt_id,
    sign_authority_status,
    sign_receipt,
)

from .model import OracleAttempt, OracleCase, stable_hex, stable_id


def _private_key(seed: int, role: str) -> Ed25519PrivateKey:
    raw = bytes.fromhex(stable_hex("pilot-private-key", seed, role))
    return Ed25519PrivateKey.from_private_bytes(raw)


def _party(role: str, seed: int) -> dict[str, str]:
    return {
        "principal_id": f"{role}.pilot.example",
        "agent_id": stable_id(f"{role}-agent", seed),
        "key_id": stable_id(f"{role}-key", seed),
    }


def _path_step(receipt: dict[str, Any]) -> tuple[str, str, str, str]:
    proposal = receipt["proposal"]
    return (
        proposal["interaction_id"],
        proposal["sender"]["principal_id"],
        proposal["receiver"]["principal_id"],
        proposal["request_hash"],
    )


def _public_key_text(private_key: Ed25519PrivateKey) -> str:
    raw = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def build_seed_case(seed: int) -> dict[str, Any]:
    """Create deterministic signed evidence shared across all conditions."""

    if seed not in range(10):
        raise ValueError("pilot seed must be an integer from 0 through 9")

    keys = {
        role: _private_key(seed, role)
        for role in ("buyer_root", "buyer", "broker", "supplier", "payment_a", "payment_b")
    }
    parties = {
        role: _party(role, seed)
        for role in ("buyer", "broker", "supplier", "payment_a", "payment_b")
    }
    registry = KeyRegistry()
    registry.add(
        principal_id=parties["buyer"]["principal_id"],
        key_id=stable_id("buyer-root-key", seed),
        public_key=keys["buyer_root"].public_key(),
        roles={"status"},
    )
    for role in ("buyer", "broker", "supplier", "payment_a", "payment_b"):
        registry.add(
            principal_id=parties[role]["principal_id"],
            key_id=parties[role]["key_id"],
            public_key=keys[role].public_key(),
            roles={"receipt"},
        )

    base = datetime(2026, 8, 6, 12, 0, seed, tzinfo=UTC)
    now = base + timedelta(minutes=10)
    active_status = sign_authority_status(
        issuer_principal_id=parties["buyer"]["principal_id"],
        issuer_key_id=stable_id("buyer-root-key", seed),
        subject_principal_id=parties["broker"]["principal_id"],
        subject_key_id=parties["broker"]["key_id"],
        authority_version=7,
        state="ACTIVE",
        issued_at=format_timestamp(base - timedelta(minutes=10)),
        fresh_until=format_timestamp(base + timedelta(hours=1)),
        issuer_private_key=keys["buyer_root"],
    )
    authority = {
        "issuer_principal_id": parties["buyer"]["principal_id"],
        "subject_principal_id": parties["broker"]["principal_id"],
        "subject_key_id": parties["broker"]["key_id"],
        "authority_version": 7,
        "revocation_status_id": active_status["status_id"],
    }
    resource = f"urn:crosstrace:pilot:supplier-{17 + seed}"
    root_max = 1_000_000 + seed * 1_000
    middle_max = root_max - 20_000
    leaf_max = middle_max - 20_000
    valid_amount = leaf_max - 1_000

    root_scope = make_scope(
        operations=["order", "payment"],
        resources=[resource],
        currency="USD",
        max_amount_minor=root_max,
        not_before=format_timestamp(base),
        not_after=format_timestamp(base + timedelta(hours=2)),
        redelegations_remaining=2,
    )
    root_request = {
        "purpose": "delegate-order-and-payment",
        "scope": root_scope,
        "subject_key_id": parties["broker"]["key_id"],
    }
    root = sign_receipt(
        make_proposal(
            interaction_id=stable_id("buyer-broker", seed),
            event_type="delegation",
            created_at=format_timestamp(base),
            nonce=stable_id("root-nonce", seed),
            sender=parties["buyer"],
            receiver=parties["broker"],
            sender_sequence=1,
            previous_receipt_id=None,
            scope=root_scope,
            authority=authority,
            request_hash=content_id("DELEGATION_REQUEST", root_request),
        ),
        sender_private_key=keys["buyer"],
        receiver_private_key=keys["broker"],
        receiver_decision="ACCEPT",
        decided_at=format_timestamp(base + timedelta(seconds=5)),
    )

    middle_scope = make_scope(
        operations=["order", "payment"],
        resources=[resource],
        currency="USD",
        max_amount_minor=middle_max,
        not_before=format_timestamp(base),
        not_after=format_timestamp(base + timedelta(minutes=110)),
        redelegations_remaining=1,
    )
    middle_request = {
        "purpose": "delegate-fulfilment-and-payment",
        "scope": middle_scope,
        "subject_key_id": parties["supplier"]["key_id"],
    }
    middle = sign_receipt(
        make_proposal(
            interaction_id=stable_id("broker-supplier", seed),
            event_type="delegation",
            created_at=format_timestamp(base + timedelta(minutes=1)),
            nonce=stable_id("middle-nonce", seed),
            sender=parties["broker"],
            receiver=parties["supplier"],
            sender_sequence=1,
            previous_receipt_id=receipt_id(root),
            scope=middle_scope,
            authority=authority,
            request_hash=content_id("DELEGATION_REQUEST", middle_request),
        ),
        sender_private_key=keys["broker"],
        receiver_private_key=keys["supplier"],
        receiver_decision="ACCEPT",
        decided_at=format_timestamp(base + timedelta(minutes=1, seconds=5)),
    )

    valid_action = make_action(
        action_nonce=stable_id("payment-action", seed),
        operation="payment",
        resource=resource,
        currency="USD",
        amount_minor=valid_amount,
    )
    leaf_scope = make_scope(
        operations=["payment"],
        resources=[resource],
        currency="USD",
        max_amount_minor=leaf_max,
        not_before=format_timestamp(base),
        not_after=format_timestamp(base + timedelta(minutes=100)),
        redelegations_remaining=0,
    )

    def make_leaf(*, receiver_role: str, action: dict[str, Any], suffix: str) -> dict[str, Any]:
        proposal = make_proposal(
            interaction_id=stable_id("supplier-payment", seed),
            event_type="action_intent",
            created_at=format_timestamp(base + timedelta(minutes=2)),
            nonce=stable_id("leaf-nonce", seed, suffix),
            sender=parties["supplier"],
            receiver=parties[receiver_role],
            sender_sequence=1,
            previous_receipt_id=receipt_id(middle),
            scope=deepcopy(leaf_scope),
            authority=deepcopy(authority),
            request_hash=action_id(action),
        )
        return sign_receipt(
            proposal,
            sender_private_key=keys["supplier"],
            receiver_private_key=keys[receiver_role],
            receiver_decision="ACCEPT",
            decided_at=format_timestamp(base + timedelta(minutes=2, seconds=5)),
        )

    leaf = make_leaf(receiver_role="payment_a", action=valid_action, suffix="a")
    fork_action = make_action(
        action_nonce=stable_id("fork-payment-action", seed),
        operation="payment",
        resource=resource,
        currency="USD",
        amount_minor=valid_amount - 1_000,
    )
    fork_leaf = make_leaf(receiver_role="payment_b", action=fork_action, suffix="b")

    over_limit_action = make_action(
        action_nonce=stable_id("over-limit-action", seed),
        operation="payment",
        resource=resource,
        currency="USD",
        amount_minor=root_max + 800_000,
    )
    over_limit_leaf = make_leaf(
        receiver_role="payment_a", action=over_limit_action, suffix="over-limit"
    )
    revoked_status = sign_authority_status(
        issuer_principal_id=parties["buyer"]["principal_id"],
        issuer_key_id=stable_id("buyer-root-key", seed),
        subject_principal_id=parties["broker"]["principal_id"],
        subject_key_id=parties["broker"]["key_id"],
        authority_version=8,
        state="REVOKED",
        issued_at=format_timestamp(base + timedelta(minutes=5)),
        fresh_until=format_timestamp(base + timedelta(hours=1)),
        issuer_private_key=keys["buyer_root"],
    )

    path_a = tuple(_path_step(receipt) for receipt in (root, middle, leaf))
    path_b = tuple(_path_step(receipt) for receipt in (root, middle, fork_leaf))
    path_over_limit = tuple(
        _path_step(receipt) for receipt in (root, middle, over_limit_leaf)
    )
    return {
        "registry": registry,
        "public_keys": [
            {
                "principal_id": parties["buyer"]["principal_id"],
                "key_id": stable_id("buyer-root-key", seed),
                "roles": ["status"],
                "public_key": _public_key_text(keys["buyer_root"]),
            },
            *[
                {
                    "principal_id": parties[role]["principal_id"],
                    "key_id": parties[role]["key_id"],
                    "roles": ["receipt"],
                    "public_key": _public_key_text(keys[role]),
                }
                for role in ("buyer", "broker", "supplier", "payment_a", "payment_b")
            ],
        ],
        "keys": keys,
        "parties": parties,
        "now": now,
        "active_status": active_status,
        "revoked_status": revoked_status,
        "root": root,
        "middle": middle,
        "leaf": leaf,
        "fork_leaf": fork_leaf,
        "over_limit_leaf": over_limit_leaf,
        "valid_action": valid_action,
        "fork_action": fork_action,
        "over_limit_action": over_limit_action,
        "path_a": path_a,
        "path_b": path_b,
        "path_over_limit": path_over_limit,
    }


def oracle_for(case: dict[str, Any], scenario: str, seed: int) -> OracleCase:
    valid_id = action_id(case["valid_action"])
    if scenario == "equivocation_joined_views":
        paths = (case["path_a"], case["path_b"])
        attempts = (
            OracleAttempt("attempt-1", valid_id, True),
            OracleAttempt("attempt-2", action_id(case["fork_action"]), False),
        )
        fault = "EQUIVOCATION"
    else:
        paths = (
            case["path_over_limit"] if scenario == "over_limit" else case["path_a"],
        )
        if scenario == "local_replay":
            attempts = (
                OracleAttempt("attempt-1", valid_id, True),
                OracleAttempt("attempt-2", valid_id, False),
            )
        elif scenario == "over_limit":
            attempts = (
                OracleAttempt("attempt-1", action_id(case["over_limit_action"]), False),
            )
        else:
            attempts = (
                OracleAttempt(
                    "attempt-1",
                    valid_id,
                    scenario in {"valid_current_within_scope", "withheld_broker_record"},
                ),
            )
        fault = {
            "valid_current_within_scope": None,
            "withheld_broker_record": "WITHHELD_RECORD",
            "revoked_authority": "AUTHORITY_REVOKED",
            "over_limit": "ACTION_OUT_OF_SCOPE",
            "local_replay": "REPLAY_DETECTED",
        }[scenario]
    return OracleCase(
        case_id=f"{scenario}-seed-{seed:02d}",
        scenario=scenario,
        seed=seed,
        paths=paths,
        attempts=attempts,
        expected_fault=fault,
    )
