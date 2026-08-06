"""Independent condition encoders and evaluators for the P0 pilot.

Fixtures are first reduced to neutral events. Each control then encodes those
events independently. Only the paired-receipt conditions retain CrossTrace
receipt identifiers and jointly attested proposal bytes. The evaluator receives
one serialized artifact and has no scenario or oracle argument.
"""

from __future__ import annotations

import base64
import tempfile
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Mapping, Sequence

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from crosstrace_sketch.protocol import (
    ActionGate,
    KeyRegistry,
    PermitStore,
    action_id,
    canonical_json,
    content_id,
    receipt_id,
)

from .model import CONDITIONS


TOOL_ID = "pilot-simulated-payment-adapter"


def _neutral_events(receipts: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Project receipts to mechanism-neutral event fields."""

    interaction_by_receipt = {
        receipt_id(receipt): receipt["proposal"]["interaction_id"] for receipt in receipts
    }
    events: list[dict[str, Any]] = []
    for receipt in receipts:
        proposal = receipt["proposal"]
        previous_receipt = proposal["previous_receipt_id"]
        previous_interaction = (
            interaction_by_receipt.get(previous_receipt, f"unresolved:{previous_receipt}")
            if previous_receipt is not None
            else None
        )
        authority = proposal["authority"]
        events.append(
            {
                "interaction_id": proposal["interaction_id"],
                "event_type": proposal["event_type"],
                "sender_principal_id": proposal["sender"]["principal_id"],
                "sender_key_id": proposal["sender"]["key_id"],
                "sender_sequence": proposal["sender_sequence"],
                "receiver_principal_id": proposal["receiver"]["principal_id"],
                "request_hash": proposal["request_hash"],
                "previous_interaction_id": previous_interaction,
                "scope": proposal["scope"],
                "authority": {
                    "issuer_principal_id": authority["issuer_principal_id"],
                    "subject_principal_id": authority["subject_principal_id"],
                    "subject_key_id": authority["subject_key_id"],
                    "authority_version": authority["authority_version"],
                },
            }
        )
    return events


def _event_hash(event: Mapping[str, Any]) -> str:
    return content_id("PILOT_NEUTRAL_EVENT", event)


def _local_body(holder_principal_id: str, event: Mapping[str, Any]) -> dict[str, Any]:
    body = {"holder_principal_id": holder_principal_id, "event": event}
    return {
        **body,
        "local_event_id": content_id("PILOT_LOCAL_EVENT", body),
    }


def _role_by_principal(case: Mapping[str, Any]) -> dict[str, str]:
    return {
        case["parties"][role]["principal_id"]: role
        for role in ("buyer", "broker", "supplier", "payment_a", "payment_b")
    }


def _signed_local_body(
    case: Mapping[str, Any], holder_principal_id: str, event: Mapping[str, Any]
) -> dict[str, Any]:
    body = _local_body(holder_principal_id, event)
    role = _role_by_principal(case)[holder_principal_id]
    signature = case["keys"][role].sign(canonical_json(body))
    return {
        "body": body,
        "signer_key_id": case["parties"][role]["key_id"],
        "signature": base64.urlsafe_b64encode(signature).rstrip(b"=").decode("ascii"),
    }


def _scenario_material(case: Mapping[str, Any], scenario: str) -> dict[str, Any]:
    base_chain = [case["root"], case["middle"], case["leaf"]]
    if scenario == "equivocation_joined_views":
        receipts = [*base_chain, case["fork_leaf"]]
        attempts = [
            {"attempt_id": "attempt-1", "action": case["valid_action"]},
            {"attempt_id": "attempt-2", "action": case["fork_action"]},
        ]
        gate_views = [
            {
                "store_id": "isolated-a",
                "attempt_id": "attempt-1",
                "receipt_chain": base_chain,
                "action": case["valid_action"],
            },
            {
                "store_id": "isolated-b",
                "attempt_id": "attempt-2",
                "receipt_chain": [case["root"], case["middle"], case["fork_leaf"]],
                "action": case["fork_action"],
            },
        ]
        audit_chains = [view["receipt_chain"] for view in gate_views]
    elif scenario == "over_limit":
        receipts = [case["root"], case["middle"], case["over_limit_leaf"]]
        attempts = [{"attempt_id": "attempt-1", "action": case["over_limit_action"]}]
        gate_views = [
            {
                "store_id": "local-a",
                "attempt_id": "attempt-1",
                "receipt_chain": receipts,
                "action": case["over_limit_action"],
            }
        ]
        audit_chains = []
    elif scenario == "local_replay":
        receipts = base_chain
        attempts = [
            {"attempt_id": "attempt-1", "action": case["valid_action"]},
            {"attempt_id": "attempt-2", "action": case["valid_action"]},
        ]
        gate_views = [
            {
                "store_id": "local-a",
                "attempt_id": attempt["attempt_id"],
                "receipt_chain": receipts,
                "action": case["valid_action"],
            }
            for attempt in attempts
        ]
        audit_chains = []
    else:
        receipts = base_chain
        attempts = [{"attempt_id": "attempt-1", "action": case["valid_action"]}]
        gate_views = [
            {
                "store_id": "local-a",
                "attempt_id": "attempt-1",
                "receipt_chain": receipts,
                "action": case["valid_action"],
            }
        ]
        audit_chains = []
    return {
        "receipts": receipts,
        "attempts": attempts,
        "gate_views": gate_views,
        "audit_chains": audit_chains,
        "status": (
            case["revoked_status"]
            if scenario == "revoked_authority"
            else case["active_status"]
        ),
        "withheld_holder": (
            case["parties"]["broker"]["principal_id"]
            if scenario == "withheld_broker_record"
            else None
        ),
    }


def build_evidence(
    case: Mapping[str, Any], scenario: str, condition: str
) -> dict[str, Any]:
    """Serialize one condition after applying the declared delivery schedule."""

    if condition not in CONDITIONS:
        raise ValueError(f"unknown pilot condition: {condition}")
    material = _scenario_material(case, scenario)
    events = _neutral_events(material["receipts"])
    endpoint_copies = [
        _local_body(holder, event)
        for event in events
        for holder in (event["sender_principal_id"], event["receiver_principal_id"])
        if holder != material["withheld_holder"]
    ]

    if condition == "ordinary_local_logs":
        evidence = {
            "local_records": endpoint_copies,
            "authority_status": material["status"]["status"],
        }
    elif condition == "central_append_only_log":
        entries: list[dict[str, Any]] = []
        previous_entry_id: str | None = None
        for event in events:
            body = {"event": event, "previous_entry_id": previous_entry_id}
            entry_id = content_id("PILOT_CENTRAL_ENTRY", body)
            entries.append({**body, "entry_id": entry_id})
            previous_entry_id = entry_id
        evidence = {
            "entries": entries,
            "authority_status": material["status"]["status"],
        }
    elif condition == "isolated_signed_logs":
        evidence = {
            "signed_local_records": [
                _signed_local_body(case, holder, event)
                for event in events
                for holder in (event["sender_principal_id"], event["receiver_principal_id"])
                if holder != material["withheld_holder"]
            ],
            "authority_status": material["status"],
        }
    else:
        evidence = {
            "receipt_copies": [
                {"holder_principal_id": holder, "receipt": receipt}
                for receipt in material["receipts"]
                for holder in (
                    receipt["proposal"]["sender"]["principal_id"],
                    receipt["proposal"]["receiver"]["principal_id"],
                )
                if holder != material["withheld_holder"]
            ],
            "authority_status": material["status"],
        }

    artifact: dict[str, Any] = {
        "condition": condition,
        "public_keys": case["public_keys"],
        "attempts": material["attempts"],
        "evidence": evidence,
    }
    if condition == "paired_receipts_with_gate":
        artifact["gate_views"] = [
            {**view, "authority_status": material["status"]}
            for view in material["gate_views"]
        ]
        artifact["audit_chains"] = material["audit_chains"]
    return artifact


def _decode_base64url(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _registry(public_keys: Sequence[Mapping[str, Any]]) -> KeyRegistry:
    registry = KeyRegistry()
    for entry in public_keys:
        registry.add(
            principal_id=entry["principal_id"],
            key_id=entry["key_id"],
            public_key=Ed25519PublicKey.from_public_bytes(
                _decode_base64url(entry["public_key"])
            ),
            roles=set(entry["roles"]),
        )
    return registry


def _unique_events(events: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    return list({_event_hash(event): dict(event) for event in events}.values())


def _events_from_evidence(
    artifact: Mapping[str, Any], registry: KeyRegistry
) -> tuple[list[dict[str, Any]], int]:
    condition = artifact["condition"]
    evidence = artifact["evidence"]
    sender_supported: set[str] = set()
    if condition == "ordinary_local_logs":
        events = [entry["event"] for entry in evidence["local_records"]]
    elif condition == "central_append_only_log":
        events = []
        expected_previous: str | None = None
        for entry in evidence["entries"]:
            body = {
                "event": entry["event"],
                "previous_entry_id": entry["previous_entry_id"],
            }
            if (
                entry["entry_id"] != content_id("PILOT_CENTRAL_ENTRY", body)
                or entry["previous_entry_id"] != expected_previous
            ):
                break
            events.append(entry["event"])
            expected_previous = entry["entry_id"]
    elif condition == "isolated_signed_logs":
        events = []
        for entry in evidence["signed_local_records"]:
            body = entry["body"]
            event = body["event"]
            try:
                public_key = registry.resolve(
                    principal_id=body["holder_principal_id"],
                    key_id=entry["signer_key_id"],
                    required_role="receipt",
                )
                public_key.verify(
                    _decode_base64url(entry["signature"]), canonical_json(body)
                )
            except (KeyError, ValueError, InvalidSignature):
                continue
            events.append(event)
            if body["holder_principal_id"] == event["sender_principal_id"]:
                sender_supported.add(_event_hash(event))
    else:
        store = PermitStore(":memory:")
        gate = ActionGate(registry=registry, permit_store=store)
        try:
            receipts_by_id = {
                receipt_id(copy["receipt"]): copy["receipt"]
                for copy in evidence["receipt_copies"]
            }
            valid_receipts = [
                receipt
                for receipt in receipts_by_id.values()
                if not gate._verify_receipt(receipt)
            ]
        finally:
            store.close()
        events = _neutral_events(valid_receipts)
        sender_supported = {_event_hash(event) for event in events}

    unique = _unique_events(events)
    if condition in {"ordinary_local_logs", "central_append_only_log"}:
        unsupported = len(unique)
    else:
        unsupported = len({_event_hash(event) for event in unique} - sender_supported)
    return unique, unsupported


def _reconstruct_paths(events: Sequence[Mapping[str, Any]]) -> list[list[list[str]]]:
    by_interaction: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
    for event in events:
        by_interaction[event["interaction_id"]].append(event)
    leaves = [event for event in events if event["event_type"] == "action_intent"]
    paths: list[list[list[str]]] = []
    for leaf in leaves:
        path: list[list[str]] = []
        current: Mapping[str, Any] | None = leaf
        seen: set[str] = set()
        while current is not None:
            marker = _event_hash(current)
            if marker in seen:
                break
            seen.add(marker)
            path.append(
                [
                    current["interaction_id"],
                    current["sender_principal_id"],
                    current["receiver_principal_id"],
                    current["request_hash"],
                ]
            )
            parent_id = current["previous_interaction_id"]
            candidates = by_interaction.get(parent_id, []) if parent_id is not None else []
            current = sorted(candidates, key=lambda item: _event_hash(item))[0] if candidates else None
        paths.append(list(reversed(path)))
    return paths


def _endpoint_copy_missing(artifact: Mapping[str, Any]) -> bool:
    condition = artifact["condition"]
    evidence = artifact["evidence"]
    if condition == "ordinary_local_logs":
        bodies = evidence["local_records"]
    elif condition == "isolated_signed_logs":
        bodies = [entry["body"] for entry in evidence["signed_local_records"]]
    elif condition in {"paired_receipts", "paired_receipts_with_gate"}:
        copies: dict[str, set[str]] = defaultdict(set)
        receipt_by_id: dict[str, Mapping[str, Any]] = {}
        for copy in evidence["receipt_copies"]:
            receipt = copy["receipt"]
            marker = receipt_id(receipt)
            receipt_by_id[marker] = receipt
            copies[marker].add(copy["holder_principal_id"])
        return any(
            copies[marker]
            != {
                receipt["proposal"]["sender"]["principal_id"],
                receipt["proposal"]["receiver"]["principal_id"],
            }
            for marker, receipt in receipt_by_id.items()
        )
    else:
        return False
    copies: dict[str, set[str]] = defaultdict(set)
    event_by_hash: dict[str, Mapping[str, Any]] = {}
    for body in bodies:
        event = body["event"]
        marker = _event_hash(event)
        event_by_hash[marker] = event
        copies[marker].add(body["holder_principal_id"])
    return any(
        copies[marker]
        != {event["sender_principal_id"], event["receiver_principal_id"]}
        for marker, event in event_by_hash.items()
    )


def _evidence_detections(
    events: Sequence[Mapping[str, Any]],
    artifact: Mapping[str, Any],
    registry: KeyRegistry,
) -> dict[str, bool]:
    interaction_ids = {event["interaction_id"] for event in events}
    missing_parent = any(
        event["previous_interaction_id"] is not None
        and event["previous_interaction_id"] not in interaction_ids
        for event in events
    )
    interaction_versions: dict[str, set[str]] = defaultdict(set)
    sequence_versions: dict[str, set[str]] = defaultdict(set)
    for event in events:
        marker = _event_hash(event)
        interaction_versions[event["interaction_id"]].add(marker)
        sequence_versions[
            f"{event['sender_key_id']}:{event['sender_sequence']}"
        ].add(marker)
    conflict = any(len(values) > 1 for values in interaction_versions.values()) or any(
        len(values) > 1 for values in sequence_versions.values()
    )
    status_wrapper = artifact["evidence"]["authority_status"]
    status = status_wrapper.get("status", status_wrapper)
    authenticated_revocation = False
    if artifact["condition"] in {
        "isolated_signed_logs",
        "paired_receipts",
        "paired_receipts_with_gate",
    }:
        store = PermitStore(":memory:")
        gate = ActionGate(registry=registry, permit_store=store)
        try:
            reasons, verified_status, _ = gate._verify_status(status_wrapper)
            authenticated_revocation = (
                not reasons
                and verified_status is not None
                and verified_status["state"] == "REVOKED"
            )
        finally:
            store.close()

    by_request = {event["request_hash"]: event for event in events}
    out_of_scope = False
    for attempt in artifact["attempts"]:
        action = attempt["action"]
        leaf = by_request.get(action_id(action))
        if leaf is not None:
            scope = leaf["scope"]
            out_of_scope = out_of_scope or not (
                action["operation"] in scope["operations"]
                and action["resource"] in scope["resources"]
                and action["currency"] == scope["currency"]
                and action["amount_minor"] <= scope["max_amount_minor"]
            )
    return {
        "conflicting_record_detected": conflict,
        "missing_parent_detected": missing_parent,
        "endpoint_copy_missing_detected": _endpoint_copy_missing(artifact),
        "revoked_status_claim_observed": status.get("state") == "REVOKED",
        "authenticated_revocation_detected": authenticated_revocation,
        "out_of_scope_action_observed": out_of_scope,
    }


def _execute_without_gate(artifact: Mapping[str, Any]) -> list[dict[str, Any]]:
    return [
        {
            "attempt_id": attempt["attempt_id"],
            "action_id": action_id(attempt["action"]),
            "executed": True,
            "decision": "EXECUTED_NO_GATE",
            "reasons": [],
        }
        for attempt in artifact["attempts"]
    ]


def _pilot_now(chain: Sequence[Mapping[str, Any]]) -> datetime:
    text = chain[0]["proposal"]["created_at"].replace("Z", "+00:00")
    return datetime.fromisoformat(text) + timedelta(minutes=10)


def _execute_with_gate(
    artifact: Mapping[str, Any], registry: KeyRegistry
) -> tuple[list[dict[str, Any]], bool]:
    attempts: list[dict[str, Any]] = []
    with tempfile.TemporaryDirectory(prefix="crosstrace_pilot_") as directory:
        gates: dict[str, tuple[ActionGate, PermitStore]] = {}
        try:
            for view in artifact["gate_views"]:
                store_id = view["store_id"]
                if store_id not in gates:
                    store = PermitStore(Path(directory) / f"{store_id}.sqlite3")
                    gates[store_id] = (ActionGate(registry=registry, permit_store=store), store)
                gate, store = gates[store_id]
                decision = gate.authorize(
                    receipt_chain=view["receipt_chain"],
                    current_authority_status=view["authority_status"],
                    action=view["action"],
                    now=_pilot_now(view["receipt_chain"]),
                    tool_id=TOOL_ID,
                )
                executed = False
                reasons = list(decision.reasons)
                if decision.permit_id:
                    consumed = gate.consume(
                        permit_id=decision.permit_id,
                        tool_id=TOOL_ID,
                        action=view["action"],
                        now=_pilot_now(view["receipt_chain"]),
                    )
                    executed = consumed.allowed
                    if consumed.reason:
                        reasons.append(consumed.reason)
                    if executed:
                        store.finish(permit_id=decision.permit_id, succeeded=True)
                attempts.append(
                    {
                        "attempt_id": view["attempt_id"],
                        "action_id": action_id(view["action"]),
                        "executed": executed,
                        "decision": decision.verdict,
                        "reasons": sorted(set(reasons)),
                    }
                )
        finally:
            for _, store in gates.values():
                store.close()

        joined_conflict = False
        if artifact["audit_chains"]:
            store = PermitStore(Path(directory) / "joined-audit.sqlite3")
            gate = ActionGate(registry=registry, permit_store=store)
            try:
                for index, chain in enumerate(artifact["audit_chains"]):
                    decision = gate.authorize(
                        receipt_chain=chain,
                        current_authority_status=artifact["gate_views"][index][
                            "authority_status"
                        ],
                        action=artifact["attempts"][index]["action"],
                        now=_pilot_now(chain),
                        tool_id=TOOL_ID,
                    )
                    joined_conflict = joined_conflict or (
                        "CONFLICTING_RECEIPT" in decision.reasons
                    )
            finally:
                store.close()
    return attempts, joined_conflict


def _signature_count(value: Any) -> int:
    if isinstance(value, Mapping):
        return sum(
            (1 if key == "signature" else 0) + _signature_count(child)
            for key, child in value.items()
        )
    if isinstance(value, list):
        return sum(_signature_count(child) for child in value)
    return 0


def evaluate_condition(artifact: Mapping[str, Any]) -> dict[str, Any]:
    """Evaluate serialized evidence without scenario or oracle labels."""

    condition = artifact["condition"]
    if condition not in CONDITIONS:
        raise ValueError(f"unknown pilot condition: {condition}")
    registry = _registry(artifact["public_keys"])
    events, unsupported_attributions = _events_from_evidence(artifact, registry)
    detections = _evidence_detections(events, artifact, registry)
    if condition == "paired_receipts_with_gate":
        attempts, joined_conflict = _execute_with_gate(artifact, registry)
    else:
        attempts = _execute_without_gate(artifact)
        joined_conflict = False
    detections["joined_view_conflict_detected"] = joined_conflict
    executed_ids = [attempt["action_id"] for attempt in attempts if attempt["executed"]]
    detections["duplicate_executed_action_observed"] = len(executed_ids) != len(
        set(executed_ids)
    )
    detections["replay_attempt_blocked"] = any(
        "REPLAY_DETECTED" in attempt["reasons"] for attempt in attempts
    )
    evidence = artifact["evidence"]
    return {
        "reconstructed_paths": _reconstruct_paths(events),
        "unsupported_principal_attributions": unsupported_attributions,
        "attempts": attempts,
        "detections": detections,
        "evidence_metrics": {
            "canonical_evidence_bytes": len(canonical_json(evidence)),
            "signatures_in_evidence": _signature_count(evidence),
            "records_observed": len(events),
            "model_calls": 0,
            "input_tokens": 0,
            "output_tokens": 0,
            "network_calls": 0,
        },
    }
