"""Representation-blind strict chain assembly for development audit views."""

from __future__ import annotations

from typing import Any, Iterable

from crosstrace_sketch.protocol import action_id, content_id
from preaward.crosstrace_sprint1.delivery import AuditObservation, LocalObservation
from preaward.crosstrace_sprint2.model import EvidenceRepresentation, PolicyView
from preaward.crosstrace_sprint2.validation import validate_observation

from .fixtures import BuiltCase


def validation_summary(
    observation: LocalObservation | AuditObservation,
    *,
    representation: EvidenceRepresentation,
    case: BuiltCase,
) -> dict[str, Any]:
    report = validate_observation(
        observation,
        representation=representation,
        key_registry=case.key_registry,
        store_registry=case.store_registry,
    )
    views = tuple(item.policy_view() for item in report.validated_handoffs)
    chain = assemble_strict_chain(views, expected_action_id=action_id(case.action))
    return {
        "validated_handoff_ids": sorted(
            item.validated_handoff_id for item in report.validated_handoffs
        ),
        "policy_view_hashes": sorted(
            content_id("SPRINT4_POLICY_VIEW", item.to_dict()) for item in views
        ),
        "issue_codes": sorted({item.reason_code for item in report.issues}),
        "chain_status": chain["chain_status"],
        "chain_reason": chain["chain_reason"],
        "interaction_ids": chain["interaction_ids"],
    }


def assemble_strict_chain(
    policy_views: Iterable[PolicyView],
    *,
    expected_action_id: str,
) -> dict[str, Any]:
    """Assemble one complete chain without accessing representation metadata."""

    views = tuple(policy_views)
    if not all(type(item) is PolicyView and item.validator_issued for item in views):
        return _unresolved("UNTRUSTED_POLICY_VIEW")
    handoffs = [item.to_dict()["handoff"] for item in views]
    by_id = {item["interaction_id"]: item for item in handoffs}
    if len(by_id) != len(handoffs):
        return _unresolved("DUPLICATE_INTERACTION")
    leaves = [
        item
        for item in handoffs
        if item["event_type"] == "action_intent"
        and item["request_hash"] == expected_action_id
    ]
    if not leaves:
        return _unresolved("LEAF_MISSING")
    if len(leaves) != 1:
        return _unresolved("AMBIGUOUS_LEAF")
    reverse: list[dict[str, Any]] = []
    seen: set[str] = set()
    current = leaves[0]
    while True:
        interaction_id = current["interaction_id"]
        if interaction_id in seen:
            return _unresolved("CHAIN_CYCLE")
        seen.add(interaction_id)
        reverse.append(current)
        parent_id = current["previous_interaction_id"]
        if parent_id is None:
            break
        if parent_id not in by_id:
            return _unresolved("PARENT_MISSING")
        current = by_id[parent_id]
    ordered = list(reversed(reverse))
    if ordered[0]["event_type"] != "delegation":
        return _unresolved("ROOT_INVALID")
    if any(item["event_type"] != "delegation" for item in ordered[:-1]):
        return _unresolved("INTERMEDIATE_INVALID")
    if set(seen) != set(by_id):
        return _unresolved("EXTRA_OR_DISCONNECTED_HANDOFF")
    return {
        "chain_status": "COMPLETE",
        "chain_reason": "OK",
        "interaction_ids": [item["interaction_id"] for item in ordered],
    }


def _unresolved(reason: str) -> dict[str, Any]:
    return {
        "chain_status": "UNRESOLVED",
        "chain_reason": reason,
        "interaction_ids": [],
    }
