"""Hand-written, deterministic inputs for the Sprint 4 development matrix."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Mapping

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from crosstrace_sketch.protocol import (
    KeyRegistry,
    action_id,
    content_id,
    loads_strict,
    make_action,
    make_scope,
    sign_authority_status,
)
from preaward.crosstrace_sprint1.delivery import (
    DeliveryPolicy,
    Disposition,
    TransmissionOverride,
)
from preaward.crosstrace_sprint2.model import (
    EndpointRole,
    NeutralHandoff,
    make_neutral_handoff,
)
from preaward.crosstrace_sprint2.validation import StoreRegistry

from .model import (
    FIXTURE_VERSION,
    RELEASE_ID,
    DestinationKind,
    FixtureConfig,
    HarnessError,
    HolderRole,
    SlotAssignment,
)

LOCAL_STORE_ID = "store.verifier"
AUDIT_STORE_ID = "store.audit"
PERMIT_STORE_ID = "store.permits"
VERIFIER_ID = "verifier.local"
TOOL_ID = "simulated-payment-adapter"
DECISION_TIME = datetime(2026, 8, 7, 14, 5, 0, tzinfo=UTC)
EPISODE_END = datetime(2026, 8, 7, 14, 6, 0, tzinfo=UTC)
AUDIT_DELTA = timedelta(minutes=10)
DELIVERY_SEED = b"crosstrace-six-cell-development-v0.1"


def _private_key(byte_value: int) -> Ed25519PrivateKey:
    # Public deterministic fixture material. Never use outside development tests.
    return Ed25519PrivateKey.from_private_bytes(bytes([byte_value]) * 32)


@dataclass(frozen=True, slots=True)
class BuiltCase:
    config: FixtureConfig
    key_registry: KeyRegistry
    store_registry: StoreRegistry
    private_keys: Mapping[str, Ed25519PrivateKey]
    handoffs: tuple[NeutralHandoff, ...]
    decided_at: Mapping[str, str]
    action: Mapping[str, Any]
    statuses: tuple[Mapping[str, Any], ...]
    slot_assignments: tuple[SlotAssignment, ...]
    delivery_policy: DeliveryPolicy
    delivery_overrides: tuple[TransmissionOverride, ...]

    @property
    def root(self) -> NeutralHandoff:
        return self.handoffs[0]

    @property
    def leaf(self) -> NeutralHandoff:
        return self.handoffs[1]

    def handoff_by_item(self, semantic_item_id: str) -> NeutralHandoff:
        mapping = {
            "item.root": self.handoffs[0],
            "item.leaf": self.handoffs[1],
        }
        if len(self.handoffs) == 3:
            mapping["item.leaf.alt"] = self.handoffs[2]
        try:
            return mapping[semantic_item_id]
        except KeyError as exc:
            raise HarnessError("slot refers to an unknown handoff item") from exc

    def status_by_item(self, semantic_item_id: str) -> Mapping[str, Any]:
        mapping = {"item.status.1": self.statuses[0]}
        if len(self.statuses) == 2:
            mapping["item.status.2"] = self.statuses[1]
        try:
            return mapping[semantic_item_id]
        except KeyError as exc:
            raise HarnessError("slot refers to an unknown status item") from exc


def fixture_manifest_path() -> Path:
    return Path(__file__).resolve().parent / "fixtures" / "development-v0.1.json"


def load_fixture_configs(path: Path | None = None) -> tuple[FixtureConfig, ...]:
    source = path or fixture_manifest_path()
    try:
        raw = source.read_bytes()
        value = loads_strict(raw)
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        raise HarnessError("fixture manifest is not valid UTF-8 JSON") from exc
    if not isinstance(value, dict) or set(value) != {
        "version",
        "fixture_set_id",
        "classification",
        "cases",
    }:
        raise HarnessError("fixture manifest fields are not exact")
    if value["version"] != FIXTURE_VERSION:
        raise HarnessError(f"fixture version must equal {FIXTURE_VERSION}")
    if value["fixture_set_id"] != RELEASE_ID:
        raise HarnessError(f"fixture_set_id must equal {RELEASE_ID}")
    if value["classification"] != "DEVELOPMENT_ONLY":
        raise HarnessError("fixture classification must be DEVELOPMENT_ONLY")
    if not isinstance(value["cases"], list):
        raise HarnessError("fixture cases must be an array")
    configs = tuple(FixtureConfig.from_dict(item) for item in value["cases"])
    expected_ids = (
        "complete",
        "one-leaf-receiver-locally-withheld",
        "both-leaf-copies-locally-withheld",
        "status-delayed-locally-audit-visible",
        "higher-revocation",
        "out-of-scope",
        "replay",
        "authenticated-conflicting-leaf",
    )
    if tuple(item.case_id for item in configs) != expected_ids:
        raise HarnessError("fixture cases or ordering do not match the frozen set")
    if len({item.opaque_trace_id for item in configs}) != len(configs):
        raise HarnessError("opaque_trace_id values must be unique")
    return configs


def build_cases(
    configs: tuple[FixtureConfig, ...] | None = None,
) -> tuple[BuiltCase, ...]:
    return tuple(build_case(config) for config in (configs or load_fixture_configs()))


def build_case(config: FixtureConfig) -> BuiltCase:
    authority_key = _private_key(0x11)
    buyer_key = _private_key(0x22)
    broker_key = _private_key(0x33)
    payment_key = _private_key(0x44)
    private_keys = {
        "buyer-agent-key-1": buyer_key,
        "broker-agent-key-1": broker_key,
        "payment-agent-key-1": payment_key,
    }
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
        key_id="buyer-authority-key-1",
        public_key=authority_key.public_key(),
        roles={"status"},
    )
    for name, principal in (
        ("buyer", "buyer.example"),
        ("broker", "broker.example"),
        ("payment", "payment.example"),
    ):
        registry.add(
            principal_id=principal,
            key_id=parties[name]["key_id"],
            public_key=private_keys[parties[name]["key_id"]].public_key(),
            roles={"receipt"},
        )

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

    active_status = sign_authority_status(
        issuer_principal_id="buyer.example",
        issuer_key_id="buyer-authority-key-1",
        subject_principal_id="broker.example",
        subject_key_id="broker-agent-key-1",
        authority_version=7,
        state="ACTIVE",
        issued_at="2026-08-07T13:55:00Z",
        fresh_until="2026-08-07T14:30:00Z",
        issuer_private_key=authority_key,
    )
    statuses: list[Mapping[str, Any]] = [active_status]
    if config.authority_mode == "ACTIVE_AND_HIGHER_REVOKED":
        statuses.append(
            sign_authority_status(
                issuer_principal_id="buyer.example",
                issuer_key_id="buyer-authority-key-1",
                subject_principal_id="broker.example",
                subject_key_id="broker-agent-key-1",
                authority_version=8,
                state="REVOKED",
                issued_at="2026-08-07T14:03:00Z",
                fresh_until="2026-08-07T14:30:00Z",
                issuer_private_key=authority_key,
            )
        )

    action = make_action(
        action_nonce=f"action-{config.opaque_trace_id}",
        operation="payment",
        resource="urn:crosstrace:payee:supplier-17",
        currency="USD",
        amount_minor=(1_800_000 if config.action_mode == "OUT_OF_SCOPE" else 900_000),
    )
    root_scope = make_scope(
        operations=["order", "payment"],
        resources=["urn:crosstrace:payee:supplier-17"],
        currency="USD",
        max_amount_minor=2_000_000,
        not_before="2026-08-07T14:00:00Z",
        not_after="2026-08-07T16:00:00Z",
        redelegations_remaining=1,
    )
    leaf_scope = make_scope(
        operations=["payment"],
        resources=["urn:crosstrace:payee:supplier-17"],
        currency="USD",
        max_amount_minor=950_000,
        not_before="2026-08-07T14:00:00Z",
        not_after="2026-08-07T15:30:00Z",
        redelegations_remaining=0,
    )
    lineage = {
        "issuer_principal_id": "buyer.example",
        "subject_principal_id": "broker.example",
        "subject_key_id": "broker-agent-key-1",
    }
    root_interaction = f"handoff-{config.opaque_trace_id}-root"
    leaf_interaction = f"handoff-{config.opaque_trace_id}-leaf"
    root = make_neutral_handoff(
        interaction_id=root_interaction,
        sender=parties["buyer"],
        receiver=parties["broker"],
        event_type="delegation",
        sender_sequence=1,
        previous_interaction_id=None,
        scope=root_scope,
        authority_lineage=lineage,
        authority_version=7,
        referenced_status_id=active_status["status_id"],
        created_at="2026-08-07T14:00:00Z",
        request_hash=content_id(
            "DEVELOPMENT_DELEGATION_REQUEST",
            {"trace": config.opaque_trace_id, "scope": root_scope},
        ),
    )
    leaf = make_neutral_handoff(
        interaction_id=leaf_interaction,
        sender=parties["broker"],
        receiver=parties["payment"],
        event_type="action_intent",
        sender_sequence=1,
        previous_interaction_id=root_interaction,
        scope=leaf_scope,
        authority_lineage=lineage,
        authority_version=7,
        referenced_status_id=active_status["status_id"],
        created_at="2026-08-07T14:01:00Z",
        request_hash=action_id(action),
    )
    handoffs: list[NeutralHandoff] = [root, leaf]
    decided_at: dict[str, str] = {
        root_interaction: "2026-08-07T14:00:05Z",
        leaf_interaction: "2026-08-07T14:01:05Z",
    }
    if config.conflicting_leaf:
        alternative = make_neutral_handoff(
            interaction_id=f"handoff-{config.opaque_trace_id}-leaf-alt",
            sender=parties["broker"],
            receiver=parties["payment"],
            event_type="action_intent",
            sender_sequence=1,
            previous_interaction_id=root_interaction,
            scope=leaf_scope,
            authority_lineage=lineage,
            authority_version=7,
            referenced_status_id=active_status["status_id"],
            created_at="2026-08-07T14:02:00Z",
            request_hash=action_id(action),
        )
        handoffs.append(alternative)
        decided_at[alternative.to_dict()["interaction_id"]] = "2026-08-07T14:02:05Z"

    assignments = _slot_assignments(
        config, tuple(handoffs), tuple(statuses), decided_at
    )
    withheld: list[str] = []
    leaf_prefix = f"slot.{config.opaque_trace_id}.leaf"
    if config.delivery_mode == "WITHHOLD_LEAF_RECEIVER_LOCAL":
        withheld.append(f"{leaf_prefix}.receiver.local")
    elif config.delivery_mode == "WITHHOLD_BOTH_LEAF_LOCAL":
        withheld.extend(
            (f"{leaf_prefix}.sender.local", f"{leaf_prefix}.receiver.local")
        )
    policy = DeliveryPolicy(withheld_delivery_slot_ids=tuple(withheld))
    overrides: list[TransmissionOverride] = []
    if config.delivery_mode == "DELAY_ACTIVE_STATUS_LOCAL":
        overrides.append(
            TransmissionOverride(
                delivery_slot_id=f"slot.{config.opaque_trace_id}.status1.authority.local",
                copy_index=0,
                disposition=Disposition.DELIVER,
                delay_seconds=900,
            )
        )
    return BuiltCase(
        config=config,
        key_registry=registry,
        store_registry=stores,
        private_keys=private_keys,
        handoffs=tuple(handoffs),
        decided_at=decided_at,
        action=action,
        statuses=tuple(statuses),
        slot_assignments=assignments,
        delivery_policy=policy,
        delivery_overrides=tuple(overrides),
    )


def _slot_assignments(
    config: FixtureConfig,
    handoffs: tuple[NeutralHandoff, ...],
    statuses: tuple[Mapping[str, Any], ...],
    decided_at: Mapping[str, str],
) -> tuple[SlotAssignment, ...]:
    result: list[SlotAssignment] = []
    handoff_items = ["item.root", "item.leaf"]
    if len(handoffs) == 3:
        handoff_items.append("item.leaf.alt")
    item_tokens = {"item.root": "root", "item.leaf": "leaf", "item.leaf.alt": "leafalt"}
    origins = {
        "buyer.example": "store.buyer",
        "broker.example": "store.broker",
        "payment.example": "store.payment",
    }
    for item_id, handoff in zip(handoff_items, handoffs, strict=True):
        body = handoff.to_dict()
        decision = datetime.strptime(
            decided_at[body["interaction_id"]], "%Y-%m-%dT%H:%M:%SZ"
        ).replace(tzinfo=UTC)
        sent_at = decision + timedelta(seconds=1)
        for holder_role, party in (
            (HolderRole.SENDER, body["sender"]),
            (HolderRole.RECEIVER, body["receiver"]),
        ):
            for destination_kind, destination_store in (
                (DestinationKind.LOCAL, LOCAL_STORE_ID),
                (DestinationKind.AUDIT, AUDIT_STORE_ID),
            ):
                result.append(
                    SlotAssignment(
                        slot_id=(
                            f"slot.{config.opaque_trace_id}.{item_tokens[item_id]}."
                            f"{holder_role.value.lower()}."
                            f"{destination_kind.value.lower()}"
                        ),
                        semantic_item_id=item_id,
                        holder_role=holder_role,
                        origin_store_id=origins[party["principal_id"]],
                        destination_kind=destination_kind,
                        destination_store_id=destination_store,
                        sent_at=sent_at,
                    )
                )
    for index, status in enumerate(statuses, 1):
        issued = datetime.strptime(
            status["status"]["issued_at"], "%Y-%m-%dT%H:%M:%SZ"
        ).replace(tzinfo=UTC)
        for destination_kind, destination_store in (
            (DestinationKind.LOCAL, LOCAL_STORE_ID),
            (DestinationKind.AUDIT, AUDIT_STORE_ID),
        ):
            result.append(
                SlotAssignment(
                    slot_id=(
                        f"slot.{config.opaque_trace_id}.status{index}.authority."
                        f"{destination_kind.value.lower()}"
                    ),
                    semantic_item_id=f"item.status.{index}",
                    holder_role=HolderRole.AUTHORITY,
                    origin_store_id="store.authority",
                    destination_kind=destination_kind,
                    destination_store_id=destination_store,
                    sent_at=issued + timedelta(seconds=1),
                )
            )
    return tuple(sorted(result, key=lambda item: item.slot_id))
