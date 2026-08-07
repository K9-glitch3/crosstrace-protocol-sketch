"""Preparation and representation-blind common action gate for Sprint 3."""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Iterable, Mapping

from cryptography.exceptions import InvalidSignature

from crosstrace_sketch.protocol import (
    KeyRegistry,
    ProtocolError,
    action_id,
    canonical_json,
    content_id,
)
from preaward.crosstrace_sprint1.delivery import LocalObservation, PayloadKind
from preaward.crosstrace_sprint2.model import (
    EvidenceRepresentation,
    PolicyView,
    evaluate_common_evidence_policy,
)
from preaward.crosstrace_sprint2.validation import (
    StoreRegistry,
    validate_observation,
)

from .crypto_compat import verify_authority_status_attestation
from .model import (
    MAX_SAFE_INTEGER,
    _PREPARATION_TOKEN,
    AuthorityStatusEvidence,
    CommonGateDecision,
    CommonGateInput,
    GateError,
    NeutralObservationRecord,
    NeutralPermitStateSnapshot,
    ObservationKind,
    PermitTransitionResult,
    format_timestamp,
    parse_timestamp,
    require_hash,
    require_identifier,
)
from .permit import (
    EvidenceConflict,
    NeutralPermitStore,
    ReplayDetected,
    StateChanged,
)


@dataclass(frozen=True, slots=True)
class _VerifierBinding:
    evidence_store_id: str
    permit_store_id: str
    tool_ids: frozenset[str]


class VerifierRegistry:
    """Freeze a verifier's evidence store, permit store, and action tools."""

    def __init__(self) -> None:
        self._bindings: dict[str, _VerifierBinding] = {}

    def add(
        self,
        *,
        verifier_id: str,
        evidence_store_id: str,
        permit_store_id: str,
        tool_ids: Iterable[str],
    ) -> None:
        require_identifier(verifier_id, "verifier_id")
        require_identifier(evidence_store_id, "evidence_store_id")
        require_identifier(permit_store_id, "permit_store_id")
        if isinstance(tool_ids, (str, bytes)):
            raise GateError("tool_ids must be an iterable of identifiers")
        try:
            frozen_tools = frozenset(tool_ids)
        except TypeError as exc:
            raise GateError("tool_ids must be an iterable") from exc
        if not frozen_tools:
            raise GateError("tool_ids must not be empty")
        for tool_id in frozen_tools:
            require_identifier(tool_id, "tool_id")
        candidate = _VerifierBinding(
            evidence_store_id=evidence_store_id,
            permit_store_id=permit_store_id,
            tool_ids=frozen_tools,
        )
        existing = self._bindings.get(verifier_id)
        if existing is not None and existing != candidate:
            raise GateError(f"verifier_id already registered: {verifier_id}")
        self._bindings[verifier_id] = candidate

    def resolve(
        self,
        *,
        verifier_id: str,
        evidence_store_id: str,
        permit_store_id: str,
    ) -> _VerifierBinding:
        binding = self._bindings.get(verifier_id)
        if (
            binding is None
            or binding.evidence_store_id != evidence_store_id
            or binding.permit_store_id != permit_store_id
        ):
            raise KeyError(verifier_id)
        return binding

    def tool_allowed(self, *, verifier_id: str, tool_id: str) -> bool:
        binding = self._bindings.get(verifier_id)
        return binding is not None and tool_id in binding.tool_ids


class StatusStoreRegistry:
    """Allow-list status issuers whose signed messages may use an origin store."""

    def __init__(self) -> None:
        self._stores: dict[str, frozenset[str]] = {}

    def add(
        self,
        *,
        store_id: str,
        issuer_principal_id: str | None = None,
        issuer_principal_ids: Iterable[str] | None = None,
    ) -> None:
        require_identifier(store_id, "status store_id")
        if (issuer_principal_id is None) == (issuer_principal_ids is None):
            raise GateError(
                "provide exactly one of issuer_principal_id or issuer_principal_ids"
            )
        if isinstance(issuer_principal_ids, (str, bytes)):
            raise GateError("issuer_principal_ids must be an iterable of identifiers")
        try:
            issuers = (
                frozenset({issuer_principal_id})
                if issuer_principal_id is not None
                else frozenset(issuer_principal_ids or ())
            )
        except TypeError as exc:
            raise GateError("issuer_principal_ids must be an iterable") from exc
        if not issuers:
            raise GateError("issuer_principal_ids must not be empty")
        for issuer in issuers:
            require_identifier(issuer, "status issuer principal_id")
        existing = self._stores.get(store_id)
        if existing is not None and existing != issuers:
            raise GateError(f"status store_id already registered: {store_id}")
        self._stores[store_id] = issuers

    def resolve(self, *, store_id: str, issuer_principal_id: str) -> None:
        issuers = self._stores.get(store_id)
        if issuers is None or issuer_principal_id not in issuers:
            raise KeyError(store_id)


def _exact_mapping(value: Any, fields: frozenset[str], name: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or not all(isinstance(key, str) for key in value):
        raise GateError(f"{name} must be an object")
    if frozenset(value) != fields:
        raise GateError(f"{name} fields do not match the profile")
    return value


def _validate_status_payload(value: Any) -> Mapping[str, Any]:
    status = _exact_mapping(
        value,
        frozenset(
            {
                "protocol_version",
                "type",
                "issuer_principal_id",
                "issuer_key_id",
                "subject_principal_id",
                "subject_key_id",
                "authority_version",
                "state",
                "issued_at",
                "fresh_until",
            }
        ),
        "authority status payload",
    )
    if (
        status["protocol_version"] != "crosstrace-sketch/0.1"
        or status["type"] != "authority_status"
    ):
        raise GateError("unsupported authority status version or type")
    for name in (
        "issuer_principal_id",
        "issuer_key_id",
        "subject_principal_id",
        "subject_key_id",
    ):
        require_identifier(status[name], f"status.{name}")
    version = status["authority_version"]
    if type(version) is not int or not 1 <= version <= MAX_SAFE_INTEGER:
        raise GateError("status authority_version is outside the safe range")
    if status["state"] not in {"ACTIVE", "REVOKED"}:
        raise GateError("status state must be ACTIVE or REVOKED")
    issued = parse_timestamp(status["issued_at"], "status.issued_at")
    fresh_until = parse_timestamp(status["fresh_until"], "status.fresh_until")
    if issued >= fresh_until:
        raise GateError("status issued_at must precede fresh_until")
    canonical_json(dict(status))
    return status


def _authenticate_status(
    payload: Any,
    *,
    key_registry: KeyRegistry,
) -> tuple[str, Mapping[str, Any]]:
    signed = _exact_mapping(
        payload,
        frozenset({"status_id", "status", "attestation"}),
        "signed authority status",
    )
    status = _validate_status_payload(signed["status"])
    expected_id = content_id("AUTHORITY_STATUS", status)
    require_hash(signed["status_id"], "status_id")
    if signed["status_id"] != expected_id:
        raise GateError("authority status digest does not match")
    attestation = _exact_mapping(
        signed["attestation"],
        frozenset({"algorithm", "key_id", "status_id", "signature"}),
        "status attestation",
    )
    if (
        attestation["algorithm"] != "Ed25519"
        or attestation["key_id"] != status["issuer_key_id"]
        or attestation["status_id"] != expected_id
    ):
        raise GateError("status attestation fields do not match")
    try:
        public_key = key_registry.resolve(
            principal_id=status["issuer_principal_id"],
            key_id=status["issuer_key_id"],
            required_role="status",
        )
    except KeyError as exc:
        raise GateError("authority status key is not trusted") from exc
    body = {
        "algorithm": attestation["algorithm"],
        "key_id": attestation["key_id"],
        "status_id": attestation["status_id"],
    }
    try:
        verify_authority_status_attestation(
            body,
            attestation["signature"],
            public_key,
        )
    except (InvalidSignature, ProtocolError, ValueError) as exc:
        raise GateError("authority status signature is invalid") from exc
    canonical_json(dict(signed))
    return expected_id, status


def prepare_common_gate_input(
    *,
    observation: LocalObservation,
    representation: EvidenceRepresentation,
    key_registry: KeyRegistry,
    store_registry: StoreRegistry,
    verifier_registry: VerifierRegistry,
    status_store_registry: StatusStoreRegistry,
    permit_state: NeutralPermitStateSnapshot,
    max_clock_skew_seconds: int = 0,
) -> CommonGateInput:
    """Prepare one tagged, representation-blind gate input from a local view."""

    if type(observation) is not LocalObservation:
        raise GateError("common gate preparation requires an exact LocalObservation")
    if not isinstance(representation, EvidenceRepresentation):
        raise GateError("representation is unsupported")
    if not isinstance(key_registry, KeyRegistry):
        raise GateError("key_registry must be a KeyRegistry")
    if not isinstance(store_registry, StoreRegistry):
        raise GateError("store_registry must be a Sprint 2 StoreRegistry")
    if not isinstance(verifier_registry, VerifierRegistry):
        raise GateError("verifier_registry must be a VerifierRegistry")
    if not isinstance(status_store_registry, StatusStoreRegistry):
        raise GateError("status_store_registry must be a StatusStoreRegistry")
    if not isinstance(permit_state, NeutralPermitStateSnapshot):
        raise GateError("permit_state must be a NeutralPermitStateSnapshot")
    if permit_state.permit_store_id != observation.permit_store_id:
        raise GateError("neutral permit state belongs to another store")
    if permit_state.captured_at != observation.decision_time:
        raise GateError("neutral permit state was not captured at decision time")

    reasons: list[str] = []
    try:
        verifier_registry.resolve(
            verifier_id=observation.verifier_id,
            evidence_store_id=observation.evidence_store_id,
            permit_store_id=observation.permit_store_id,
        )
    except KeyError:
        reasons.append("VERIFIER_STORE_MISMATCH")
    if observation.permit_state.records or observation.permit_state.observations:
        reasons.append("LEGACY_PERMIT_STATE_NONEMPTY")

    report = validate_observation(
        observation,
        representation=representation,
        key_registry=key_registry,
        store_registry=store_registry,
        max_clock_skew_seconds=max_clock_skew_seconds,
    )
    reasons.extend(issue.reason_code for issue in report.issues)
    policy_views = tuple(item.policy_view() for item in report.validated_handoffs)

    statuses: list[AuthorityStatusEvidence] = []
    for message in observation.unique_evidence():
        if message.payload_kind is not PayloadKind.AUTHORITY_STATUS:
            continue
        try:
            status_id, status = _authenticate_status(
                message.payload,
                key_registry=key_registry,
            )
            status_store_registry.resolve(
                store_id=message.origin_store_id,
                issuer_principal_id=status["issuer_principal_id"],
            )
            statuses.append(
                AuthorityStatusEvidence(
                    message_id=message.message_id,
                    delivery_slot_id=message.delivery_slot_id,
                    origin_store_id=message.origin_store_id,
                    status_id=status_id,
                    signed_status_bytes=canonical_json(message.payload),
                )
            )
        except (GateError, KeyError, TypeError, ValueError):
            reasons.append("STATUS_INVALID")

    return CommonGateInput._from_preparer(
        verifier_id=observation.verifier_id,
        evidence_store_id=observation.evidence_store_id,
        permit_store_id=observation.permit_store_id,
        decision_time=observation.decision_time,
        policy_views=policy_views,
        authority_status_evidence=tuple(statuses),
        permit_state=permit_state,
        preparation_reasons=tuple(reasons),
        _preparation_token=_PREPARATION_TOKEN,
    )


def _scope_attenuated(parent: Mapping[str, Any], child: Mapping[str, Any]) -> bool:
    return (
        set(child["operations"]).issubset(parent["operations"])
        and set(child["resources"]).issubset(parent["resources"])
        and child["currency"] == parent["currency"]
        and child["max_amount_minor"] <= parent["max_amount_minor"]
        and parse_timestamp(child["not_before"], "scope.not_before")
        >= parse_timestamp(parent["not_before"], "scope.not_before")
        and parse_timestamp(child["not_after"], "scope.not_after")
        <= parse_timestamp(parent["not_after"], "scope.not_after")
        and child["redelegations_remaining"] < parent["redelegations_remaining"]
    )


def _action_within_scope(action: Mapping[str, Any], scope: Mapping[str, Any]) -> bool:
    return (
        action["operation"] in scope["operations"]
        and action["resource"] in scope["resources"]
        and action["currency"] == scope["currency"]
        and action["amount_minor"] <= scope["max_amount_minor"]
    )


@dataclass(frozen=True, slots=True)
class CommonGateEvaluation:
    verdict: str
    reasons: tuple[str, ...]
    action_id: str
    leaf_neutral_handoff_id: str | None = None
    neutral_chain_id: str | None = None
    controlling_status_id: str | None = None
    replay_scope_id: str | None = None
    permit_expires_at: str | None = None
    observations: tuple[NeutralObservationRecord, ...] = ()

    @property
    def allowed(self) -> bool:
        return self.verdict == "ALLOW"


class CommonActionGate:
    """Apply one policy to representation-blind prepared evidence."""

    def __init__(
        self,
        *,
        verifier_registry: VerifierRegistry,
        permit_store: NeutralPermitStore,
        permit_ttl_seconds: int = 60,
        max_clock_skew_seconds: int = 0,
    ) -> None:
        if not isinstance(verifier_registry, VerifierRegistry):
            raise GateError("verifier_registry must be a VerifierRegistry")
        if not isinstance(permit_store, NeutralPermitStore):
            raise GateError("permit_store must be a NeutralPermitStore")
        if type(permit_ttl_seconds) is not int or not 1 <= permit_ttl_seconds <= 300:
            raise GateError("permit_ttl_seconds must be between 1 and 300")
        if type(max_clock_skew_seconds) is not int or max_clock_skew_seconds < 0:
            raise GateError("max_clock_skew_seconds must be non-negative")
        try:
            clock_skew = timedelta(seconds=max_clock_skew_seconds)
        except OverflowError as exc:
            raise GateError("max_clock_skew_seconds exceeds datetime range") from exc
        self.verifier_registry = verifier_registry
        self.permit_store = permit_store
        self.permit_ttl_seconds = permit_ttl_seconds
        self.clock_skew = clock_skew

    @staticmethod
    def _pause(
        *,
        action_hash: str,
        reasons: Iterable[str],
        leaf_id: str | None = None,
        chain_id: str | None = None,
        status_id: str | None = None,
        replay_scope_id: str | None = None,
    ) -> CommonGateEvaluation:
        reason_tuple = tuple(sorted(set(reasons)))
        if not reason_tuple:
            reason_tuple = ("INTERNAL_ERROR",)
        return CommonGateEvaluation(
            verdict="PAUSE",
            reasons=reason_tuple,
            action_id=action_hash,
            leaf_neutral_handoff_id=leaf_id,
            neutral_chain_id=chain_id,
            controlling_status_id=status_id,
            replay_scope_id=replay_scope_id,
        )

    def evaluate(
        self,
        common_input: CommonGateInput,
        *,
        action: Mapping[str, Any],
        tool_id: str,
    ) -> CommonGateEvaluation:
        """Evaluate without mutating permit state."""

        if (
            type(common_input) is not CommonGateInput
            or not common_input.preparer_issued
        ):
            raise GateError("common_input must be issued directly by the preparer")
        try:
            action_hash = action_id(action)
            require_identifier(tool_id, "tool_id")
        except (ProtocolError, GateError, KeyError, TypeError, ValueError):
            return self._pause(
                action_hash=content_id("INVALID_ACTION", {}),
                reasons=("SCHEMA_INVALID",),
            )
        if self.permit_store.permit_store_id != common_input.permit_store_id:
            return self._pause(
                action_hash=action_hash,
                reasons=("VERIFIER_STORE_MISMATCH",),
            )
        try:
            self.verifier_registry.resolve(
                verifier_id=common_input.verifier_id,
                evidence_store_id=common_input.evidence_store_id,
                permit_store_id=common_input.permit_store_id,
            )
        except KeyError:
            return self._pause(
                action_hash=action_hash,
                reasons=("VERIFIER_STORE_MISMATCH",),
            )
        if not self.verifier_registry.tool_allowed(
            verifier_id=common_input.verifier_id,
            tool_id=tool_id,
        ):
            return self._pause(
                action_hash=action_hash,
                reasons=("TOOL_UNAUTHORISED",),
            )
        if common_input.preparation_reasons:
            return self._pause(
                action_hash=action_hash,
                reasons=common_input.preparation_reasons,
            )
        if not all(
            type(view) is PolicyView and view.validator_issued
            for view in common_input.policy_views
        ):
            raise GateError("common input contains an untrusted policy view")

        by_interaction: dict[str, list[PolicyView]] = {}
        matching_leaves: list[PolicyView] = []
        for view in common_input.policy_views:
            handoff = view.to_dict()["handoff"]
            by_interaction.setdefault(handoff["interaction_id"], []).append(view)
            if (
                handoff["event_type"] == "action_intent"
                and handoff["request_hash"] == action_hash
            ):
                matching_leaves.append(view)
        if not matching_leaves:
            return self._pause(action_hash=action_hash, reasons=("LEAF_MISSING",))
        if len(matching_leaves) != 1:
            return self._pause(action_hash=action_hash, reasons=("LEAF_AMBIGUOUS",))

        leaf = matching_leaves[0]
        leaf_body = leaf.to_dict()["handoff"]
        leaf_id = leaf_body and leaf.to_dict()["neutral_handoff_id"]
        reverse_chain: list[PolicyView] = []
        visited: set[str] = set()
        current = leaf
        chain_reasons: list[str] = []
        while True:
            body = current.to_dict()["handoff"]
            interaction_id = body["interaction_id"]
            if interaction_id in visited:
                chain_reasons.append("CHAIN_CYCLE")
                break
            visited.add(interaction_id)
            reverse_chain.append(current)
            previous = body["previous_interaction_id"]
            if previous is None:
                break
            parents = by_interaction.get(previous, [])
            if not parents:
                chain_reasons.append("PARENT_MISSING")
                break
            if len(parents) != 1:
                chain_reasons.append("CHAIN_AMBIGUOUS")
                break
            current = parents[0]
        chain = tuple(reversed(reverse_chain))
        chain_ids = tuple(view.to_dict()["neutral_handoff_id"] for view in chain)
        chain_id = content_id(
            "NEUTRAL_HANDOFF_CHAIN",
            {"neutral_handoff_ids": list(chain_ids)},
        )
        if chain_reasons:
            return self._pause(
                action_hash=action_hash,
                reasons=chain_reasons,
                leaf_id=leaf_id,
                chain_id=chain_id,
            )

        bodies = [view.to_dict()["handoff"] for view in chain]
        reasons: list[str] = []
        for view in chain:
            decision = evaluate_common_evidence_policy(view)
            reasons.extend(decision.reasons)
        if (
            bodies[0]["previous_interaction_id"] is not None
            or bodies[0]["event_type"] != "delegation"
        ):
            reasons.append("ROOT_NOT_DELEGATION")
        if bodies[-1]["event_type"] != "action_intent":
            reasons.append("LEAF_NOT_ACTION_INTENT")
        if any(body["event_type"] != "delegation" for body in bodies[1:-1]):
            reasons.append("INTERMEDIATE_NOT_DELEGATION")

        root_lineage = bodies[0]["authority_lineage"]
        root_version = bodies[0]["authority_version"]
        if (
            root_lineage["issuer_principal_id"] != bodies[0]["sender"]["principal_id"]
            or root_lineage["subject_principal_id"]
            != bodies[0]["receiver"]["principal_id"]
            or root_lineage["subject_key_id"] != bodies[0]["receiver"]["key_id"]
        ):
            reasons.append("ROOT_AUTHORITY_MISMATCH")
        if any(
            body["authority_lineage"] != root_lineage
            or body["authority_version"] != root_version
            for body in bodies[1:]
        ):
            reasons.append("AUTHORITY_CHAIN_MISMATCH")

        decision_time = common_input.decision_time
        for index, (view, body) in enumerate(zip(chain, bodies, strict=True)):
            created = parse_timestamp(body["created_at"], "created_at")
            decided = parse_timestamp(
                view.to_dict()["receiver_decided_at"],
                "receiver_decided_at",
            )
            if created > decision_time:
                reasons.append("NOT_YET_VALID")
            if decided < created or decided > decision_time:
                reasons.append("CAUSAL_TIME_INVALID")
            scope = body["scope"]
            not_before = parse_timestamp(scope["not_before"], "scope.not_before")
            not_after = parse_timestamp(scope["not_after"], "scope.not_after")
            if decision_time < not_before:
                reasons.append("NOT_YET_VALID")
            if decision_time >= not_after:
                reasons.append("EXPIRED")
            if index:
                parent_body = bodies[index - 1]
                parent_decided = parse_timestamp(
                    chain[index - 1].to_dict()["receiver_decided_at"],
                    "parent receiver_decided_at",
                )
                if parent_body["receiver"] != body["sender"]:
                    reasons.append("PARTY_CONTINUITY_BROKEN")
                if parent_decided > created + self.clock_skew:
                    reasons.append("CAUSAL_TIME_INVALID")
                if not _scope_attenuated(parent_body["scope"], scope):
                    reasons.append("SCOPE_EXPANSION")
        if bodies[-1]["request_hash"] != action_hash:
            reasons.append("REQUEST_HASH_MISMATCH")
        if any(not _action_within_scope(action, body["scope"]) for body in bodies):
            reasons.append("ACTION_OUT_OF_SCOPE")

        lineage_key = (
            root_lineage["issuer_principal_id"],
            root_lineage["subject_principal_id"],
            root_lineage["subject_key_id"],
        )
        relevant: list[tuple[str, Mapping[str, Any]]] = []
        for evidence in common_input.authority_status_evidence:
            status = evidence.signed_status["status"]
            status_lineage = (
                status["issuer_principal_id"],
                status["subject_principal_id"],
                status["subject_key_id"],
            )
            if status_lineage == lineage_key:
                relevant.append((evidence.status_id, status))
        controlling_status_id: str | None = None
        controlling_status: Mapping[str, Any] | None = None
        if not relevant:
            reasons.append("STATUS_MISSING")
        else:
            by_version: dict[int, dict[str, Mapping[str, Any]]] = {}
            for status_id, status in relevant:
                by_version.setdefault(status["authority_version"], {})[
                    status_id
                ] = status
            if any(len(candidates) != 1 for candidates in by_version.values()):
                reasons.append("STATUS_CONFLICT")
            highest_version = max(by_version)
            highest_candidates = by_version[highest_version]
            if len(highest_candidates) == 1:
                controlling_status_id, controlling_status = next(
                    iter(highest_candidates.items())
                )
                if highest_version > root_version:
                    reasons.append("AUTHORITY_VERSION_STALE")
                elif highest_version < root_version:
                    reasons.append("STATUS_MISSING")
                if any(
                    body["referenced_status_id"] != controlling_status_id
                    for body in bodies
                ):
                    reasons.append("REVOCATION_STATUS_STALE")
                if controlling_status["state"] == "REVOKED":
                    reasons.append("AUTHORITY_REVOKED")
                issued = parse_timestamp(
                    controlling_status["issued_at"],
                    "status.issued_at",
                )
                fresh_until = parse_timestamp(
                    controlling_status["fresh_until"],
                    "status.fresh_until",
                )
                if issued > decision_time:
                    reasons.append("STATUS_NOT_YET_VALID")
                if fresh_until <= decision_time:
                    reasons.append("STATUS_STALE")
                if any(
                    body["referenced_status_id"] == controlling_status_id
                    and issued > parse_timestamp(body["created_at"], "created_at")
                    for body in bodies
                ):
                    reasons.append("STATUS_CAUSAL_TIME_INVALID")

        replay_scope_id = content_id(
            "NEUTRAL_REPLAY_SCOPE",
            {
                "authority_lineage": root_lineage,
                "authority_version": root_version,
            },
        )
        if reasons or controlling_status is None or controlling_status_id is None:
            return self._pause(
                action_hash=action_hash,
                reasons=reasons,
                leaf_id=leaf_id,
                chain_id=chain_id,
                status_id=controlling_status_id,
                replay_scope_id=replay_scope_id,
            )

        try:
            ttl_expiry = decision_time + timedelta(seconds=self.permit_ttl_seconds)
        except OverflowError:
            return self._pause(
                action_hash=action_hash,
                reasons=("INTERNAL_ERROR",),
                leaf_id=leaf_id,
                chain_id=chain_id,
                status_id=controlling_status_id,
                replay_scope_id=replay_scope_id,
            )
        expiry = min(
            ttl_expiry,
            parse_timestamp(controlling_status["fresh_until"], "status.fresh_until"),
            *(
                parse_timestamp(body["scope"]["not_after"], "scope.not_after")
                for body in bodies
            ),
        )
        if expiry <= decision_time:
            return self._pause(
                action_hash=action_hash,
                reasons=("EXPIRED",),
                leaf_id=leaf_id,
                chain_id=chain_id,
                status_id=controlling_status_id,
                replay_scope_id=replay_scope_id,
            )
        observations: list[NeutralObservationRecord] = []
        for view, body in zip(chain, bodies, strict=True):
            neutral_id = view.to_dict()["neutral_handoff_id"]
            observations.append(
                NeutralObservationRecord(
                    observation_kind=ObservationKind.INTERACTION,
                    observation_key=content_id(
                        "NEUTRAL_INTERACTION_KEY",
                        {"interaction_id": body["interaction_id"]},
                    ),
                    neutral_handoff_id=neutral_id,
                )
            )
            observations.append(
                NeutralObservationRecord(
                    observation_kind=ObservationKind.SENDER_SEQUENCE,
                    observation_key=content_id(
                        "NEUTRAL_SENDER_SEQUENCE_KEY",
                        {
                            "principal_id": body["sender"]["principal_id"],
                            "key_id": body["sender"]["key_id"],
                            "sender_sequence": body["sender_sequence"],
                        },
                    ),
                    neutral_handoff_id=neutral_id,
                )
            )
        return CommonGateEvaluation(
            verdict="ALLOW",
            reasons=(),
            action_id=action_hash,
            leaf_neutral_handoff_id=leaf_id,
            neutral_chain_id=chain_id,
            controlling_status_id=controlling_status_id,
            replay_scope_id=replay_scope_id,
            permit_expires_at=format_timestamp(expiry),
            observations=tuple(observations),
        )

    def authorize(
        self,
        common_input: CommonGateInput,
        *,
        action: Mapping[str, Any],
        tool_id: str,
    ) -> CommonGateDecision:
        """Evaluate and atomically reserve one neutral permit when eligible."""

        if (
            type(common_input) is not CommonGateInput
            or not common_input.preparer_issued
        ):
            raise GateError("common_input must be issued directly by the preparer")
        try:
            evaluation = self.evaluate(common_input, action=action, tool_id=tool_id)
        except Exception:
            try:
                failed_action_id = action_id(action)
            except Exception:
                failed_action_id = content_id("INVALID_ACTION", {})
            return CommonGateDecision.make(
                verdict="PAUSE",
                reasons=("INTERNAL_ERROR",),
                action_id=failed_action_id,
            )
        if not evaluation.allowed:
            return CommonGateDecision.make(
                verdict="PAUSE",
                reasons=evaluation.reasons,
                action_id=evaluation.action_id,
                leaf_neutral_handoff_id=evaluation.leaf_neutral_handoff_id,
                neutral_chain_id=evaluation.neutral_chain_id,
                controlling_status_id=evaluation.controlling_status_id,
                replay_scope_id=evaluation.replay_scope_id,
            )
        assert evaluation.leaf_neutral_handoff_id is not None
        assert evaluation.neutral_chain_id is not None
        assert evaluation.controlling_status_id is not None
        assert evaluation.replay_scope_id is not None
        assert evaluation.permit_expires_at is not None
        try:
            permit = self.permit_store.reserve(
                expected_revision=common_input.permit_state.revision,
                observations=evaluation.observations,
                leaf_neutral_handoff_id=evaluation.leaf_neutral_handoff_id,
                neutral_chain_id=evaluation.neutral_chain_id,
                controlling_status_id=evaluation.controlling_status_id,
                replay_scope_id=evaluation.replay_scope_id,
                request_hash=evaluation.action_id,
                action_nonce=action["action_nonce"],
                tool_id=tool_id,
                issued_at=common_input.decision_time,
                expires_at=parse_timestamp(
                    evaluation.permit_expires_at,
                    "permit_expires_at",
                ),
            )
        except EvidenceConflict:
            reason = "CONFLICTING_HANDOFF"
        except ReplayDetected:
            reason = "REPLAY_DETECTED"
        except StateChanged:
            reason = "STATE_CHANGED"
        except (sqlite3.Error, OSError):
            reason = "STATE_UNAVAILABLE"
        except Exception:
            reason = "INTERNAL_ERROR"
        else:
            return CommonGateDecision.make(
                verdict="ALLOW",
                reasons=(),
                action_id=evaluation.action_id,
                leaf_neutral_handoff_id=evaluation.leaf_neutral_handoff_id,
                neutral_chain_id=evaluation.neutral_chain_id,
                controlling_status_id=evaluation.controlling_status_id,
                replay_scope_id=evaluation.replay_scope_id,
                permit_id=permit.permit_id,
                permit_expires_at=evaluation.permit_expires_at,
            )
        return CommonGateDecision.make(
            verdict="PAUSE",
            reasons=(reason,),
            action_id=evaluation.action_id,
            leaf_neutral_handoff_id=evaluation.leaf_neutral_handoff_id,
            neutral_chain_id=evaluation.neutral_chain_id,
            controlling_status_id=evaluation.controlling_status_id,
            replay_scope_id=evaluation.replay_scope_id,
        )

    def consume(
        self,
        *,
        permit_id: str,
        action: Mapping[str, Any],
        tool_id: str,
        now: datetime,
    ) -> PermitTransitionResult:
        """Consume one reserved permit before the adapter acts."""

        require_identifier(permit_id, "permit_id")
        if type(now) is not datetime or now.tzinfo is None or now.microsecond:
            return PermitTransitionResult(
                "PAUSE",
                "PERMIT_TIME_INVALID",
                permit_id,
            )
        try:
            request_hash = action_id(action)
            return self.permit_store.consume(
                permit_id=permit_id,
                tool_id=tool_id,
                request_hash=request_hash,
                action_nonce=action["action_nonce"],
                now=now.astimezone(UTC),
            )
        except (ProtocolError, GateError, KeyError, TypeError, ValueError):
            return PermitTransitionResult(
                "PAUSE",
                "PERMIT_ACTION_MISMATCH",
                permit_id,
            )
        except (sqlite3.Error, OSError):
            return PermitTransitionResult("PAUSE", "STATE_UNAVAILABLE", permit_id)
        except Exception:
            return PermitTransitionResult("PAUSE", "INTERNAL_ERROR", permit_id)

    def finish(self, *, permit_id: str, succeeded: bool) -> bool:
        """Record the adapter outcome once; state failure returns ``False``."""

        try:
            return self.permit_store.finish(permit_id=permit_id, succeeded=succeeded)
        except (GateError, sqlite3.Error, OSError):
            return False


__all__ = [
    "CommonActionGate",
    "CommonGateEvaluation",
    "StatusStoreRegistry",
    "VerifierRegistry",
    "prepare_common_gate_input",
]
