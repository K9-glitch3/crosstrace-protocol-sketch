"""Strict internal models for the deterministic Sprint 4 harness."""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import Enum
from typing import Any, Mapping

from crosstrace_sketch.protocol import canonical_json, content_id
from preaward.crosstrace_sprint1.delivery import (
    AuditObservation,
    DeliverySchedule,
    LocalObservation,
)
from preaward.crosstrace_sprint2.model import EvidenceRepresentation, NeutralHandoff

HARNESS_VERSION = "crosstrace-six-cell/0.1"
FIXTURE_VERSION = "crosstrace-six-cell-fixtures/0.1"
RELEASE_ID = "crosstrace-six-cell-development-v0.1"
CLAIM_LEVEL = "PREAWARD_DEVELOPMENT_CONFORMANCE"

_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$")


class HarnessError(ValueError):
    """Raised when a harness object violates the frozen development profile."""


class Enforcement(str, Enum):
    AUDIT = "AUDIT"
    GATE = "GATE"


@dataclass(frozen=True, slots=True)
class CellSpec:
    cell_id: str
    representation: EvidenceRepresentation
    enforcement: Enforcement

    def __post_init__(self) -> None:
        _identifier(self.cell_id, "cell_id")
        expected = f"{self.representation.value}-{self.enforcement.value}"
        if self.cell_id != expected:
            raise HarnessError(f"cell_id must equal {expected}")

    def to_dict(self) -> dict[str, str]:
        return {
            "cell_id": self.cell_id,
            "representation": self.representation.value,
            "enforcement": self.enforcement.value,
        }


@dataclass(frozen=True, slots=True)
class FixtureConfig:
    case_id: str
    opaque_trace_id: str
    delivery_mode: str
    authority_mode: str
    action_mode: str
    attempt_count: int
    conflicting_leaf: bool

    @classmethod
    def from_dict(cls, value: Any) -> FixtureConfig:
        fields = _exact(
            value,
            {
                "case_id",
                "opaque_trace_id",
                "delivery_mode",
                "authority_mode",
                "action_mode",
                "attempt_count",
                "conflicting_leaf",
            },
            "fixture case",
        )
        case_id = _identifier(fields["case_id"], "case_id")
        opaque_trace_id = _identifier(fields["opaque_trace_id"], "opaque_trace_id")
        delivery_mode = fields["delivery_mode"]
        if delivery_mode not in {
            "COMPLETE",
            "WITHHOLD_LEAF_RECEIVER_LOCAL",
            "WITHHOLD_BOTH_LEAF_LOCAL",
            "DELAY_ACTIVE_STATUS_LOCAL",
        }:
            raise HarnessError("delivery_mode is unsupported")
        authority_mode = fields["authority_mode"]
        if authority_mode not in {"ACTIVE_ONLY", "ACTIVE_AND_HIGHER_REVOKED"}:
            raise HarnessError("authority_mode is unsupported")
        action_mode = fields["action_mode"]
        if action_mode not in {"IN_SCOPE", "OUT_OF_SCOPE"}:
            raise HarnessError("action_mode is unsupported")
        attempt_count = fields["attempt_count"]
        if type(attempt_count) is not int or attempt_count not in {1, 2}:
            raise HarnessError("attempt_count must be 1 or 2")
        conflicting_leaf = fields["conflicting_leaf"]
        if type(conflicting_leaf) is not bool:
            raise HarnessError("conflicting_leaf must be boolean")
        if (attempt_count == 2) != (case_id == "replay"):
            raise HarnessError("only the replay fixture may contain two attempts")
        return cls(
            case_id=case_id,
            opaque_trace_id=opaque_trace_id,
            delivery_mode=delivery_mode,
            authority_mode=authority_mode,
            action_mode=action_mode,
            attempt_count=attempt_count,
            conflicting_leaf=conflicting_leaf,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "opaque_trace_id": self.opaque_trace_id,
            "delivery_mode": self.delivery_mode,
            "authority_mode": self.authority_mode,
            "action_mode": self.action_mode,
            "attempt_count": self.attempt_count,
            "conflicting_leaf": self.conflicting_leaf,
        }


class DestinationKind(str, Enum):
    LOCAL = "LOCAL"
    AUDIT = "AUDIT"


class HolderRole(str, Enum):
    SENDER = "SENDER"
    RECEIVER = "RECEIVER"
    AUTHORITY = "AUTHORITY"


@dataclass(frozen=True, slots=True)
class SlotAssignment:
    slot_id: str
    semantic_item_id: str
    holder_role: HolderRole
    origin_store_id: str
    destination_kind: DestinationKind
    destination_store_id: str
    sent_at: datetime

    def __post_init__(self) -> None:
        for field_name in (
            "slot_id",
            "semantic_item_id",
            "origin_store_id",
            "destination_store_id",
        ):
            _identifier(getattr(self, field_name), field_name)
        if not isinstance(self.holder_role, HolderRole):
            raise HarnessError("holder_role must be a HolderRole")
        if not isinstance(self.destination_kind, DestinationKind):
            raise HarnessError("destination_kind must be a DestinationKind")
        sent_at = _utc_second(self.sent_at, "sent_at")
        object.__setattr__(self, "sent_at", sent_at)

    def to_dict(self) -> dict[str, str]:
        return {
            "slot_id": self.slot_id,
            "semantic_item_id": self.semantic_item_id,
            "holder_role": self.holder_role.value,
            "origin_store_id": self.origin_store_id,
            "destination_kind": self.destination_kind.value,
            "destination_store_id": self.destination_store_id,
            "sent_at": format_time(self.sent_at),
        }


@dataclass(frozen=True, slots=True)
class RepresentationBundle:
    case_id: str
    representation: EvidenceRepresentation
    neutral_trace_hash: str
    action_hash: str
    slot_manifest_hash: str
    transport_projection_hash: str
    bundle_id: str
    neutral_handoffs: tuple[NeutralHandoff, ...]
    slot_assignments: tuple[SlotAssignment, ...]
    schedule: DeliverySchedule
    local_observation: LocalObservation
    audit_observation: AuditObservation
    transport_projection: tuple[dict[str, Any], ...]
    endpoint_sender_bytes: tuple[bytes, ...]
    pr_copy_pairs_equal: bool | None

    def __post_init__(self) -> None:
        _identifier(self.case_id, "case_id")
        if not isinstance(self.representation, EvidenceRepresentation):
            raise HarnessError("representation is unsupported")
        for name in (
            "neutral_trace_hash",
            "action_hash",
            "slot_manifest_hash",
            "transport_projection_hash",
            "bundle_id",
        ):
            _sha256(getattr(self, name), name)
        if not self.neutral_handoffs or not all(
            isinstance(item, NeutralHandoff) for item in self.neutral_handoffs
        ):
            raise HarnessError(
                "neutral_handoffs must be non-empty NeutralHandoff values"
            )
        if not self.slot_assignments or not all(
            isinstance(item, SlotAssignment) for item in self.slot_assignments
        ):
            raise HarnessError(
                "slot_assignments must be non-empty SlotAssignment values"
            )
        if not isinstance(self.schedule, DeliverySchedule):
            raise HarnessError("schedule must be a DeliverySchedule")
        if not isinstance(self.local_observation, LocalObservation):
            raise HarnessError("local_observation must be a LocalObservation")
        if not isinstance(self.audit_observation, AuditObservation):
            raise HarnessError("audit_observation must be an AuditObservation")

    def to_release_dict(self) -> dict[str, Any]:
        return {
            "version": HARNESS_VERSION,
            "bundle_id": self.bundle_id,
            "case_id": self.case_id,
            "representation": self.representation.value,
            "neutral_trace_hash": self.neutral_trace_hash,
            "action_hash": self.action_hash,
            "slot_manifest_hash": self.slot_manifest_hash,
            "transport_projection_hash": self.transport_projection_hash,
            "neutral_handoff_ids": [
                handoff.neutral_handoff_id for handoff in self.neutral_handoffs
            ],
            "slot_assignments": [item.to_dict() for item in self.slot_assignments],
            "transport_projection": list(self.transport_projection),
            "schedule": self.schedule.to_dict(),
            "local_observation": self.local_observation.to_dict(),
            "audit_observation": self.audit_observation.to_dict(),
            "endpoint_sender_bytes_b64": [
                _b64url(item) for item in self.endpoint_sender_bytes
            ],
            "pr_copy_pairs_equal": self.pr_copy_pairs_equal,
        }


def _exact(value: Any, expected: set[str], name: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or not all(isinstance(key, str) for key in value):
        raise HarnessError(f"{name} must be an object with string keys")
    actual = set(value)
    if actual != expected:
        raise HarnessError(
            f"{name} fields mismatch; missing={sorted(expected-actual)}, "
            f"extra={sorted(actual-expected)}"
        )
    return value


def _identifier(value: Any, name: str) -> str:
    if not isinstance(value, str) or not _ID_RE.fullmatch(value):
        raise HarnessError(f"{name} must be a bounded ASCII identifier")
    return value


def _sha256(value: Any, name: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", value):
        raise HarnessError(f"{name} must be a sha256 identifier")
    return value


def _utc_second(value: Any, name: str) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise HarnessError(f"{name} must be timezone-aware")
    normal = value.astimezone(UTC)
    if normal.microsecond:
        raise HarnessError(f"{name} must use whole-second precision")
    return normal


def format_time(value: datetime) -> str:
    return _utc_second(value, "timestamp").strftime("%Y-%m-%dT%H:%M:%SZ")


def object_hash(label: str, value: Mapping[str, Any] | list[Any]) -> str:
    return content_id(label, value)


def canonical_size(value: Mapping[str, Any] | list[Any]) -> int:
    return len(canonical_json(value))


def _b64url(value: bytes) -> str:
    import base64

    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


CELL_SPECS = tuple(
    CellSpec(f"{representation.value}-{enforcement.value}", representation, enforcement)
    for representation in (
        EvidenceRepresentation.SL,
        EvidenceRepresentation.CR,
        EvidenceRepresentation.PR,
    )
    for enforcement in (Enforcement.AUDIT, Enforcement.GATE)
)
