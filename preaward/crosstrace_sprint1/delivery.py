"""Deterministic evidence delivery with bounded local projections.

This module is development-only Sprint 1 infrastructure.  It models transport;
it does not validate evidence, resolve authority status, consult an oracle, or
make an action decision.  Global schedules remain evaluator-side.  A gate or
auditor receives only a frozen projection of messages delivered to its own
inbox by a declared cutoff.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import Enum
from typing import Any, Iterable, Mapping, Sequence

from crosstrace_sketch.protocol import canonical_json, content_id, loads_strict


DELIVERY_VERSION = "crosstrace-delivery/0.1"
MAX_PROFILE_SECONDS = 31_536_000
_DRAW_DOMAIN = b"CROSSTRACE-DELIVERY-DRAW\x00"
_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$")
_HASH_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_B64URL_RE = re.compile(r"^[A-Za-z0-9_-]+$")
_TIMESTAMP_RE = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$"
)
_RESERVED_EVALUATOR_FIELDS = frozenset(
    {
        "conditionlabel",
        "deliveryseed",
        "expected_fault",
        "expectedfault",
        "fault_label",
        "faultlabel",
        "groundtruth",
        "oracle",
        "oraclelabel",
        "oracle_authorised",
        "oracleauthorised",
        "oracle_graph",
        "oraclegraph",
        "oracle_path",
        "oraclepath",
        "oracle_paths",
        "oraclepaths",
        "oracle_unauthorised",
        "oracleunauthorised",
        "scenario",
        "scenario_label",
        "scenariolabel",
        "scheduleid",
        "treatmentassignment",
    }
)


class DeliveryError(ValueError):
    """Raised when a delivery object is outside the Sprint 1 profile."""


class PayloadKind(str, Enum):
    AUTHORITY_STATUS = "AUTHORITY_STATUS"
    RECEIPT = "RECEIPT"
    SIGNED_ENDPOINT_RECORD = "SIGNED_ENDPOINT_RECORD"
    CROSS_REFERENCED_RECORD = "CROSS_REFERENCED_RECORD"
    PROTOCOL_SIGNAL = "PROTOCOL_SIGNAL"


class Disposition(str, Enum):
    DELIVER = "DELIVER"
    LOST = "LOST"
    WITHHELD = "WITHHELD"


class PermitLifecycle(str, Enum):
    RESERVED = "RESERVED"
    ATTEMPTED = "ATTEMPTED"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"


def _require_identifier(value: Any, name: str) -> str:
    if not isinstance(value, str) or not _ID_RE.fullmatch(value):
        raise DeliveryError(f"{name} must be a bounded ASCII identifier")
    return value


def _require_hash(value: Any, name: str) -> str:
    if not isinstance(value, str) or not _HASH_RE.fullmatch(value):
        raise DeliveryError(f"{name} must be a sha256 identifier")
    return value


def _utc_second(value: datetime, name: str) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise DeliveryError(f"{name} must be timezone-aware")
    normalised = value.astimezone(UTC)
    if normalised.microsecond:
        raise DeliveryError(f"{name} must use whole-second precision")
    return normalised


def _format_time(value: datetime) -> str:
    return value.strftime("%Y-%m-%dT%H:%M:%SZ")


def _encode_bytes(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _decode_bytes(value: Any, name: str) -> bytes:
    if not isinstance(value, str) or not _B64URL_RE.fullmatch(value):
        raise DeliveryError(f"{name} must be non-empty unpadded base64url")
    padding = "=" * (-len(value) % 4)
    try:
        decoded = base64.b64decode(value + padding, altchars=b"-_", validate=True)
    except (ValueError, binascii.Error) as exc:
        raise DeliveryError(f"{name} must be valid unpadded base64url") from exc
    if _encode_bytes(decoded) != value:
        raise DeliveryError(f"{name} must use canonical unpadded base64url")
    return decoded


def _parse_timestamp(value: Any, name: str) -> datetime:
    if not isinstance(value, str) or not _TIMESTAMP_RE.fullmatch(value):
        raise DeliveryError(f"{name} must be a whole-second UTC timestamp")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError as exc:
        raise DeliveryError(f"{name} must be a valid UTC timestamp") from exc
    if _format_time(parsed) != value:
        raise DeliveryError(f"{name} must use canonical UTC timestamp encoding")
    return parsed


def _require_object_fields(
    value: Any,
    name: str,
    expected_fields: frozenset[str],
) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise DeliveryError(f"{name} must be an object")
    if not all(isinstance(key, str) for key in value):
        raise DeliveryError(f"{name} contains a non-string key")
    actual_fields = frozenset(value)
    if actual_fields != expected_fields:
        missing = sorted(expected_fields - actual_fields)
        extra = sorted(actual_fields - expected_fields)
        raise DeliveryError(f"{name} fields mismatch; missing={missing}, extra={extra}")
    return value


def _require_array(value: Any, name: str) -> list[Any]:
    if not isinstance(value, list):
        raise DeliveryError(f"{name} must be an array")
    return value


def _require_int(
    value: Any,
    name: str,
    *,
    minimum: int = 0,
    maximum: int | None = None,
) -> int:
    if type(value) is not int or value < minimum or (
        maximum is not None and value > maximum
    ):
        upper = "" if maximum is None else f" and at most {maximum}"
        raise DeliveryError(f"{name} must be an integer at least {minimum}{upper}")
    return value


def _require_version(value: Any) -> None:
    if value != DELIVERY_VERSION:
        raise DeliveryError(f"version must equal {DELIVERY_VERSION}")


def _decode_canonical_object(raw: Any, name: str) -> Mapping[str, Any]:
    if not isinstance(raw, bytes):
        raise DeliveryError(f"{name} must be bytes")
    try:
        value = loads_strict(raw)
        encoded = canonical_json(value)
    except ValueError as exc:
        raise DeliveryError(f"{name} must be canonical-profile JSON") from exc
    if not isinstance(value, dict):
        raise DeliveryError(f"{name} must encode an object")
    if encoded != raw:
        raise DeliveryError(f"{name} must use canonical JSON encoding")
    return value


def _payload_hash(payload_bytes: bytes) -> str:
    return "sha256:" + hashlib.sha256(payload_bytes).hexdigest()


def _reject_reserved_evaluator_fields(value: Any, path: str = "$") -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            if not isinstance(key, str):
                raise DeliveryError(f"{path} contains a non-string object key")
            normalised_key = re.sub(r"[^a-z0-9]", "", key.casefold())
            if (
                key.casefold() in _RESERVED_EVALUATOR_FIELDS
                or normalised_key in _RESERVED_EVALUATOR_FIELDS
                or normalised_key.startswith(("oracle", "scenario"))
                or normalised_key.endswith("groundtruth")
            ):
                raise DeliveryError(f"{path}.{key} is evaluator-only")
            _reject_reserved_evaluator_fields(child, f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _reject_reserved_evaluator_fields(child, f"{path}[{index}]")


def _message_identity_body(
    *,
    delivery_slot_id: str,
    origin_store_id: str,
    destination_store_id: str,
    sent_at: datetime,
    payload_kind: PayloadKind,
    payload_hash: str,
) -> dict[str, Any]:
    return {
        "version": DELIVERY_VERSION,
        "delivery_slot_id": delivery_slot_id,
        "origin_store_id": origin_store_id,
        "destination_store_id": destination_store_id,
        "sent_at": _format_time(sent_at),
        "payload_kind": payload_kind.value,
        "payload_hash": payload_hash,
    }


@dataclass(frozen=True, slots=True)
class EvidenceMessage:
    """One logical exact-byte message addressed to one evidence store."""

    message_id: str
    delivery_slot_id: str
    origin_store_id: str
    destination_store_id: str
    sent_at: datetime
    payload_kind: PayloadKind
    payload_hash: str
    payload_bytes: bytes

    def __post_init__(self) -> None:
        _require_hash(self.message_id, "message_id")
        _require_identifier(self.delivery_slot_id, "delivery_slot_id")
        _require_identifier(self.origin_store_id, "origin_store_id")
        _require_identifier(self.destination_store_id, "destination_store_id")
        sent_at = _utc_second(self.sent_at, "sent_at")
        object.__setattr__(self, "sent_at", sent_at)
        if not isinstance(self.payload_kind, PayloadKind):
            raise DeliveryError("payload_kind must be a PayloadKind")
        if not isinstance(self.payload_bytes, bytes):
            raise DeliveryError("payload_bytes must be bytes")
        _require_hash(self.payload_hash, "payload_hash")
        if _payload_hash(self.payload_bytes) != self.payload_hash:
            raise DeliveryError("payload_hash does not match payload_bytes")
        try:
            payload = loads_strict(self.payload_bytes)
        except ValueError as exc:
            raise DeliveryError("payload_bytes must be canonical-profile JSON") from exc
        if not isinstance(payload, dict):
            raise DeliveryError("evidence payload must be a JSON object")
        if canonical_json(payload) != self.payload_bytes:
            raise DeliveryError("payload_bytes must use canonical encoding")
        _reject_reserved_evaluator_fields(payload)
        expected_id = content_id(
            "EVIDENCE_MESSAGE",
            _message_identity_body(
                delivery_slot_id=self.delivery_slot_id,
                origin_store_id=self.origin_store_id,
                destination_store_id=self.destination_store_id,
                sent_at=sent_at,
                payload_kind=self.payload_kind,
                payload_hash=self.payload_hash,
            ),
        )
        if self.message_id != expected_id:
            raise DeliveryError("message_id does not match message fields")

    @property
    def payload(self) -> dict[str, Any]:
        value = loads_strict(self.payload_bytes)
        assert isinstance(value, dict)
        return value

    @classmethod
    def from_dict(cls, value: Any) -> EvidenceMessage:
        """Strictly decode and verify a serialized evidence message."""

        fields = _require_object_fields(
            value,
            "evidence message",
            frozenset(
                {
                    "version",
                    "message_id",
                    "delivery_slot_id",
                    "origin_store_id",
                    "destination_store_id",
                    "sent_at",
                    "payload_kind",
                    "payload_hash",
                    "payload_b64",
                    "payload_size_bytes",
                }
            ),
        )
        _require_version(fields["version"])
        payload_bytes = _decode_bytes(fields["payload_b64"], "payload_b64")
        payload_size = _require_int(
            fields["payload_size_bytes"],
            "payload_size_bytes",
            minimum=2,
        )
        if len(payload_bytes) != payload_size:
            raise DeliveryError("payload_size_bytes does not match payload_b64")
        try:
            payload_kind = PayloadKind(fields["payload_kind"])
        except (TypeError, ValueError) as exc:
            raise DeliveryError("payload_kind is not supported") from exc
        return cls(
            message_id=fields["message_id"],
            delivery_slot_id=fields["delivery_slot_id"],
            origin_store_id=fields["origin_store_id"],
            destination_store_id=fields["destination_store_id"],
            sent_at=_parse_timestamp(fields["sent_at"], "sent_at"),
            payload_kind=payload_kind,
            payload_hash=fields["payload_hash"],
            payload_bytes=payload_bytes,
        )

    @classmethod
    def from_bytes(cls, raw: Any) -> EvidenceMessage:
        parsed = cls.from_dict(_decode_canonical_object(raw, "evidence message"))
        if parsed.canonical_bytes != raw:
            raise DeliveryError("evidence message object order is not canonical")
        return parsed

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": DELIVERY_VERSION,
            "message_id": self.message_id,
            "delivery_slot_id": self.delivery_slot_id,
            "origin_store_id": self.origin_store_id,
            "destination_store_id": self.destination_store_id,
            "sent_at": _format_time(self.sent_at),
            "payload_kind": self.payload_kind.value,
            "payload_hash": self.payload_hash,
            "payload_b64": _encode_bytes(self.payload_bytes),
            "payload_size_bytes": len(self.payload_bytes),
        }

    @property
    def canonical_bytes(self) -> bytes:
        return canonical_json(self.to_dict())


def make_evidence_message(
    *,
    delivery_slot_id: str,
    origin_store_id: str,
    destination_store_id: str,
    sent_at: datetime,
    payload_kind: PayloadKind,
    payload: Mapping[str, Any],
) -> EvidenceMessage:
    """Canonicalise a structured payload and bind its transport identity."""

    _require_identifier(delivery_slot_id, "delivery_slot_id")
    _require_identifier(origin_store_id, "origin_store_id")
    _require_identifier(destination_store_id, "destination_store_id")
    sent_at = _utc_second(sent_at, "sent_at")
    if not isinstance(payload_kind, PayloadKind):
        raise DeliveryError("payload_kind must be a PayloadKind")
    if not isinstance(payload, Mapping):
        raise DeliveryError("payload must be a mapping")
    payload_dict = dict(payload)
    _reject_reserved_evaluator_fields(payload_dict)
    try:
        payload_bytes = canonical_json(payload_dict)
    except ValueError as exc:
        raise DeliveryError("payload must use canonical-profile JSON values") from exc
    payload_hash = _payload_hash(payload_bytes)
    message_id = content_id(
        "EVIDENCE_MESSAGE",
        _message_identity_body(
            delivery_slot_id=delivery_slot_id,
            origin_store_id=origin_store_id,
            destination_store_id=destination_store_id,
            sent_at=sent_at,
            payload_kind=payload_kind,
            payload_hash=payload_hash,
        ),
    )
    return EvidenceMessage(
        message_id=message_id,
        delivery_slot_id=delivery_slot_id,
        origin_store_id=origin_store_id,
        destination_store_id=destination_store_id,
        sent_at=sent_at,
        payload_kind=payload_kind,
        payload_hash=payload_hash,
        payload_bytes=payload_bytes,
    )


@dataclass(frozen=True, slots=True)
class PartitionWindow:
    """Directional half-open partition that buffers until its end time."""

    partition_id: str
    origin_store_id: str
    destination_store_id: str
    starts_at: datetime
    ends_at: datetime

    def __post_init__(self) -> None:
        _require_identifier(self.partition_id, "partition_id")
        _require_identifier(self.origin_store_id, "origin_store_id")
        _require_identifier(self.destination_store_id, "destination_store_id")
        starts_at = _utc_second(self.starts_at, "starts_at")
        ends_at = _utc_second(self.ends_at, "ends_at")
        if starts_at >= ends_at:
            raise DeliveryError("partition starts_at must precede ends_at")
        object.__setattr__(self, "starts_at", starts_at)
        object.__setattr__(self, "ends_at", ends_at)

    def matches(self, message: EvidenceMessage, candidate: datetime) -> bool:
        return (
            self.origin_store_id == message.origin_store_id
            and self.destination_store_id == message.destination_store_id
            and self.starts_at <= candidate < self.ends_at
        )

    @classmethod
    def from_dict(cls, value: Any) -> PartitionWindow:
        fields = _require_object_fields(
            value,
            "partition",
            frozenset(
                {
                    "partition_id",
                    "origin_store_id",
                    "destination_store_id",
                    "starts_at",
                    "ends_at",
                    "behaviour",
                }
            ),
        )
        if fields["behaviour"] != "BUFFER_UNTIL_END":
            raise DeliveryError("partition behaviour must be BUFFER_UNTIL_END")
        return cls(
            partition_id=fields["partition_id"],
            origin_store_id=fields["origin_store_id"],
            destination_store_id=fields["destination_store_id"],
            starts_at=_parse_timestamp(fields["starts_at"], "partition.starts_at"),
            ends_at=_parse_timestamp(fields["ends_at"], "partition.ends_at"),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "partition_id": self.partition_id,
            "origin_store_id": self.origin_store_id,
            "destination_store_id": self.destination_store_id,
            "starts_at": _format_time(self.starts_at),
            "ends_at": _format_time(self.ends_at),
            "behaviour": "BUFFER_UNTIL_END",
        }


@dataclass(frozen=True, slots=True)
class DeliveryPolicy:
    """Frozen hash-derived delivery policy; rates use parts per million."""

    min_delay_seconds: int = 0
    max_delay_seconds: int = 0
    loss_rate_ppm: int = 0
    duplicate_rate_ppm: int = 0
    partitions: tuple[PartitionWindow, ...] = ()
    withheld_delivery_slot_ids: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.partitions, tuple):
            raise DeliveryError("partitions must be a tuple")
        if not isinstance(self.withheld_delivery_slot_ids, tuple):
            raise DeliveryError("withheld_delivery_slot_ids must be a tuple")
        for name in ("min_delay_seconds", "max_delay_seconds"):
            value = getattr(self, name)
            if type(value) is not int or not 0 <= value <= MAX_PROFILE_SECONDS:
                raise DeliveryError(
                    f"{name} must be between 0 and {MAX_PROFILE_SECONDS}"
                )
        if self.min_delay_seconds > self.max_delay_seconds:
            raise DeliveryError("min_delay_seconds cannot exceed max_delay_seconds")
        for name in ("loss_rate_ppm", "duplicate_rate_ppm"):
            value = getattr(self, name)
            if type(value) is not int or not 0 <= value <= 1_000_000:
                raise DeliveryError(f"{name} must be between 0 and 1000000")
        if not all(isinstance(item, PartitionWindow) for item in self.partitions):
            raise DeliveryError("partitions must contain PartitionWindow objects")
        partitions = tuple(sorted(self.partitions, key=lambda item: item.partition_id))
        if len({item.partition_id for item in partitions}) != len(partitions):
            raise DeliveryError("partition_id values must be unique")
        withheld = tuple(sorted(set(self.withheld_delivery_slot_ids)))
        for delivery_slot_id in withheld:
            _require_identifier(delivery_slot_id, "withheld_delivery_slot_ids entry")
        object.__setattr__(self, "partitions", partitions)
        object.__setattr__(self, "withheld_delivery_slot_ids", withheld)

    @classmethod
    def from_dict(cls, value: Any) -> DeliveryPolicy:
        fields = _require_object_fields(
            value,
            "delivery policy",
            frozenset(
                {
                    "min_delay_seconds",
                    "max_delay_seconds",
                    "loss_rate_ppm",
                    "duplicate_rate_ppm",
                    "partitions",
                    "withheld_delivery_slot_ids",
                }
            ),
        )
        partitions = tuple(
            PartitionWindow.from_dict(item)
            for item in _require_array(fields["partitions"], "policy.partitions")
        )
        withheld = _require_array(
            fields["withheld_delivery_slot_ids"],
            "policy.withheld_delivery_slot_ids",
        )
        if not all(isinstance(item, str) for item in withheld):
            raise DeliveryError("withheld_delivery_slot_ids entries must be strings")
        if len(set(withheld)) != len(withheld):
            raise DeliveryError("withheld_delivery_slot_ids entries must be unique")
        return cls(
            min_delay_seconds=_require_int(
                fields["min_delay_seconds"],
                "min_delay_seconds",
                maximum=MAX_PROFILE_SECONDS,
            ),
            max_delay_seconds=_require_int(
                fields["max_delay_seconds"],
                "max_delay_seconds",
                maximum=MAX_PROFILE_SECONDS,
            ),
            loss_rate_ppm=_require_int(fields["loss_rate_ppm"], "loss_rate_ppm"),
            duplicate_rate_ppm=_require_int(
                fields["duplicate_rate_ppm"],
                "duplicate_rate_ppm",
            ),
            partitions=partitions,
            withheld_delivery_slot_ids=tuple(withheld),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "min_delay_seconds": self.min_delay_seconds,
            "max_delay_seconds": self.max_delay_seconds,
            "loss_rate_ppm": self.loss_rate_ppm,
            "duplicate_rate_ppm": self.duplicate_rate_ppm,
            "partitions": [item.to_dict() for item in self.partitions],
            "withheld_delivery_slot_ids": list(self.withheld_delivery_slot_ids),
        }


@dataclass(frozen=True, slots=True)
class TransmissionOverride:
    """Development-fixture override for one independently scheduled copy."""

    delivery_slot_id: str
    copy_index: int
    disposition: Disposition
    delay_seconds: int | None = None

    def __post_init__(self) -> None:
        _require_identifier(self.delivery_slot_id, "delivery_slot_id")
        if type(self.copy_index) is not int or not 0 <= self.copy_index <= 7:
            raise DeliveryError("copy_index must be between 0 and 7")
        if not isinstance(self.disposition, Disposition):
            raise DeliveryError("disposition must be a Disposition")
        if self.delay_seconds is not None and (
            type(self.delay_seconds) is not int
            or not 0 <= self.delay_seconds <= MAX_PROFILE_SECONDS
        ):
            raise DeliveryError(
                f"delay_seconds must be null or between 0 and {MAX_PROFILE_SECONDS}"
            )
        if self.disposition is not Disposition.DELIVER and self.delay_seconds is not None:
            raise DeliveryError("non-delivery overrides cannot specify delay_seconds")

    @classmethod
    def from_dict(cls, value: Any) -> TransmissionOverride:
        fields = _require_object_fields(
            value,
            "transmission override",
            frozenset(
                {
                    "delivery_slot_id",
                    "copy_index",
                    "disposition",
                    "delay_seconds",
                }
            ),
        )
        try:
            disposition = Disposition(fields["disposition"])
        except (TypeError, ValueError) as exc:
            raise DeliveryError("override disposition is not supported") from exc
        delay_seconds = fields["delay_seconds"]
        if delay_seconds is not None:
            delay_seconds = _require_int(
                delay_seconds,
                "override.delay_seconds",
                maximum=MAX_PROFILE_SECONDS,
            )
        return cls(
            delivery_slot_id=fields["delivery_slot_id"],
            copy_index=_require_int(fields["copy_index"], "override.copy_index"),
            disposition=disposition,
            delay_seconds=delay_seconds,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "delivery_slot_id": self.delivery_slot_id,
            "copy_index": self.copy_index,
            "disposition": self.disposition.value,
            "delay_seconds": self.delay_seconds,
        }


def _transmission_id(delivery_slot_id: str, copy_index: int) -> str:
    return content_id(
        "DELIVERY_TRANSMISSION",
        {"delivery_slot_id": delivery_slot_id, "copy_index": copy_index},
    )


@dataclass(frozen=True, slots=True)
class ScheduledTransmission:
    """Evaluator-side delivery outcome; never passed directly to a gate."""

    transmission_id: str
    delivery_slot_id: str
    message_id: str
    copy_index: int
    disposition: Disposition
    delivered_at: datetime | None
    fault_tags: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _require_hash(self.transmission_id, "transmission_id")
        _require_identifier(self.delivery_slot_id, "delivery_slot_id")
        _require_hash(self.message_id, "message_id")
        if type(self.copy_index) is not int or not 0 <= self.copy_index <= 7:
            raise DeliveryError("copy_index must be between 0 and 7")
        if self.transmission_id != _transmission_id(self.delivery_slot_id, self.copy_index):
            raise DeliveryError("transmission_id does not match delivery_slot_id and copy_index")
        if not isinstance(self.disposition, Disposition):
            raise DeliveryError("disposition must be a Disposition")
        if self.disposition is Disposition.DELIVER:
            if self.delivered_at is None:
                raise DeliveryError("delivered transmission requires delivered_at")
            object.__setattr__(
                self,
                "delivered_at",
                _utc_second(self.delivered_at, "delivered_at"),
            )
        elif self.delivered_at is not None:
            raise DeliveryError("non-delivery transmission must not have delivered_at")
        if not isinstance(self.fault_tags, tuple):
            raise DeliveryError("fault_tags must be a tuple")
        tags = tuple(sorted(set(self.fault_tags)))
        for tag in tags:
            _require_identifier(tag, "fault tag")
        object.__setattr__(self, "fault_tags", tags)

    @classmethod
    def from_dict(cls, value: Any) -> ScheduledTransmission:
        fields = _require_object_fields(
            value,
            "scheduled transmission",
            frozenset(
                {
                    "transmission_id",
                    "delivery_slot_id",
                    "message_id",
                    "copy_index",
                    "disposition",
                    "delivered_at",
                    "fault_tags",
                }
            ),
        )
        try:
            disposition = Disposition(fields["disposition"])
        except (TypeError, ValueError) as exc:
            raise DeliveryError("transmission disposition is not supported") from exc
        delivered_value = fields["delivered_at"]
        delivered_at = (
            None
            if delivered_value is None
            else _parse_timestamp(delivered_value, "transmission.delivered_at")
        )
        fault_tags = _require_array(fields["fault_tags"], "transmission.fault_tags")
        if not all(isinstance(item, str) for item in fault_tags):
            raise DeliveryError("fault_tags entries must be strings")
        if len(set(fault_tags)) != len(fault_tags):
            raise DeliveryError("fault_tags entries must be unique")
        return cls(
            transmission_id=fields["transmission_id"],
            delivery_slot_id=fields["delivery_slot_id"],
            message_id=fields["message_id"],
            copy_index=_require_int(fields["copy_index"], "transmission.copy_index"),
            disposition=disposition,
            delivered_at=delivered_at,
            fault_tags=tuple(fault_tags),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "transmission_id": self.transmission_id,
            "delivery_slot_id": self.delivery_slot_id,
            "message_id": self.message_id,
            "copy_index": self.copy_index,
            "disposition": self.disposition.value,
            "delivered_at": None if self.delivered_at is None else _format_time(self.delivered_at),
            "fault_tags": list(self.fault_tags),
        }


@dataclass(frozen=True, slots=True)
class DeliveredMessage:
    """Schedule-free projection of one copy that actually arrived."""

    transmission_id: str
    delivery_slot_id: str
    message_id: str
    copy_index: int
    origin_store_id: str
    destination_store_id: str
    sent_at: datetime
    delivered_at: datetime
    payload_kind: PayloadKind
    payload_hash: str
    payload_bytes: bytes

    def __post_init__(self) -> None:
        _require_hash(self.transmission_id, "transmission_id")
        _require_identifier(self.delivery_slot_id, "delivery_slot_id")
        _require_hash(self.message_id, "message_id")
        if type(self.copy_index) is not int or not 0 <= self.copy_index <= 7:
            raise DeliveryError("copy_index must be between 0 and 7")
        if self.transmission_id != _transmission_id(self.delivery_slot_id, self.copy_index):
            raise DeliveryError("transmission_id does not match delivery_slot_id and copy_index")
        _require_identifier(self.origin_store_id, "origin_store_id")
        _require_identifier(self.destination_store_id, "destination_store_id")
        sent_at = _utc_second(self.sent_at, "sent_at")
        delivered_at = _utc_second(self.delivered_at, "delivered_at")
        if delivered_at < sent_at:
            raise DeliveryError("delivered_at cannot precede sent_at")
        if not isinstance(self.payload_kind, PayloadKind):
            raise DeliveryError("payload_kind must be a PayloadKind")
        if not isinstance(self.payload_bytes, bytes):
            raise DeliveryError("payload_bytes must be bytes")
        _require_hash(self.payload_hash, "payload_hash")
        if _payload_hash(self.payload_bytes) != self.payload_hash:
            raise DeliveryError("payload_hash does not match payload_bytes")
        try:
            payload = loads_strict(self.payload_bytes)
        except ValueError as exc:
            raise DeliveryError("payload_bytes must be canonical-profile JSON") from exc
        if not isinstance(payload, dict) or canonical_json(payload) != self.payload_bytes:
            raise DeliveryError("payload_bytes must be a canonical JSON object")
        _reject_reserved_evaluator_fields(payload)
        expected_message_id = content_id(
            "EVIDENCE_MESSAGE",
            _message_identity_body(
                delivery_slot_id=self.delivery_slot_id,
                origin_store_id=self.origin_store_id,
                destination_store_id=self.destination_store_id,
                sent_at=sent_at,
                payload_kind=self.payload_kind,
                payload_hash=self.payload_hash,
            ),
        )
        if self.message_id != expected_message_id:
            raise DeliveryError("message_id does not match delivered message fields")
        object.__setattr__(self, "sent_at", sent_at)
        object.__setattr__(self, "delivered_at", delivered_at)

    @property
    def payload(self) -> dict[str, Any]:
        value = loads_strict(self.payload_bytes)
        assert isinstance(value, dict)
        return value

    @classmethod
    def from_dict(cls, value: Any) -> DeliveredMessage:
        """Strictly decode and verify one delivered-message projection."""

        fields = _require_object_fields(
            value,
            "delivered message",
            frozenset(
                {
                    "transmission_id",
                    "delivery_slot_id",
                    "message_id",
                    "copy_index",
                    "origin_store_id",
                    "destination_store_id",
                    "sent_at",
                    "delivered_at",
                    "payload_kind",
                    "payload_hash",
                    "payload_b64",
                    "payload_size_bytes",
                }
            ),
        )
        payload_bytes = _decode_bytes(fields["payload_b64"], "payload_b64")
        payload_size = _require_int(
            fields["payload_size_bytes"],
            "payload_size_bytes",
            minimum=2,
        )
        if len(payload_bytes) != payload_size:
            raise DeliveryError("payload_size_bytes does not match payload_b64")
        try:
            payload_kind = PayloadKind(fields["payload_kind"])
        except (TypeError, ValueError) as exc:
            raise DeliveryError("payload_kind is not supported") from exc
        return cls(
            transmission_id=fields["transmission_id"],
            delivery_slot_id=fields["delivery_slot_id"],
            message_id=fields["message_id"],
            copy_index=_require_int(fields["copy_index"], "copy_index"),
            origin_store_id=fields["origin_store_id"],
            destination_store_id=fields["destination_store_id"],
            sent_at=_parse_timestamp(fields["sent_at"], "sent_at"),
            delivered_at=_parse_timestamp(fields["delivered_at"], "delivered_at"),
            payload_kind=payload_kind,
            payload_hash=fields["payload_hash"],
            payload_bytes=payload_bytes,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "transmission_id": self.transmission_id,
            "delivery_slot_id": self.delivery_slot_id,
            "message_id": self.message_id,
            "copy_index": self.copy_index,
            "origin_store_id": self.origin_store_id,
            "destination_store_id": self.destination_store_id,
            "sent_at": _format_time(self.sent_at),
            "delivered_at": _format_time(self.delivered_at),
            "payload_kind": self.payload_kind.value,
            "payload_hash": self.payload_hash,
            "payload_b64": _encode_bytes(self.payload_bytes),
            "payload_size_bytes": len(self.payload_bytes),
        }


@dataclass(frozen=True, slots=True)
class PermitObservationRecord:
    """One receipt binding retained for local equivocation detection."""

    observation_kind: str
    observation_key: str
    receipt_id: str

    def __post_init__(self) -> None:
        _require_identifier(self.observation_kind, "observation_kind")
        _require_identifier(self.observation_key, "observation_key")
        _require_hash(self.receipt_id, "receipt_id")

    @classmethod
    def from_dict(cls, value: Any) -> PermitObservationRecord:
        fields = _require_object_fields(
            value,
            "permit observation",
            frozenset({"observation_kind", "observation_key", "receipt_id"}),
        )
        return cls(
            observation_kind=fields["observation_kind"],
            observation_key=fields["observation_key"],
            receipt_id=fields["receipt_id"],
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "observation_kind": self.observation_kind,
            "observation_key": self.observation_key,
            "receipt_id": self.receipt_id,
        }


@dataclass(frozen=True, slots=True)
class PermitStateRecord:
    """One local permit record exposed in a decision-time snapshot."""

    permit_id: str
    leaf_receipt_id: str
    replay_scope: str
    request_hash: str
    action_nonce: str
    tool_id: str
    state: PermitLifecycle
    issued_at: datetime
    expires_at: datetime

    def __post_init__(self) -> None:
        _require_identifier(self.permit_id, "permit_id")
        _require_hash(self.leaf_receipt_id, "leaf_receipt_id")
        _require_hash(self.replay_scope, "replay_scope")
        _require_hash(self.request_hash, "request_hash")
        _require_identifier(self.action_nonce, "action_nonce")
        _require_identifier(self.tool_id, "tool_id")
        if not isinstance(self.state, PermitLifecycle):
            raise DeliveryError("state must be a PermitLifecycle")
        issued_at = _utc_second(self.issued_at, "issued_at")
        expires_at = _utc_second(self.expires_at, "expires_at")
        if issued_at >= expires_at:
            raise DeliveryError("permit issued_at must precede expires_at")
        object.__setattr__(self, "issued_at", issued_at)
        object.__setattr__(self, "expires_at", expires_at)

    @classmethod
    def from_dict(cls, value: Any) -> PermitStateRecord:
        fields = _require_object_fields(
            value,
            "permit record",
            frozenset(
                {
                    "permit_id",
                    "leaf_receipt_id",
                    "replay_scope",
                    "request_hash",
                    "action_nonce",
                    "tool_id",
                    "state",
                    "issued_at",
                    "expires_at",
                }
            ),
        )
        try:
            state = PermitLifecycle(fields["state"])
        except (TypeError, ValueError) as exc:
            raise DeliveryError("permit state is not supported") from exc
        return cls(
            permit_id=fields["permit_id"],
            leaf_receipt_id=fields["leaf_receipt_id"],
            replay_scope=fields["replay_scope"],
            request_hash=fields["request_hash"],
            action_nonce=fields["action_nonce"],
            tool_id=fields["tool_id"],
            state=state,
            issued_at=_parse_timestamp(fields["issued_at"], "permit.issued_at"),
            expires_at=_parse_timestamp(fields["expires_at"], "permit.expires_at"),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "permit_id": self.permit_id,
            "leaf_receipt_id": self.leaf_receipt_id,
            "replay_scope": self.replay_scope,
            "request_hash": self.request_hash,
            "action_nonce": self.action_nonce,
            "tool_id": self.tool_id,
            "state": self.state.value,
            "issued_at": _format_time(self.issued_at),
            "expires_at": _format_time(self.expires_at),
        }


@dataclass(frozen=True, slots=True)
class PermitStateSnapshot:
    """Immutable local permit-store state captured at the decision time."""

    permit_store_id: str
    captured_at: datetime
    records: tuple[PermitStateRecord, ...] = ()
    observations: tuple[PermitObservationRecord, ...] = ()

    def __post_init__(self) -> None:
        _require_identifier(self.permit_store_id, "permit_store_id")
        captured_at = _utc_second(self.captured_at, "captured_at")
        if not isinstance(self.records, tuple):
            raise DeliveryError("records must be a tuple")
        if not isinstance(self.observations, tuple):
            raise DeliveryError("observations must be a tuple")
        if not all(isinstance(item, PermitStateRecord) for item in self.records):
            raise DeliveryError("records must contain PermitStateRecord objects")
        if not all(
            isinstance(item, PermitObservationRecord) for item in self.observations
        ):
            raise DeliveryError(
                "observations must contain PermitObservationRecord objects"
            )
        records = tuple(sorted(self.records, key=lambda item: item.permit_id))
        if len({item.permit_id for item in records}) != len(records):
            raise DeliveryError("permit_id values must be unique within a snapshot")
        replay_keys = {
            (item.tool_id, item.replay_scope, item.action_nonce) for item in records
        }
        if len(replay_keys) != len(records):
            raise DeliveryError("permit replay keys must be unique within a snapshot")
        if any(item.issued_at > captured_at for item in records):
            raise DeliveryError("permit snapshot contains a future-issued permit")
        observations = tuple(
            sorted(
                self.observations,
                key=lambda item: (item.observation_kind, item.observation_key),
            )
        )
        observation_keys = {
            (item.observation_kind, item.observation_key) for item in observations
        }
        if len(observation_keys) != len(observations):
            raise DeliveryError("permit observation keys must be unique")
        object.__setattr__(self, "captured_at", captured_at)
        object.__setattr__(self, "records", records)
        object.__setattr__(self, "observations", observations)

    @classmethod
    def from_dict(cls, value: Any) -> PermitStateSnapshot:
        fields = _require_object_fields(
            value,
            "permit state",
            frozenset(
                {"permit_store_id", "captured_at", "records", "observations"}
            ),
        )
        records = tuple(
            PermitStateRecord.from_dict(item)
            for item in _require_array(fields["records"], "permit_state.records")
        )
        observations = tuple(
            PermitObservationRecord.from_dict(item)
            for item in _require_array(
                fields["observations"],
                "permit_state.observations",
            )
        )
        return cls(
            permit_store_id=fields["permit_store_id"],
            captured_at=_parse_timestamp(fields["captured_at"], "permit_state.captured_at"),
            records=records,
            observations=observations,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "permit_store_id": self.permit_store_id,
            "captured_at": _format_time(self.captured_at),
            "records": [item.to_dict() for item in self.records],
            "observations": [item.to_dict() for item in self.observations],
        }


def empty_permit_state(*, permit_store_id: str, captured_at: datetime) -> PermitStateSnapshot:
    return PermitStateSnapshot(
        permit_store_id=permit_store_id,
        captured_at=captured_at,
        records=(),
        observations=(),
    )


@dataclass(frozen=True, slots=True)
class LocalObservation:
    """Immutable evidence-store snapshot at one decision time."""

    verifier_id: str
    evidence_store_id: str
    permit_store_id: str
    decision_time: datetime
    delivered_messages: tuple[DeliveredMessage, ...]
    permit_state: PermitStateSnapshot

    def __post_init__(self) -> None:
        _require_identifier(self.verifier_id, "verifier_id")
        _require_identifier(self.evidence_store_id, "evidence_store_id")
        _require_identifier(self.permit_store_id, "permit_store_id")
        decision_time = _utc_second(self.decision_time, "decision_time")
        if not isinstance(self.permit_state, PermitStateSnapshot):
            raise DeliveryError("permit_state must be a PermitStateSnapshot")
        if self.permit_state.captured_at != decision_time:
            raise DeliveryError("permit_state must be captured at decision_time")
        if self.permit_state.permit_store_id != self.permit_store_id:
            raise DeliveryError("permit_state does not match permit_store_id")
        if not isinstance(self.delivered_messages, tuple):
            raise DeliveryError("delivered_messages must be a tuple")
        if not all(isinstance(item, DeliveredMessage) for item in self.delivered_messages):
            raise DeliveryError("delivered_messages must contain DeliveredMessage objects")
        messages = tuple(
            sorted(
                self.delivered_messages,
                key=lambda item: (item.delivered_at, item.transmission_id),
            )
        )
        if len({item.transmission_id for item in messages}) != len(messages):
            raise DeliveryError("delivered transmission IDs must be unique")
        for item in messages:
            if item.destination_store_id != self.evidence_store_id:
                raise DeliveryError("observation contains a message for another store")
            if item.delivered_at > decision_time:
                raise DeliveryError("observation contains a future delivery")
        object.__setattr__(self, "decision_time", decision_time)
        object.__setattr__(self, "delivered_messages", messages)

    @classmethod
    def from_dict(cls, value: Any) -> LocalObservation:
        fields = _require_object_fields(
            value,
            "local observation",
            frozenset(
                {
                    "version",
                    "observation_type",
                    "verifier_id",
                    "evidence_store_id",
                    "permit_store_id",
                    "decision_time",
                    "delivered_messages",
                    "permit_state",
                }
            ),
        )
        _require_version(fields["version"])
        if fields["observation_type"] != "LOCAL":
            raise DeliveryError("local observation type must be LOCAL")
        messages = tuple(
            DeliveredMessage.from_dict(item)
            for item in _require_array(
                fields["delivered_messages"],
                "local observation.delivered_messages",
            )
        )
        return cls(
            verifier_id=fields["verifier_id"],
            evidence_store_id=fields["evidence_store_id"],
            permit_store_id=fields["permit_store_id"],
            decision_time=_parse_timestamp(fields["decision_time"], "decision_time"),
            delivered_messages=messages,
            permit_state=PermitStateSnapshot.from_dict(fields["permit_state"]),
        )

    @classmethod
    def from_bytes(cls, raw: Any) -> LocalObservation:
        parsed = cls.from_dict(_decode_canonical_object(raw, "local observation"))
        if parsed.canonical_bytes != raw:
            raise DeliveryError("local observation object order is not canonical")
        return parsed

    def unique_evidence(self) -> tuple[DeliveredMessage, ...]:
        result: list[DeliveredMessage] = []
        seen: set[str] = set()
        for item in self.delivered_messages:
            if item.message_id not in seen:
                seen.add(item.message_id)
                result.append(item)
        return tuple(result)

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": DELIVERY_VERSION,
            "observation_type": "LOCAL",
            "verifier_id": self.verifier_id,
            "evidence_store_id": self.evidence_store_id,
            "permit_store_id": self.permit_store_id,
            "decision_time": _format_time(self.decision_time),
            "delivered_messages": [item.to_dict() for item in self.delivered_messages],
            "permit_state": self.permit_state.to_dict(),
        }

    @property
    def canonical_bytes(self) -> bytes:
        return canonical_json(self.to_dict())


@dataclass(frozen=True, slots=True)
class AuditObservation:
    """Immutable projection of one explicit audit inbox at its audit cutoff."""

    audit_store_id: str
    episode_end: datetime
    delta_audit_seconds: int
    cutoff: datetime
    delivered_messages: tuple[DeliveredMessage, ...]

    def __post_init__(self) -> None:
        _require_identifier(self.audit_store_id, "audit_store_id")
        episode_end = _utc_second(self.episode_end, "episode_end")
        cutoff = _utc_second(self.cutoff, "cutoff")
        if (
            type(self.delta_audit_seconds) is not int
            or not 0 <= self.delta_audit_seconds <= MAX_PROFILE_SECONDS
        ):
            raise DeliveryError(
                f"delta_audit_seconds must be between 0 and {MAX_PROFILE_SECONDS}"
            )
        try:
            expected_cutoff = episode_end + timedelta(
                seconds=self.delta_audit_seconds
            )
        except OverflowError as exc:
            raise DeliveryError("audit cutoff exceeds the datetime range") from exc
        if cutoff != expected_cutoff:
            raise DeliveryError("audit cutoff does not match episode_end plus delta")
        if not isinstance(self.delivered_messages, tuple):
            raise DeliveryError("delivered_messages must be a tuple")
        if not all(isinstance(item, DeliveredMessage) for item in self.delivered_messages):
            raise DeliveryError("delivered_messages must contain DeliveredMessage objects")
        messages = tuple(
            sorted(
                self.delivered_messages,
                key=lambda item: (item.delivered_at, item.transmission_id),
            )
        )
        if len({item.transmission_id for item in messages}) != len(messages):
            raise DeliveryError("delivered transmission IDs must be unique")
        for item in messages:
            if item.destination_store_id != self.audit_store_id:
                raise DeliveryError("audit observation contains another store's message")
            if item.delivered_at > cutoff:
                raise DeliveryError("audit observation contains a future delivery")
        object.__setattr__(self, "episode_end", episode_end)
        object.__setattr__(self, "cutoff", cutoff)
        object.__setattr__(self, "delivered_messages", messages)

    @classmethod
    def from_dict(cls, value: Any) -> AuditObservation:
        fields = _require_object_fields(
            value,
            "audit observation",
            frozenset(
                {
                    "version",
                    "observation_type",
                    "audit_store_id",
                    "episode_end",
                    "delta_audit_seconds",
                    "cutoff",
                    "delivered_messages",
                }
            ),
        )
        _require_version(fields["version"])
        if fields["observation_type"] != "AUDIT":
            raise DeliveryError("audit observation type must be AUDIT")
        messages = tuple(
            DeliveredMessage.from_dict(item)
            for item in _require_array(
                fields["delivered_messages"],
                "audit observation.delivered_messages",
            )
        )
        return cls(
            audit_store_id=fields["audit_store_id"],
            episode_end=_parse_timestamp(fields["episode_end"], "episode_end"),
            delta_audit_seconds=_require_int(
                fields["delta_audit_seconds"],
                "delta_audit_seconds",
                maximum=MAX_PROFILE_SECONDS,
            ),
            cutoff=_parse_timestamp(fields["cutoff"], "cutoff"),
            delivered_messages=messages,
        )

    @classmethod
    def from_bytes(cls, raw: Any) -> AuditObservation:
        parsed = cls.from_dict(_decode_canonical_object(raw, "audit observation"))
        if parsed.canonical_bytes != raw:
            raise DeliveryError("audit observation object order is not canonical")
        return parsed

    def unique_evidence(self) -> tuple[DeliveredMessage, ...]:
        result: list[DeliveredMessage] = []
        seen: set[str] = set()
        for item in self.delivered_messages:
            if item.message_id not in seen:
                seen.add(item.message_id)
                result.append(item)
        return tuple(result)

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": DELIVERY_VERSION,
            "observation_type": "AUDIT",
            "audit_store_id": self.audit_store_id,
            "episode_end": _format_time(self.episode_end),
            "delta_audit_seconds": self.delta_audit_seconds,
            "cutoff": _format_time(self.cutoff),
            "delivered_messages": [item.to_dict() for item in self.delivered_messages],
        }

    @property
    def canonical_bytes(self) -> bytes:
        return canonical_json(self.to_dict())


@dataclass(frozen=True, slots=True)
class DeliverySchedule:
    """Evaluator-side complete schedule and scorer-only transport outcomes."""

    seed: bytes
    policy: DeliveryPolicy
    messages: tuple[EvidenceMessage, ...]
    overrides: tuple[TransmissionOverride, ...]
    transmissions: tuple[ScheduledTransmission, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.seed, bytes) or not 1 <= len(self.seed) <= 64:
            raise DeliveryError("seed must contain between 1 and 64 bytes")
        if not isinstance(self.policy, DeliveryPolicy):
            raise DeliveryError("policy must be a DeliveryPolicy")
        if not isinstance(self.messages, tuple):
            raise DeliveryError("messages must be a tuple")
        if not isinstance(self.overrides, tuple):
            raise DeliveryError("overrides must be a tuple")
        if not isinstance(self.transmissions, tuple):
            raise DeliveryError("transmissions must be a tuple")
        if not all(isinstance(item, EvidenceMessage) for item in self.messages):
            raise DeliveryError("messages must contain EvidenceMessage objects")
        if not all(isinstance(item, TransmissionOverride) for item in self.overrides):
            raise DeliveryError("overrides must contain TransmissionOverride objects")
        if not all(isinstance(item, ScheduledTransmission) for item in self.transmissions):
            raise DeliveryError("transmissions must contain ScheduledTransmission objects")
        messages = tuple(
            sorted(self.messages, key=lambda item: (item.delivery_slot_id, item.message_id))
        )
        if len({item.message_id for item in messages}) != len(messages):
            raise DeliveryError("message_id values must be unique")
        if len({item.delivery_slot_id for item in messages}) != len(messages):
            raise DeliveryError("delivery_slot_id values must be unique within a schedule")
        overrides = tuple(
            sorted(
                self.overrides,
                key=lambda item: (item.delivery_slot_id, item.copy_index),
            )
        )
        if (
            len({(item.delivery_slot_id, item.copy_index) for item in overrides})
            != len(overrides)
        ):
            raise DeliveryError("transmission overrides must be unique")
        transmissions = tuple(sorted(self.transmissions, key=lambda item: item.transmission_id))
        if len({item.transmission_id for item in transmissions}) != len(transmissions):
            raise DeliveryError("transmission_id values must be unique")
        message_by_id = {item.message_id: item for item in messages}
        message_by_slot = {item.delivery_slot_id: item for item in messages}
        for item in overrides:
            if item.delivery_slot_id not in message_by_slot:
                raise DeliveryError("schedule override references an unknown delivery slot")
        for item in transmissions:
            if item.message_id not in message_by_id:
                raise DeliveryError("schedule transmission references an unknown message")
            if message_by_id[item.message_id].delivery_slot_id != item.delivery_slot_id:
                raise DeliveryError("transmission delivery slot does not match its message")
            if (
                item.disposition is Disposition.DELIVER
                and item.delivered_at is not None
                and item.delivered_at < message_by_id[item.message_id].sent_at
            ):
                raise DeliveryError("transmission delivery cannot precede message send time")
        expected = tuple(
            sorted(
                _build_transmissions(
                    messages,
                    policy=self.policy,
                    seed=self.seed,
                    overrides=overrides,
                ),
                key=lambda item: item.transmission_id,
            )
        )
        if transmissions != expected:
            raise DeliveryError("transmissions do not match the compiled schedule inputs")
        object.__setattr__(self, "messages", messages)
        object.__setattr__(self, "overrides", overrides)
        object.__setattr__(self, "transmissions", transmissions)

    @classmethod
    def from_dict(cls, value: Any) -> DeliverySchedule:
        """Strictly decode and recompile a serialized evaluator schedule."""

        fields = _require_object_fields(
            value,
            "delivery schedule",
            frozenset(
                {
                    "version",
                    "seed_b64",
                    "policy",
                    "messages",
                    "overrides",
                    "transmissions",
                }
            ),
        )
        _require_version(fields["version"])
        messages = tuple(
            EvidenceMessage.from_dict(item)
            for item in _require_array(fields["messages"], "schedule.messages")
        )
        overrides = tuple(
            TransmissionOverride.from_dict(item)
            for item in _require_array(fields["overrides"], "schedule.overrides")
        )
        transmissions = tuple(
            ScheduledTransmission.from_dict(item)
            for item in _require_array(
                fields["transmissions"],
                "schedule.transmissions",
            )
        )
        return cls(
            seed=_decode_bytes(fields["seed_b64"], "seed_b64"),
            policy=DeliveryPolicy.from_dict(fields["policy"]),
            messages=messages,
            overrides=overrides,
            transmissions=transmissions,
        )

    @classmethod
    def from_bytes(cls, raw: Any) -> DeliverySchedule:
        parsed = cls.from_dict(_decode_canonical_object(raw, "delivery schedule"))
        if parsed.canonical_bytes != raw:
            raise DeliveryError("delivery schedule object order is not canonical")
        return parsed

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": DELIVERY_VERSION,
            "seed_b64": _encode_bytes(self.seed),
            "policy": self.policy.to_dict(),
            "messages": [item.to_dict() for item in self.messages],
            "overrides": [item.to_dict() for item in self.overrides],
            "transmissions": [item.to_dict() for item in self.transmissions],
        }

    @property
    def canonical_bytes(self) -> bytes:
        return canonical_json(self.to_dict())

    @property
    def content_hash(self) -> str:
        return content_id("DELIVERY_SCHEDULE", self.to_dict())


def _draw(
    seed: bytes,
    delivery_slot_id: str,
    copy_index: int,
    label: str,
    modulus: int,
) -> int:
    if modulus <= 0:
        raise DeliveryError("draw modulus must be positive")
    body = canonical_json(
        {
            "version": DELIVERY_VERSION,
            "seed_b64": _encode_bytes(seed),
            "delivery_slot_id": delivery_slot_id,
            "copy_index": copy_index,
            "label": label,
        }
    )
    value = int.from_bytes(hashlib.sha256(_DRAW_DOMAIN + body).digest(), "big")
    return value % modulus


def _partition_release(
    message: EvidenceMessage,
    candidate: datetime,
    partitions: Sequence[PartitionWindow],
) -> tuple[datetime, tuple[str, ...]]:
    tags: set[str] = set()
    for _ in range(len(partitions) + 1):
        matches = [item for item in partitions if item.matches(message, candidate)]
        if not matches:
            return candidate, tuple(sorted(tags))
        tags.update(f"partition:{item.partition_id}" for item in matches)
        candidate = max(item.ends_at for item in matches)
    raise DeliveryError("partition release did not converge")


def _build_transmissions(
    messages: Sequence[EvidenceMessage],
    *,
    policy: DeliveryPolicy,
    seed: bytes,
    overrides: Sequence[TransmissionOverride],
) -> tuple[ScheduledTransmission, ...]:
    message_by_slot = {item.delivery_slot_id: item for item in messages}
    if len(message_by_slot) != len(messages):
        raise DeliveryError("delivery_slot_id values must be unique within a schedule")
    override_map: dict[tuple[str, int], TransmissionOverride] = {}
    for override in overrides:
        if override.delivery_slot_id not in message_by_slot:
            raise DeliveryError("override references an unknown delivery slot")
        key = (override.delivery_slot_id, override.copy_index)
        if key in override_map:
            raise DeliveryError("duplicate transmission override")
        override_map[key] = override

    withheld = set(policy.withheld_delivery_slot_ids)
    unknown_withheld = withheld - set(message_by_slot)
    if unknown_withheld:
        raise DeliveryError("policy withholds an unknown delivery slot")

    transmissions: list[ScheduledTransmission] = []
    for message in messages:
        slot_id = message.delivery_slot_id
        duplicate = _draw(seed, slot_id, 0, "duplicate", 1_000_000)
        copy_count = 2 if duplicate < policy.duplicate_rate_ppm else 1
        override_indices = [
            copy_index
            for override_slot_id, copy_index in override_map
            if override_slot_id == slot_id
        ]
        if override_indices:
            copy_count = max(copy_count, max(override_indices) + 1)

        for copy_index in range(copy_count):
            override = override_map.get((slot_id, copy_index))
            tags: set[str] = set()
            if copy_index:
                tags.add("duplicate_copy")

            if slot_id in withheld:
                disposition = Disposition.WITHHELD
                delay_seconds = None
                tags.add("explicit_withholding")
                if override is not None:
                    tags.add("override_suppressed")
            elif override is not None:
                disposition = override.disposition
                delay_seconds = override.delay_seconds
                tags.add("fixture_override")
            else:
                lost = _draw(seed, slot_id, copy_index, "loss", 1_000_000)
                if lost < policy.loss_rate_ppm:
                    disposition = Disposition.LOST
                    delay_seconds = None
                    tags.add("stochastic_loss")
                else:
                    disposition = Disposition.DELIVER
                    width = policy.max_delay_seconds - policy.min_delay_seconds + 1
                    delay_seconds = policy.min_delay_seconds + _draw(
                        seed,
                        slot_id,
                        copy_index,
                        "delay",
                        width,
                    )

            delivered_at: datetime | None = None
            if disposition is Disposition.DELIVER:
                if delay_seconds is None:
                    width = policy.max_delay_seconds - policy.min_delay_seconds + 1
                    delay_seconds = policy.min_delay_seconds + _draw(
                        seed,
                        slot_id,
                        copy_index,
                        "delay",
                        width,
                    )
                try:
                    candidate = message.sent_at + timedelta(seconds=delay_seconds)
                except OverflowError as exc:
                    raise DeliveryError(
                        "delivery time exceeds the datetime range"
                    ) from exc
                delivered_at, partition_tags = _partition_release(
                    message,
                    candidate,
                    policy.partitions,
                )
                tags.update(partition_tags)

            transmissions.append(
                ScheduledTransmission(
                    transmission_id=_transmission_id(slot_id, copy_index),
                    delivery_slot_id=slot_id,
                    message_id=message.message_id,
                    copy_index=copy_index,
                    disposition=disposition,
                    delivered_at=delivered_at,
                    fault_tags=tuple(tags),
                )
            )
    return tuple(transmissions)


def compile_schedule(
    messages: Iterable[EvidenceMessage],
    *,
    policy: DeliveryPolicy,
    seed: bytes,
    overrides: Iterable[TransmissionOverride] = (),
) -> DeliverySchedule:
    """Compile an input-order-independent schedule from canonical inputs."""

    if not isinstance(seed, bytes) or not 1 <= len(seed) <= 64:
        raise DeliveryError("seed must contain between 1 and 64 bytes")
    if not isinstance(policy, DeliveryPolicy):
        raise DeliveryError("policy must be a DeliveryPolicy")
    try:
        message_items = tuple(messages)
        override_items = tuple(overrides)
    except TypeError as exc:
        raise DeliveryError("messages and overrides must be iterable") from exc
    if not all(isinstance(item, EvidenceMessage) for item in message_items):
        raise DeliveryError("messages must contain EvidenceMessage objects")
    if not all(isinstance(item, TransmissionOverride) for item in override_items):
        raise DeliveryError("overrides must contain TransmissionOverride objects")
    ordered_messages = tuple(
        sorted(message_items, key=lambda item: (item.delivery_slot_id, item.message_id))
    )
    if len({item.message_id for item in ordered_messages}) != len(ordered_messages):
        raise DeliveryError("message_id values must be unique")
    if len({item.delivery_slot_id for item in ordered_messages}) != len(ordered_messages):
        raise DeliveryError("delivery_slot_id values must be unique within a schedule")
    ordered_overrides = tuple(
        sorted(override_items, key=lambda item: (item.delivery_slot_id, item.copy_index))
    )
    transmissions = _build_transmissions(
        ordered_messages,
        policy=policy,
        seed=seed,
        overrides=ordered_overrides,
    )

    return DeliverySchedule(
        seed=bytes(seed),
        policy=policy,
        messages=ordered_messages,
        overrides=ordered_overrides,
        transmissions=transmissions,
    )


def _delivered_for_store(
    schedule: DeliverySchedule,
    *,
    evidence_store_id: str,
    cutoff: datetime,
) -> tuple[DeliveredMessage, ...]:
    _require_identifier(evidence_store_id, "evidence_store_id")
    cutoff = _utc_second(cutoff, "cutoff")
    message_by_id = {item.message_id: item for item in schedule.messages}
    delivered: list[DeliveredMessage] = []
    for transmission in schedule.transmissions:
        if transmission.disposition is not Disposition.DELIVER:
            continue
        assert transmission.delivered_at is not None
        message = message_by_id[transmission.message_id]
        if message.destination_store_id != evidence_store_id:
            continue
        if transmission.delivered_at > cutoff:
            continue
        delivered.append(
            DeliveredMessage(
                transmission_id=transmission.transmission_id,
                delivery_slot_id=message.delivery_slot_id,
                message_id=message.message_id,
                copy_index=transmission.copy_index,
                origin_store_id=message.origin_store_id,
                destination_store_id=message.destination_store_id,
                sent_at=message.sent_at,
                delivered_at=transmission.delivered_at,
                payload_kind=message.payload_kind,
                payload_hash=message.payload_hash,
                payload_bytes=message.payload_bytes,
            )
        )
    return tuple(sorted(delivered, key=lambda item: (item.delivered_at, item.transmission_id)))


def project_local(
    schedule: DeliverySchedule,
    *,
    verifier_id: str,
    evidence_store_id: str,
    permit_store_id: str,
    decision_time: datetime,
    permit_state: PermitStateSnapshot,
) -> LocalObservation:
    """Return only messages delivered to one local store by decision_time."""

    _require_identifier(verifier_id, "verifier_id")
    _require_identifier(permit_store_id, "permit_store_id")
    decision_time = _utc_second(decision_time, "decision_time")
    return LocalObservation(
        verifier_id=verifier_id,
        evidence_store_id=evidence_store_id,
        permit_store_id=permit_store_id,
        decision_time=decision_time,
        delivered_messages=_delivered_for_store(
            schedule,
            evidence_store_id=evidence_store_id,
            cutoff=decision_time,
        ),
        permit_state=permit_state,
    )


def project_audit(
    schedule: DeliverySchedule,
    *,
    audit_store_id: str,
    episode_end: datetime,
    delta_audit: timedelta,
) -> AuditObservation:
    """Project one explicit audit inbox at episode_end plus delta_audit."""

    _require_identifier(audit_store_id, "audit_store_id")
    episode_end = _utc_second(episode_end, "episode_end")
    if not isinstance(delta_audit, timedelta):
        raise DeliveryError("delta_audit must be a timedelta")
    delta_seconds = delta_audit.total_seconds()
    if (
        not delta_seconds.is_integer()
        or not 0 <= delta_seconds <= MAX_PROFILE_SECONDS
    ):
        raise DeliveryError(
            f"delta_audit must be between 0 and {MAX_PROFILE_SECONDS} whole seconds"
        )
    try:
        cutoff = episode_end + delta_audit
    except OverflowError as exc:
        raise DeliveryError("audit cutoff exceeds the datetime range") from exc
    return AuditObservation(
        audit_store_id=audit_store_id,
        episode_end=episode_end,
        delta_audit_seconds=int(delta_seconds),
        cutoff=cutoff,
        delivered_messages=_delivered_for_store(
            schedule,
            evidence_store_id=audit_store_id,
            cutoff=cutoff,
        ),
    )
