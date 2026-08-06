"""Shared types and deterministic helpers for the scripted pilot."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any, Mapping

from crosstrace_sketch.protocol import canonical_json


PILOT_ID = "crosstrace-scripted-systems-pilot-v0.1"
CONDITIONS = (
    "ordinary_local_logs",
    "central_append_only_log",
    "isolated_signed_logs",
    "paired_receipts",
    "paired_receipts_with_gate",
)
SCENARIOS = (
    "valid_current_within_scope",
    "withheld_broker_record",
    "equivocation_joined_views",
    "revoked_authority",
    "over_limit",
    "local_replay",
)
SEEDS = tuple(range(10))


@dataclass(frozen=True)
class OracleAttempt:
    """Ground-truth authorisation for one simulated adapter attempt."""

    attempt_id: str
    action_id: str
    authorised: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "attempt_id": self.attempt_id,
            "action_id": self.action_id,
            "authorised": self.authorised,
        }


@dataclass(frozen=True)
class OracleCase:
    """Ground truth retained by the scorer and never passed to an evaluator."""

    case_id: str
    scenario: str
    seed: int
    paths: tuple[tuple[tuple[str, str, str, str], ...], ...]
    attempts: tuple[OracleAttempt, ...]
    expected_fault: str | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "scenario": self.scenario,
            "seed": self.seed,
            "paths": [[list(step) for step in path] for path in self.paths],
            "attempts": [attempt.to_dict() for attempt in self.attempts],
            "expected_fault": self.expected_fault,
        }

    @property
    def content_hash(self) -> str:
        return "sha256:" + hashlib.sha256(canonical_json(self.to_dict())).hexdigest()


def stable_hex(namespace: str, *parts: object) -> str:
    body = "|".join([namespace, *(str(part) for part in parts)]).encode("ascii")
    return hashlib.sha256(body).hexdigest()


def stable_id(prefix: str, *parts: object, length: int = 16) -> str:
    return f"{prefix}-{stable_hex(prefix, *parts)[:length]}"


def canonical_size(value: Mapping[str, Any] | list[Any]) -> int:
    return len(canonical_json(value))
