"""Verify and deterministically regenerate a Sprint 4 six-cell release."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import tempfile
from collections import Counter
from datetime import timedelta
from functools import lru_cache
from pathlib import Path
from typing import Any, Mapping, Sequence

from jsonschema import Draft202012Validator
from jsonschema.exceptions import SchemaError, ValidationError

from crosstrace_sketch.protocol import canonical_json, content_id, loads_strict
from preaward.crosstrace_sprint1.delivery import (
    AuditObservation,
    DeliverySchedule,
    LocalObservation,
    project_audit,
    project_local,
)

from .harness import compute_invariance, summarise_engineering
from .model import CELL_SPECS, CLAIM_LEVEL, HARNESS_VERSION, RELEASE_ID, HarnessError
from .runner import (
    DETERMINISTIC_FILES,
    INTEGRITY_FILES,
    repository_root,
    resolved_fixture,
    source_manifest,
    write_release,
)


class VerificationError(ValueError):
    """Raised when a Sprint 4 release is malformed or not reproducible."""


_BUNDLE_FIELDS = {
    "version",
    "bundle_id",
    "case_id",
    "representation",
    "neutral_trace_hash",
    "action_hash",
    "slot_manifest_hash",
    "transport_projection_hash",
    "neutral_handoff_ids",
    "slot_assignments",
    "transport_projection",
    "schedule",
    "local_observation",
    "audit_observation",
    "endpoint_sender_bytes_b64",
    "pr_copy_pairs_equal",
}
_EXECUTION_FIELDS = {
    "execution_id",
    "version",
    "release_id",
    "claim_level",
    "case_id",
    "cell_id",
    "representation",
    "enforcement",
    "bundle_id",
    "neutral_trace_hash",
    "action_hash",
    "slot_manifest_hash",
    "transport_projection_hash",
    "local_validation",
    "audit_validation",
    "gate",
    "adapter_attempts",
    "engineering_counts",
}


@lru_cache(maxsize=None)
def _schema_validator(name: str) -> Draft202012Validator:
    relative = Path(name)
    path = (
        repository_root() / relative
        if len(relative.parts) > 1
        else repository_root() / "schema" / relative
    )
    try:
        schema = json.loads(path.read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
    except (OSError, json.JSONDecodeError, SchemaError) as exc:
        raise VerificationError(f"schema is unavailable or invalid: {name}") from exc
    return Draft202012Validator(schema)


def _validate_schema(name: str, value: Any, object_name: str) -> None:
    try:
        _schema_validator(name).validate(value)
    except ValidationError as exc:
        raise VerificationError(f"{object_name} fails {name}") from exc


def _read_json(path: Path) -> dict[str, Any]:
    raw = path.read_bytes()
    if not raw.endswith(b"\n"):
        raise VerificationError(f"{path.name} must end with one newline")
    try:
        value = loads_strict(raw[:-1])
    except ValueError as exc:
        raise VerificationError(f"{path.name} is not strict JSON") from exc
    if not isinstance(value, dict):
        raise VerificationError(f"{path.name} must contain an object")
    if canonical_json(value) + b"\n" != raw:
        raise VerificationError(f"{path.name} is not canonical JSON")
    return value


def _read_jsonl(path: Path) -> tuple[dict[str, Any], ...]:
    raw = path.read_bytes()
    if not raw or not raw.endswith(b"\n"):
        raise VerificationError(f"{path.name} must be non-empty canonical JSONL")
    rows: list[dict[str, Any]] = []
    for line_number, line in enumerate(raw.splitlines(), 1):
        try:
            value = loads_strict(line)
        except ValueError as exc:
            raise VerificationError(
                f"{path.name} line {line_number} is not strict JSON"
            ) from exc
        if not isinstance(value, dict) or canonical_json(value) != line:
            raise VerificationError(
                f"{path.name} line {line_number} is not a canonical object"
            )
        rows.append(value)
    return tuple(rows)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _verify_checksums(directory: Path) -> None:
    declared: dict[str, str] = {}
    for line in (
        (directory / "checksums.sha256").read_text(encoding="ascii").splitlines()
    ):
        try:
            digest, name = line.split("  ", 1)
        except ValueError as exc:
            raise VerificationError(
                "checksums.sha256 contains a malformed line"
            ) from exc
        if name in declared or len(digest) != 64:
            raise VerificationError(
                "checksums.sha256 contains a duplicate or invalid digest"
            )
        declared[name] = digest
    if set(declared) != set(INTEGRITY_FILES):
        raise VerificationError("checksum file set is not exact")
    for name, digest in declared.items():
        if _sha256(directory / name) != digest:
            raise VerificationError(f"checksum mismatch: {name}")


def _require_fields(value: Mapping[str, Any], expected: set[str], name: str) -> None:
    if set(value) != expected:
        raise VerificationError(f"{name} fields are not exact")


def _verify_bundle(row: Mapping[str, Any]) -> None:
    _validate_schema(
        "preaward/crosstrace_sprint4/schemas/six-cell-bundle.schema.json",
        row,
        "bundle",
    )
    _require_fields(row, _BUNDLE_FIELDS, "bundle")
    if row["version"] != HARNESS_VERSION or row["representation"] not in {
        "SL",
        "CR",
        "PR",
    }:
        raise VerificationError("bundle version or representation is invalid")
    schedule = DeliverySchedule.from_dict(row["schedule"])
    local = LocalObservation.from_dict(row["local_observation"])
    audit = AuditObservation.from_dict(row["audit_observation"])
    _validate_schema("delivery-schedule.schema.json", row["schedule"], "schedule")
    _validate_schema(
        "delivery-observation.schema.json",
        row["local_observation"],
        "local observation",
    )
    _validate_schema(
        "delivery-observation.schema.json",
        row["audit_observation"],
        "audit observation",
    )
    schedule_messages = {item.message_id for item in schedule.messages}
    if any(
        item.message_id not in schedule_messages for item in local.delivered_messages
    ):
        raise VerificationError("local observation refers outside its schedule")
    if any(
        item.message_id not in schedule_messages for item in audit.delivered_messages
    ):
        raise VerificationError("audit observation refers outside its schedule")
    expected_local = project_local(
        schedule,
        verifier_id=local.verifier_id,
        evidence_store_id=local.evidence_store_id,
        permit_store_id=local.permit_store_id,
        decision_time=local.decision_time,
        permit_state=local.permit_state,
    )
    expected_audit = project_audit(
        schedule,
        audit_store_id=audit.audit_store_id,
        episode_end=audit.episode_end,
        delta_audit=timedelta(seconds=audit.delta_audit_seconds),
    )
    if expected_local.to_dict() != row["local_observation"]:
        raise VerificationError("local observation does not project from its schedule")
    if expected_audit.to_dict() != row["audit_observation"]:
        raise VerificationError("audit observation does not project from its schedule")
    slot_hash = content_id("SPRINT4_SLOT_MANIFEST", row["slot_assignments"])
    if row["slot_manifest_hash"] != slot_hash:
        raise VerificationError("slot_manifest_hash is invalid")
    projection_hash = content_id(
        "SPRINT4_TRANSPORT_PROJECTION", row["transport_projection"]
    )
    if row["transport_projection_hash"] != projection_hash:
        raise VerificationError("transport_projection_hash is invalid")
    message_by_id = {item.message_id: item for item in schedule.messages}
    expected_projection = []
    for transmission in schedule.transmissions:
        message = message_by_id[transmission.message_id]
        expected_projection.append(
            {
                "delivery_slot_id": transmission.delivery_slot_id,
                "copy_index": transmission.copy_index,
                "origin_store_id": message.origin_store_id,
                "destination_store_id": message.destination_store_id,
                "sent_at": message.to_dict()["sent_at"],
                "disposition": transmission.disposition.value,
                "delivered_at": transmission.to_dict()["delivered_at"],
                "fault_tags": list(transmission.fault_tags),
            }
        )
    expected_projection.sort(
        key=lambda item: (item["delivery_slot_id"], item["copy_index"])
    )
    if expected_projection != row["transport_projection"]:
        raise VerificationError("transport projection does not match schedule")
    bundle_body = {
        "version": HARNESS_VERSION,
        "representation": row["representation"],
        "neutral_trace_hash": row["neutral_trace_hash"],
        "action_hash": row["action_hash"],
        "slot_manifest_hash": row["slot_manifest_hash"],
        "transport_projection_hash": row["transport_projection_hash"],
        "schedule": row["schedule"],
        "local_observation": row["local_observation"],
        "audit_observation": row["audit_observation"],
    }
    if row["bundle_id"] != content_id("SPRINT4_REPRESENTATION_BUNDLE", bundle_body):
        raise VerificationError("bundle_id is invalid")


def _verify_execution(row: Mapping[str, Any], *, attempt_count: int) -> None:
    _validate_schema(
        "preaward/crosstrace_sprint4/schemas/six-cell-execution.schema.json",
        row,
        "execution",
    )
    _require_fields(row, _EXECUTION_FIELDS, "execution")
    if (
        row["version"] != HARNESS_VERSION
        or row["release_id"] != RELEASE_ID
        or row["claim_level"] != CLAIM_LEVEL
    ):
        raise VerificationError("execution identity fields are invalid")
    expected_cell = f"{row['representation']}-{row['enforcement']}"
    if row["cell_id"] != expected_cell:
        raise VerificationError("execution cell factor mapping is invalid")
    body = dict(row)
    execution_id = body.pop("execution_id")
    if execution_id != content_id("SPRINT4_EXECUTION", body):
        raise VerificationError("execution_id is invalid")
    if set(row["engineering_counts"]) != {
        "local_delivered_messages",
        "audit_delivered_messages",
        "local_delivered_payload_bytes",
        "audit_delivered_payload_bytes",
        "adapter_calls",
        "model_calls",
        "input_tokens",
        "output_tokens",
        "runtime_network_calls",
    }:
        raise VerificationError("engineering_counts fields are not exact")
    for name in (
        "model_calls",
        "input_tokens",
        "output_tokens",
        "runtime_network_calls",
    ):
        if row["engineering_counts"][name] != 0:
            raise VerificationError("an external-call counter is non-zero")
    gate = row["gate"]
    _require_fields(
        gate,
        {
            "invoked",
            "common_input_ids",
            "common_inputs",
            "common_input_forbidden_fields",
            "decisions",
            "transitions",
            "finish_results",
            "permit_reservations",
            "permit_store_mutations",
        },
        "gate trace",
    )
    if gate["common_input_forbidden_fields"]:
        raise VerificationError("gate input contains forbidden metadata")
    for common_input in gate["common_inputs"]:
        _validate_schema(
            "common-gate-input.schema.json", common_input, "common gate input"
        )
        _validate_schema(
            "neutral-permit-state.schema.json",
            common_input["permit_state"],
            "neutral permit state",
        )
    for decision in gate["decisions"]:
        _validate_schema(
            "common-gate-decision.schema.json", decision, "common gate decision"
        )
    if len(row["adapter_attempts"]) != attempt_count:
        raise VerificationError("adapter attempt count does not match the fixture")
    if row["enforcement"] == "AUDIT" and (
        gate["invoked"] or gate["permit_reservations"] or gate["permit_store_mutations"]
    ):
        raise VerificationError("audit branch mutated gate state")
    if row["enforcement"] == "AUDIT":
        if any(
            gate[name]
            for name in (
                "common_input_ids",
                "common_inputs",
                "decisions",
                "transitions",
                "finish_results",
            )
        ):
            raise VerificationError("audit branch contains gate artifacts")
    else:
        if not gate["invoked"]:
            raise VerificationError("gate branch did not invoke the gate")
        if not (
            len(gate["decisions"])
            == len(gate["common_input_ids"])
            == len(gate["common_inputs"])
            == attempt_count
        ):
            raise VerificationError("gate input, decision, or attempt count is wrong")
        if gate["common_input_ids"] != [
            item.get("input_id") for item in gate["common_inputs"]
        ]:
            raise VerificationError("common input identifiers do not match inputs")
        allow_count = sum(
            decision["verdict"] == "ALLOW" for decision in gate["decisions"]
        )
        if (
            gate["permit_reservations"] != allow_count
            or len(gate["transitions"]) != allow_count
            or len(gate["finish_results"]) != allow_count
            or not all(gate["finish_results"])
            or gate["permit_store_mutations"] != 3 * allow_count
        ):
            raise VerificationError("permit transition trace is inconsistent")
    for attempt in row["adapter_attempts"]:
        _require_fields(
            attempt,
            {"attempt_id", "attempted", "committed", "operational_failure"},
            "adapter attempt",
        )
        if attempt["committed"] and not attempt["attempted"]:
            raise VerificationError("adapter committed without an attempt")
    if row["engineering_counts"]["adapter_calls"] != sum(
        attempt["attempted"] for attempt in row["adapter_attempts"]
    ):
        raise VerificationError("adapter call counter does not match attempt trace")
    if row["enforcement"] == "GATE":
        for decision, attempt in zip(
            gate["decisions"], row["adapter_attempts"], strict=True
        ):
            if (decision["verdict"] == "ALLOW") != attempt["attempted"]:
                raise VerificationError("gate verdict does not match adapter boundary")


def _verify_manifest(
    manifest: Mapping[str, Any], fixture: Mapping[str, Any], bundles, executions
) -> None:
    _validate_schema(
        "preaward/crosstrace_sprint4/schemas/six-cell-manifest.schema.json",
        manifest,
        "manifest",
    )
    expected_fields = {
        "version",
        "release_id",
        "claim_level",
        "classification",
        "cells",
        "fixture_count",
        "bundle_count",
        "execution_count",
        "unit",
        "fixture_hash",
        "source_tree_hash",
        "source_files",
        "deterministic_files",
        "policies",
    }
    _require_fields(manifest, expected_fields, "manifest")
    if (
        manifest["version"] != HARNESS_VERSION
        or manifest["release_id"] != RELEASE_ID
        or manifest["claim_level"] != CLAIM_LEVEL
        or manifest["classification"] != "DEVELOPMENT_ONLY"
    ):
        raise VerificationError("manifest identity is invalid")
    if manifest["cells"] != [item.to_dict() for item in CELL_SPECS]:
        raise VerificationError("manifest six-cell declaration is invalid")
    if (
        manifest["fixture_count"] != 8
        or manifest["bundle_count"] != 24
        or manifest["bundle_count"] != len(bundles)
        or manifest["execution_count"] != 48
        or manifest["execution_count"] != len(executions)
    ):
        raise VerificationError("manifest counts are invalid")
    if manifest["fixture_hash"] != content_id("SPRINT4_RESOLVED_FIXTURE", fixture):
        raise VerificationError("manifest fixture hash is invalid")
    sources, source_hash = source_manifest()
    if (
        manifest["source_files"] != list(sources)
        or manifest["source_tree_hash"] != source_hash
    ):
        raise VerificationError("manifest source closure does not match current source")
    if manifest["deterministic_files"] != list(DETERMINISTIC_FILES):
        raise VerificationError("manifest deterministic file set is invalid")
    policies = manifest["policies"]
    if policies != {
        "engineering_only": True,
        "independent_trials": False,
        "model_calls": 0,
        "runtime_network_calls": 0,
        "synthetic_adapter": True,
    }:
        raise VerificationError("manifest claim-boundary policies are invalid")


def _verify_matrix(bundles, executions) -> None:
    if len(bundles) != 24 or len(executions) != 48:
        raise VerificationError("release does not contain 24 bundles and 48 executions")
    bundle_keys = Counter((row["case_id"], row["representation"]) for row in bundles)
    execution_keys = Counter((row["case_id"], row["cell_id"]) for row in executions)
    case_ids = {row["case_id"] for row in executions}
    if (
        len(case_ids) != 8
        or any(value != 1 for value in bundle_keys.values())
        or len(bundle_keys) != 24
    ):
        raise VerificationError("bundle matrix is incomplete or duplicated")
    if (
        any(value != 1 for value in execution_keys.values())
        or len(execution_keys) != 48
    ):
        raise VerificationError("execution matrix is incomplete or duplicated")
    bundle_ids = {
        (row["case_id"], row["representation"]): row["bundle_id"] for row in bundles
    }
    for row in executions:
        if row["bundle_id"] != bundle_ids[(row["case_id"], row["representation"])]:
            raise VerificationError(
                "execution refers to the wrong representation bundle"
            )


def _verify_regeneration(directory: Path) -> None:
    with tempfile.TemporaryDirectory(prefix="crosstrace_sprint4_verify_") as temporary:
        regenerated = write_release(output_dir=Path(temporary) / "release")
        for name in DETERMINISTIC_FILES:
            if (directory / name).read_bytes() != (regenerated / name).read_bytes():
                raise VerificationError(f"deterministic regeneration mismatch: {name}")


def verify_release(directory: Path, *, regenerate: bool = True) -> dict[str, Any]:
    expected_files = {*INTEGRITY_FILES, "checksums.sha256"}
    entries = tuple(directory.iterdir())
    actual_names = {item.name for item in entries}
    if actual_names != expected_files or any(not item.is_file() for item in entries):
        raise VerificationError("release file set is not exact")
    _verify_checksums(directory)
    fixture = _read_json(directory / "fixtures.resolved.json")
    manifest = _read_json(directory / "manifest.resolved.json")
    bundles = _read_jsonl(directory / "bundles.jsonl")
    executions = _read_jsonl(directory / "executions.jsonl")
    invariance = _read_json(directory / "invariance.json")
    summary = _read_json(directory / "summary.json")
    environment = _read_json(directory / "environment.json")
    if fixture != resolved_fixture():
        raise VerificationError("resolved fixture does not match the frozen source")
    for row in bundles:
        _verify_bundle(row)
    attempt_counts = {
        item["case_id"]: item["attempt_count"] for item in fixture["cases"]
    }
    for row in executions:
        try:
            attempt_count = attempt_counts[row["case_id"]]
        except KeyError as exc:
            raise VerificationError("execution refers to an unknown fixture") from exc
        _verify_execution(row, attempt_count=attempt_count)
    _verify_matrix(bundles, executions)
    _verify_manifest(manifest, fixture, bundles, executions)
    recomputed_invariance = compute_invariance(bundles, executions)
    if invariance != recomputed_invariance or invariance["violation_count"]:
        raise VerificationError("invariance record is wrong or contains violations")
    if summary != summarise_engineering(executions, invariance):
        raise VerificationError("summary does not recompute from execution rows")
    _require_fields(
        environment,
        {
            "python",
            "implementation",
            "platform",
            "cryptography",
            "jsonschema",
            "sqlite",
            "openssl",
            "model_calls",
            "runtime_network_calls",
        },
        "environment",
    )
    if not all(
        isinstance(environment[name], str) and environment[name]
        for name in (
            "python",
            "implementation",
            "platform",
            "cryptography",
            "jsonschema",
            "sqlite",
            "openssl",
        )
    ):
        raise VerificationError("environment version fields must be non-empty strings")
    if (
        type(environment["model_calls"]) is not int
        or type(environment["runtime_network_calls"]) is not int
        or environment["model_calls"] != 0
        or environment["runtime_network_calls"] != 0
    ):
        raise VerificationError("environment external-call counters are invalid")
    if regenerate:
        _verify_regeneration(directory)
    return {
        "release_id": RELEASE_ID,
        "cells": len(CELL_SPECS),
        "fixtures": 8,
        "executions": len(executions),
        "invariant_violations": invariance["violation_count"],
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("result_directory", type=Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        result = verify_release(
            args.result_directory,
        )
    except (OSError, ValueError, KeyError, TypeError, HarnessError) as exc:
        print(f"verification failed: {exc}", file=sys.stderr)
        return 1
    print(
        f"verified {result['release_id']}: {result['cells']} cells, "
        f"{result['fixtures']} fixtures, {result['executions']} executions, "
        f"{result['invariant_violations']} invariant violations, "
        "0 model calls, 0 runtime network calls"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
