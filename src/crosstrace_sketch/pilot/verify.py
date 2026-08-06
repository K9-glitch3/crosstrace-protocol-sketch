"""Verify a CrossTrace scripted-pilot result release."""

from __future__ import annotations

import argparse
import hashlib
import sys
import tempfile
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Mapping, Sequence

from crosstrace_sketch.protocol import canonical_json, loads_strict

from .model import CONDITIONS, PILOT_ID, SCENARIOS, SEEDS
from .runner import CORE_FILES, repository_root, source_tree_hash, write_release
from .scoring import summarise


class VerificationError(ValueError):
    """Raised when a result release fails a reproducibility invariant."""


def _read_json(path: Path) -> dict[str, Any]:
    value = loads_strict(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise VerificationError(f"{path.name} must contain a JSON object")
    return value


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line:
            continue
        value = loads_strict(line)
        if not isinstance(value, dict):
            raise VerificationError(f"episodes.jsonl line {line_number} is not an object")
        rows.append(value)
    return rows


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _verify_checksums(directory: Path) -> None:
    declared: dict[str, str] = {}
    for line in (directory / "checksums.sha256").read_text(encoding="ascii").splitlines():
        try:
            digest, name = line.split("  ", 1)
        except ValueError as exc:
            raise VerificationError("invalid checksums.sha256 line") from exc
        declared[name] = digest
    if set(declared) != set(CORE_FILES):
        raise VerificationError("checksum file set does not match the declared core files")
    for name in CORE_FILES:
        if _sha256(directory / name) != declared[name]:
            raise VerificationError(f"checksum mismatch: {name}")


def _attempt(row: Mapping[str, Any], attempt_id: str) -> Mapping[str, Any]:
    for attempt in row["attempts"]:
        if attempt["attempt_id"] == attempt_id:
            return attempt
    raise VerificationError(f"{row['episode_id']} lacks {attempt_id}")


def _verify_gate_counterfactuals(rows: Sequence[Mapping[str, Any]]) -> None:
    for row in rows:
        attempts = row["attempts"]
        if row["condition"] != "paired_receipts_with_gate":
            if not all(attempt["executed"] for attempt in attempts):
                raise VerificationError("a no-gate condition unexpectedly blocked an attempt")
            continue
        scenario = row["scenario"]
        first = _attempt(row, "attempt-1")
        if scenario in {"valid_current_within_scope", "withheld_broker_record"}:
            if not first["executed"]:
                raise VerificationError("gate blocked the declared valid attempt")
        elif scenario in {"revoked_authority", "over_limit"}:
            if first["executed"]:
                raise VerificationError("gate executed a declared unauthorised attempt")
        elif scenario == "local_replay":
            second = _attempt(row, "attempt-2")
            if not first["executed"] or second["executed"]:
                raise VerificationError("gate replay counterfactual does not match the design")
            if "REPLAY_DETECTED" not in second["reasons"]:
                raise VerificationError("blocked replay lacks REPLAY_DETECTED")
        elif scenario == "equivocation_joined_views":
            second = _attempt(row, "attempt-2")
            if not first["executed"] or not second["executed"]:
                raise VerificationError("isolated-view fork boundary was not reproduced")
            if not row["detections"]["joined_view_conflict_detected"]:
                raise VerificationError("joined view failed to detect the fork")


def _verify_manifest_binding(directory: Path, manifest: Mapping[str, Any]) -> None:
    schema_reference = manifest.get("$schema")
    if schema_reference != "pilot-release-manifest.schema.json":
        raise VerificationError("resolved manifest schema reference is invalid")
    schema_path = (directory / schema_reference).resolve()
    if not schema_path.is_file():
        raise VerificationError("resolved manifest schema is unavailable")
    source_schema = (
        repository_root() / "pilot" / "schemas" / "pilot-release-manifest.schema.json"
    )
    release_schema = _read_json(schema_path)
    source_schema_value = _read_json(source_schema)
    if canonical_json(release_schema) != canonical_json(source_schema_value):
        raise VerificationError("release schema does not match the bound source schema")
    implementation = manifest.get("implementation")
    if not isinstance(implementation, dict):
        raise VerificationError("resolved manifest implementation binding is missing")
    declared_hash = implementation.get("source_tree_hash")
    current_hash = source_tree_hash(repository_root())
    if declared_hash != current_hash:
        raise VerificationError("release source-tree hash does not match the current source")


def _verify_deterministic_regeneration(directory: Path) -> None:
    with tempfile.TemporaryDirectory(prefix="crosstrace_verify_") as temporary:
        regenerated = write_release(output_dir=Path(temporary) / "release")
        for name in (*CORE_FILES, "checksums.sha256"):
            if (directory / name).read_bytes() != (regenerated / name).read_bytes():
                raise VerificationError(f"deterministic regeneration mismatch: {name}")


def verify_release(directory: Path) -> dict[str, int | str]:
    """Verify checksums, design cells, oracle separation, and summary recomputation."""

    required = {*CORE_FILES, "environment.json", "checksums.sha256"}
    missing = sorted(name for name in required if not (directory / name).is_file())
    if missing:
        raise VerificationError(f"missing release files: {', '.join(missing)}")
    _verify_checksums(directory)
    manifest = _read_json(directory / "manifest.resolved.json")
    episodes = _read_jsonl(directory / "episodes.jsonl")
    summary = _read_json(directory / "summary.json")

    if manifest.get("pilot_id") != PILOT_ID or summary.get("pilot_id") != PILOT_ID:
        raise VerificationError("pilot identifier mismatch")
    _verify_manifest_binding(directory, manifest)
    if len(episodes) != 300 or manifest.get("episode_count") != 300:
        raise VerificationError("pilot must contain exactly 300 executions")
    episode_ids = [row["episode_id"] for row in episodes]
    if len(episode_ids) != len(set(episode_ids)):
        raise VerificationError("episode identifiers are not unique")

    expected_cells = {
        (condition, scenario): len(SEEDS)
        for condition in CONDITIONS
        for scenario in SCENARIOS
    }
    observed_cells = Counter((row["condition"], row["scenario"]) for row in episodes)
    if dict(observed_cells) != expected_cells:
        raise VerificationError("condition/scenario cells are incomplete")
    if {row["seed"] for row in episodes} != set(SEEDS):
        raise VerificationError("fixture variant set is incomplete")

    hashes_by_case: dict[str, set[str]] = defaultdict(set)
    conditions_by_case: dict[str, set[str]] = defaultdict(set)
    for row in episodes:
        if row["pilot_id"] != PILOT_ID:
            raise VerificationError("episode pilot identifier mismatch")
        hashes_by_case[row["case_id"]].add(row["oracle_case_hash"])
        conditions_by_case[row["case_id"]].add(row["condition"])
        metrics = row["evidence_metrics"]
        if any(
            metrics[field] != 0
            for field in ("model_calls", "input_tokens", "output_tokens", "network_calls")
        ):
            raise VerificationError("credential-free execution counters are non-zero")
    if any(len(values) != 1 for values in hashes_by_case.values()):
        raise VerificationError("oracle hashes differ across conditions for one case")
    if any(values != set(CONDITIONS) for values in conditions_by_case.values()):
        raise VerificationError("a case is missing an evidence condition")

    recomputed = summarise(episodes)
    if canonical_json(recomputed) != canonical_json(summary):
        raise VerificationError("summary does not match recomputed episode results")
    _verify_gate_counterfactuals(episodes)
    _verify_deterministic_regeneration(directory)
    return {"pilot_id": PILOT_ID, "episodes": len(episodes), "cases": len(hashes_by_case)}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("result_directory", type=Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        result = verify_release(args.result_directory)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print(f"verification failed: {exc}", file=sys.stderr)
        return 1
    print(
        f"verified {result['pilot_id']}: {result['episodes']} executions, "
        f"{result['cases']} oracle cases"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
