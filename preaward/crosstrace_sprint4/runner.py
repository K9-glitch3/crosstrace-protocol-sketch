"""Write a deterministic, development-only six-cell release."""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import platform
import sqlite3
import ssl
import sys
from pathlib import Path
from typing import Any, Mapping, Sequence

from crosstrace_sketch.protocol import canonical_json

from .fixtures import load_fixture_configs
from .harness import HarnessRun, run_matrix
from .model import CELL_SPECS, CLAIM_LEVEL, HARNESS_VERSION, RELEASE_ID, object_hash

DETERMINISTIC_FILES = (
    "fixtures.resolved.json",
    "manifest.resolved.json",
    "bundles.jsonl",
    "executions.jsonl",
    "invariance.json",
    "summary.json",
    "REPORT.md",
)
INTEGRITY_FILES = (*DETERMINISTIC_FILES, "environment.json")

SOURCE_PATHS = (
    "LICENSE",
    "pyproject.toml",
    "preaward/__init__.py",
    "preaward/README.md",
    "preaward/DEVELOPMENT_CLAIMS_BOUNDARY.md",
    "preaward/REVIEWER_REPRODUCTION.md",
    "preaward/crosstrace_sprint1/__init__.py",
    "preaward/crosstrace_sprint1/delivery.py",
    "preaward/crosstrace_sprint2/__init__.py",
    "preaward/crosstrace_sprint2/crypto_compat.py",
    "preaward/crosstrace_sprint2/model.py",
    "preaward/crosstrace_sprint2/validation.py",
    "preaward/crosstrace_sprint3/__init__.py",
    "preaward/crosstrace_sprint3/crypto_compat.py",
    "preaward/crosstrace_sprint3/model.py",
    "preaward/crosstrace_sprint3/permit.py",
    "preaward/crosstrace_sprint3/gate.py",
    "preaward/crosstrace_sprint3/README.md",
    "preaward/crosstrace_sprint4/__init__.py",
    "preaward/crosstrace_sprint4/model.py",
    "preaward/crosstrace_sprint4/fixtures.py",
    "preaward/crosstrace_sprint4/encoding.py",
    "preaward/crosstrace_sprint4/chain.py",
    "preaward/crosstrace_sprint4/harness.py",
    "preaward/crosstrace_sprint4/runner.py",
    "preaward/crosstrace_sprint4/verify.py",
    "preaward/crosstrace_sprint4/README.md",
    "preaward/crosstrace_sprint4/THREAT_TO_TEST.md",
    "preaward/crosstrace_sprint4/fixtures/development-v0.1.json",
    "preaward/crosstrace_sprint4/schemas/six-cell-bundle.schema.json",
    "preaward/crosstrace_sprint4/schemas/six-cell-execution.schema.json",
    "preaward/crosstrace_sprint4/schemas/six-cell-manifest.schema.json",
    "src/crosstrace_sketch/__init__.py",
    "src/crosstrace_sketch/protocol.py",
    "THREAT_MODEL.md",
    "tests/test_delivery.py",
    "tests/test_sprint2_evidence.py",
    "tests/test_sprint3_common_gate.py",
    "tests/test_sprint4_harness.py",
    "schema/authority-status.schema.json",
    "schema/common-gate-input.schema.json",
    "schema/common-gate-decision.schema.json",
    "schema/neutral-permit-state.schema.json",
    "schema/delivery-observation.schema.json",
    "schema/delivery-schedule.schema.json",
    "schema/evidence-message.schema.json",
    "schema/handoff-receipt.schema.json",
    "schema/neutral-handoff.schema.json",
    "schema/payment-action.schema.json",
    "schema/signed-endpoint-record.schema.json",
    "schema/cross-referenced-record.schema.json",
    "schema/validated-handoff.schema.json",
)


def repository_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _normalised_source_bytes(path: Path) -> bytes:
    body = path.read_bytes()
    if path.suffix.lower() in {".json", ".md", ".py", ".toml"}:
        return body.replace(b"\r\n", b"\n").replace(b"\r", b"\n")
    return body


def source_manifest() -> tuple[tuple[dict[str, str], ...], str]:
    root = repository_root()
    missing = [relative for relative in SOURCE_PATHS if not (root / relative).is_file()]
    if missing:
        raise ValueError(f"release source closure is incomplete: {', '.join(missing)}")
    rows: list[dict[str, str]] = []
    digest = hashlib.sha256()
    for relative in SOURCE_PATHS:
        path = root / relative
        body = _normalised_source_bytes(path)
        body_hash = hashlib.sha256(body).hexdigest()
        rows.append({"path": relative, "sha256": body_hash})
        encoded_path = relative.encode("utf-8")
        digest.update(len(encoded_path).to_bytes(4, "big"))
        digest.update(encoded_path)
        digest.update(len(body).to_bytes(8, "big"))
        digest.update(body)
    return tuple(rows), "sha256:" + digest.hexdigest()


def _write_json(path: Path, value: Mapping[str, Any]) -> None:
    path.write_bytes(canonical_json(dict(value)) + b"\n")


def _write_jsonl(path: Path, rows: Sequence[Mapping[str, Any]]) -> None:
    path.write_bytes(b"".join(canonical_json(dict(row)) + b"\n" for row in rows))


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def resolved_fixture() -> dict[str, Any]:
    configs = load_fixture_configs()
    source = {
        "version": "crosstrace-six-cell-fixtures/0.1",
        "fixture_set_id": RELEASE_ID,
        "classification": "DEVELOPMENT_ONLY",
        "cases": [item.to_dict() for item in configs],
    }
    return {
        **source,
        "source_hash": "sha256:" + hashlib.sha256(canonical_json(source)).hexdigest(),
    }


def resolved_manifest(run: HarnessRun, fixture: Mapping[str, Any]) -> dict[str, Any]:
    sources, tree_hash = source_manifest()
    fixture_hash = object_hash("SPRINT4_RESOLVED_FIXTURE", dict(fixture))
    return {
        "version": HARNESS_VERSION,
        "release_id": RELEASE_ID,
        "claim_level": CLAIM_LEVEL,
        "classification": "DEVELOPMENT_ONLY",
        "cells": [item.to_dict() for item in CELL_SPECS],
        "fixture_count": len(fixture["cases"]),
        "bundle_count": len(run.bundles),
        "execution_count": len(run.executions),
        "unit": "one synthetic fixture encoding and enforcement branch",
        "fixture_hash": fixture_hash,
        "source_tree_hash": tree_hash,
        "source_files": list(sources),
        "deterministic_files": list(DETERMINISTIC_FILES),
        "policies": {
            "engineering_only": True,
            "independent_trials": False,
            "model_calls": 0,
            "runtime_network_calls": 0,
            "synthetic_adapter": True,
        },
    }


def render_report(run: HarnessRun) -> str:
    lines = [
        "# CrossTrace six-cell development harness v0.1",
        "",
        "> **Claim boundary:** deterministic pre-award engineering conformance only.",
        "> These hand-written encodings are not trials, calibration data, held-out",
        "> material, or evidence that any representation improves AI safety.",
        "",
        "The runner made no model, network, wallet, or payment-service calls. Actions",
        "below are in-memory adapter branches. Counts describe exercised code paths,",
        "not rates or treatment effects.",
        "",
        "## Case matrix",
        "",
        "| Case | SL-GATE | CR-GATE | PR-GATE | Audit chain (SL/CR/PR) |",
        "|---|---|---|---|---|",
    ]
    executions = {(row["case_id"], row["cell_id"]): row for row in run.executions}
    case_ids = [item.case_id for item in load_fixture_configs()]
    for case_id in case_ids:
        verdicts = []
        for representation in ("SL", "CR", "PR"):
            row = executions[(case_id, f"{representation}-GATE")]
            verdicts.append(
                " -> ".join(item["verdict"] for item in row["gate"]["decisions"])
            )
        chains = "/".join(
            executions[(case_id, f"{representation}-AUDIT")]["audit_validation"][
                "chain_status"
            ]
            for representation in ("SL", "CR", "PR")
        )
        lines.append(
            f"| {case_id} | {verdicts[0]} | {verdicts[1]} | {verdicts[2]} | {chains} |"
        )
    lines.extend(
        [
            "",
            "## Verification",
            "",
            f"- Cells: {len(CELL_SPECS)}",
            f"- Fixtures: {run.summary['fixture_count']}",
            f"- Deterministic branch executions: {run.summary['execution_count']}",
            f"- Invariant violations: {run.summary['invariant_violations']}",
            "- Model calls: 0",
            "- Runtime network calls: 0",
            "",
            "Run `python -m preaward.crosstrace_sprint4.verify <directory>` to",
            "check integrity, recompute all rows, and compare deterministic artifacts.",
            "",
        ]
    )
    return "\n".join(lines)


def write_release(*, output_dir: Path) -> Path:
    if output_dir.exists() and any(output_dir.iterdir()):
        raise ValueError("output directory must not already contain files")
    run = run_matrix()
    if run.invariance["violation_count"]:
        raise ValueError("Sprint 4 invariants failed; refusing to write a release")
    fixture = resolved_fixture()
    manifest = resolved_manifest(run, fixture)
    output_dir.mkdir(parents=True, exist_ok=True)
    _write_json(output_dir / "fixtures.resolved.json", fixture)
    _write_json(output_dir / "manifest.resolved.json", manifest)
    _write_jsonl(output_dir / "bundles.jsonl", run.bundles)
    _write_jsonl(output_dir / "executions.jsonl", run.executions)
    _write_json(output_dir / "invariance.json", run.invariance)
    _write_json(output_dir / "summary.json", run.summary)
    (output_dir / "REPORT.md").write_text(
        render_report(run), encoding="utf-8", newline="\n"
    )
    environment = {
        "python": platform.python_version(),
        "implementation": platform.python_implementation(),
        "platform": platform.platform(),
        "cryptography": importlib.metadata.version("cryptography"),
        "jsonschema": importlib.metadata.version("jsonschema"),
        "sqlite": sqlite3.sqlite_version,
        "openssl": ssl.OPENSSL_VERSION,
        "model_calls": 0,
        "runtime_network_calls": 0,
    }
    _write_json(output_dir / "environment.json", environment)
    checksum_lines = [
        f"{_sha256(output_dir / name)}  {name}" for name in INTEGRITY_FILES
    ]
    (output_dir / "checksums.sha256").write_text(
        "\n".join(checksum_lines) + "\n", encoding="ascii", newline="\n"
    )
    return output_dir


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    path = write_release(output_dir=args.output_dir)
    print(f"wrote {RELEASE_ID} to {path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
