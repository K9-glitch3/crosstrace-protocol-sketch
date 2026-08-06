"""Run the deterministic, credential-free CrossTrace P0 systems pilot."""

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

from .baselines import build_evidence, evaluate_condition
from .model import CONDITIONS, PILOT_ID, SCENARIOS, SEEDS
from .scenarios import build_seed_case, oracle_for
from .scoring import score_episode, summarise


CORE_FILES = (
    "pilot-release-manifest.schema.json",
    "manifest.resolved.json",
    "episodes.jsonl",
    "summary.json",
    "REPORT.md",
)


def repository_root() -> Path:
    return Path(__file__).resolve().parents[3]


def _load_declared_manifest(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    expected = {
        "pilot_id": PILOT_ID,
        "conditions": list(CONDITIONS),
        "scenarios": list(SCENARIOS),
        "seeds": list(SEEDS),
    }
    for field, value in expected.items():
        if data.get(field) != value:
            raise ValueError(f"manifest {field!r} does not match the implemented pilot")
    return data


def run_episodes() -> list[dict[str, Any]]:
    """Execute all 300 scripted condition/scenario/seed episodes."""

    episodes: list[dict[str, Any]] = []
    for scenario in SCENARIOS:
        for seed in SEEDS:
            case = build_seed_case(seed)
            oracle = oracle_for(case, scenario, seed)
            for condition in CONDITIONS:
                artifact = build_evidence(case, scenario, condition)
                observation = evaluate_condition(artifact)
                episodes.append(
                    score_episode(
                        oracle=oracle,
                        condition=condition,
                        observation=observation,
                    )
                )
    return sorted(
        episodes,
        key=lambda row: (row["scenario"], row["seed"], row["condition"]),
    )


def _write_json(path: Path, value: Mapping[str, Any]) -> None:
    path.write_bytes(canonical_json(value) + b"\n")


def _write_jsonl(path: Path, rows: Sequence[Mapping[str, Any]]) -> None:
    body = b"".join(canonical_json(row) + b"\n" for row in rows)
    path.write_bytes(body)


def _pct(metric: Mapping[str, Any]) -> str:
    denominator = metric["denominator"]
    return "--" if not denominator else f"{100 * metric['count'] / denominator:.1f}%"


def _mean(metric: Mapping[str, Any]) -> str:
    denominator = metric["denominator"]
    return "--" if not denominator else f"{metric['total'] / denominator:.1f}"


def render_report(summary: Mapping[str, Any]) -> str:
    lines = [
        "# CrossTrace scripted systems pilot v0.1",
        "",
        "> **Claim boundary:** This is a deterministic, credential-free protocol",
        "> conformance pilot over synthetic fixtures. It uses no LLM or frontier-agent",
        "> traffic and is not evidence that CrossTrace improves real-world AI safety.",
        "",
        "## Design",
        "",
        "Five evidence conditions were exercised against six declared scenarios and ten",
        "deterministic fixture variants per cell (300 executions). The variants change",
        "identifiers, times, resources, and amounts; they are not independent statistical",
        "trials. The hidden oracle was used only by",
        "the scorer; it was not passed to the evidence conditions or ActionGate.",
        "",
        "## Aggregate scripted outcomes",
        "",
        "| Condition | Exact path | Unauthorised simulated action | Attempt prevented | Legitimate completion | False pause | Unsupported attributions | Mean retained bytes |",
        "|---|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for condition in CONDITIONS:
        row = summary["by_condition"][condition]
        lines.append(
            "| "
            + " | ".join(
                [
                    condition.replace("_", " "),
                    _pct(row["exact_path_reconstruction"]),
                    _pct(row["unauthorised_simulated_action_executed"]),
                    _pct(row["unauthorised_attempt_prevented"]),
                    _pct(row["legitimate_task_completed"]),
                    _pct(row["false_pause"]),
                    str(row["unsupported_principal_attributions"]),
                    _mean(row["canonical_evidence_bytes"]),
                ]
            )
            + " |"
        )
    lines.extend(
        [
            "",
            "Every rate is stored as an integer count and denominator in `summary.json`.",
            "Action denominators are attempt-level because replay and equivocation contain",
            "two attempts. Retained bytes are the serialized joined evidence, including",
            "each visible endpoint copy; they are not network-transfer or runtime costs.",
            "",
            "## What this run can establish",
            "",
            "- the declared fixtures execute reproducibly without credentials or network access;",
            "- controls are independently encoded from neutral events; only the paired",
            "  conditions retain CrossTrace receipt IDs and jointly attested proposal bytes;",
            "- the current verifier accepts valid evidence and pauses on the scripted",
            "  revocation, limit, and local-replay cases when supplied a complete receipt",
            "  chain and the declared current signed status;",
            "- two isolated stores can both authorise conflicting leaves, while a merged",
            "  local view detects the conflict after observation; and",
            "- every episode carries the hash of the same per-case oracle across conditions.",
            "",
            "## What this run cannot establish",
            "",
            "It does not model evidence delivery, status propagation or decision-time",
            "partial observability. It does not estimate real-agent failure rates, provide",
            "independent trials, solve global fork prevention, model collusion or key",
            "compromise, establish external validity, or support a",
            "claim of improved safety. Those are proposed research questions, not results.",
            "",
            "Run `python -m crosstrace_sketch.pilot.verify <result-directory>` to",
            "recompute the summary and verify the release checksums.",
            "",
        ]
    )
    return "\n".join(lines)


def source_tree_hash(root: Path) -> str:
    candidates = [
        *(root / "src").rglob("*.py"),
        *(root / "pilot" / "manifests").rglob("*.json"),
        *(root / "pilot" / "schemas").rglob("*.json"),
        *(root / "pilot").glob("*.md"),
        root / "pyproject.toml",
        root / "README.md",
        root / "THREAT_MODEL.md",
    ]
    digest = hashlib.sha256()
    for path in sorted({path for path in candidates if path.is_file()}):
        relative = path.relative_to(root).as_posix().encode("utf-8")
        digest.update(len(relative).to_bytes(4, "big"))
        digest.update(relative)
        body = path.read_bytes()
        if path.suffix.lower() in {".json", ".md", ".py", ".toml"}:
            body = body.replace(b"\r\n", b"\n").replace(b"\r", b"\n")
        digest.update(len(body).to_bytes(8, "big"))
        digest.update(body)
    return "sha256:" + digest.hexdigest()


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def write_release(*, output_dir: Path, manifest_path: Path | None = None) -> Path:
    """Write one deterministic result release and return its directory."""

    root = repository_root()
    declared_path = manifest_path or root / "pilot" / "manifests" / "pilot-v0.1.json"
    manifest = _load_declared_manifest(declared_path)
    episodes = run_episodes()
    summary = summarise(episodes)

    output_dir.mkdir(parents=True, exist_ok=True)
    resolved = {
        **manifest,
        "$schema": "pilot-release-manifest.schema.json",
        "episode_count": len(episodes),
        "implementation": {
            "package": "crosstrace-protocol-sketch",
            "package_version": "0.1.0",
            "runner": "crosstrace_sketch.pilot.runner",
            "source_tree_hash": source_tree_hash(root),
        },
    }
    release_schema = json.loads(
        (root / "pilot" / "schemas" / "pilot-release-manifest.schema.json").read_text(
            encoding="utf-8"
        )
    )
    _write_json(output_dir / "pilot-release-manifest.schema.json", release_schema)
    _write_json(output_dir / "manifest.resolved.json", resolved)
    _write_jsonl(output_dir / "episodes.jsonl", episodes)
    _write_json(output_dir / "summary.json", summary)
    with (output_dir / "REPORT.md").open("w", encoding="utf-8", newline="\n") as handle:
        handle.write(render_report(summary))
    environment = {
        "python": platform.python_version(),
        "implementation": platform.python_implementation(),
        "platform": platform.platform(),
        "cryptography": importlib.metadata.version("cryptography"),
        "sqlite": sqlite3.sqlite_version,
        "openssl": ssl.OPENSSL_VERSION,
        "model_calls": 0,
        "network_calls": 0,
    }
    _write_json(output_dir / "environment.json", environment)
    checksum_lines = [f"{_sha256(output_dir / name)}  {name}" for name in CORE_FILES]
    with (output_dir / "checksums.sha256").open(
        "w", encoding="ascii", newline="\n"
    ) as handle:
        handle.write("\n".join(checksum_lines) + "\n")
    return output_dir


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=repository_root() / "pilot" / "results" / "pilot-v0.1",
        help="directory for the deterministic result release",
    )
    parser.add_argument(
        "--manifest",
        type=Path,
        default=None,
        help="declared pilot manifest (defaults to pilot/manifests/pilot-v0.1.json)",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    path = write_release(output_dir=args.output_dir, manifest_path=args.manifest)
    print(f"wrote {PILOT_ID} to {path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
