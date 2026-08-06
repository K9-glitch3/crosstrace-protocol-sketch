from __future__ import annotations

import json
import shutil
from copy import deepcopy
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from crosstrace_sketch.pilot.baselines import build_evidence, evaluate_condition
from crosstrace_sketch.pilot.model import CONDITIONS, SCENARIOS
from crosstrace_sketch.pilot.runner import CORE_FILES, write_release
from crosstrace_sketch.pilot.scenarios import build_seed_case
from crosstrace_sketch.pilot.verify import VerificationError, verify_release
from crosstrace_sketch.protocol import canonical_json


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="module")
def pilot_release(tmp_path_factory: pytest.TempPathFactory) -> Path:
    return write_release(output_dir=tmp_path_factory.mktemp("pilot-release"))


def test_declared_manifest_and_all_episode_rows_match_schemas(pilot_release: Path) -> None:
    manifest_schema = json.loads(
        (REPOSITORY_ROOT / "pilot" / "schemas" / "pilot-manifest.schema.json").read_text(
            encoding="utf-8"
        )
    )
    episode_schema = json.loads(
        (REPOSITORY_ROOT / "pilot" / "schemas" / "episode-result.schema.json").read_text(
            encoding="utf-8"
        )
    )
    Draft202012Validator.check_schema(manifest_schema)
    Draft202012Validator.check_schema(episode_schema)
    manifest = json.loads(
        (REPOSITORY_ROOT / "pilot" / "manifests" / "pilot-v0.1.json").read_text(
            encoding="utf-8"
        )
    )
    Draft202012Validator(manifest_schema).validate(manifest)
    release_schema = json.loads(
        (pilot_release / "pilot-release-manifest.schema.json").read_text(
            encoding="utf-8"
        )
    )
    Draft202012Validator.check_schema(release_schema)
    resolved_manifest = json.loads(
        (pilot_release / "manifest.resolved.json").read_text(encoding="utf-8")
    )
    Draft202012Validator(release_schema).validate(resolved_manifest)
    validator = Draft202012Validator(episode_schema)
    for line in (pilot_release / "episodes.jsonl").read_text(encoding="utf-8").splitlines():
        validator.validate(json.loads(line))


def test_serialized_evaluator_artifacts_contain_no_oracle_or_scenario_label() -> None:
    case = build_seed_case(0)
    for scenario in SCENARIOS:
        for condition in CONDITIONS:
            artifact = build_evidence(case, scenario, condition)
            assert "scenario" not in artifact
            assert "oracle" not in artifact
            assert "expected_fault" not in artifact


def test_controls_are_independently_encoded_from_neutral_events() -> None:
    case = build_seed_case(0)
    ordinary = build_evidence(case, "valid_current_within_scope", "ordinary_local_logs")
    isolated = build_evidence(case, "valid_current_within_scope", "isolated_signed_logs")
    ordinary_bytes = canonical_json(ordinary["evidence"])
    isolated_bytes = canonical_json(isolated["evidence"])
    assert b"previous_receipt_id" not in ordinary_bytes
    assert b"receipt_id" not in ordinary_bytes
    assert b"proposal_hash" not in ordinary_bytes
    assert b"previous_receipt_id" not in isolated_bytes
    first, second = isolated["evidence"]["signed_local_records"][:2]
    assert first["body"]["holder_principal_id"] != second["body"]["holder_principal_id"]
    assert first["body"]["local_event_id"] != second["body"]["local_event_id"]


def test_invalid_local_signatures_and_broken_central_chain_are_not_used() -> None:
    case = build_seed_case(0)
    isolated = build_evidence(case, "valid_current_within_scope", "isolated_signed_logs")
    tampered_isolated = deepcopy(isolated)
    target_interaction = case["middle"]["proposal"]["interaction_id"]
    for entry in tampered_isolated["evidence"]["signed_local_records"]:
        if entry["body"]["event"]["interaction_id"] == target_interaction:
            entry["signature"] = "AA"
    result = evaluate_condition(tampered_isolated)
    assert all(
        target_interaction not in {step[0] for step in path}
        for path in result["reconstructed_paths"]
    )

    central = build_evidence(case, "valid_current_within_scope", "central_append_only_log")
    tampered_central = deepcopy(central)
    tampered_central["evidence"]["entries"][1]["event"]["request_hash"] = "sha256:" + "0" * 64
    central_result = evaluate_condition(tampered_central)
    assert central_result["evidence_metrics"]["records_observed"] == 1


def test_release_verifier_recomputes_matrix_and_counterfactuals(pilot_release: Path) -> None:
    result = verify_release(pilot_release)
    assert result == {
        "pilot_id": "crosstrace-scripted-systems-pilot-v0.1",
        "episodes": 300,
        "cases": 60,
    }


def test_two_runs_have_identical_core_files(tmp_path: Path) -> None:
    first = write_release(output_dir=tmp_path / "first")
    second = write_release(output_dir=tmp_path / "second")
    for name in (*CORE_FILES, "checksums.sha256"):
        assert (first / name).read_bytes() == (second / name).read_bytes()


def test_verifier_rejects_tampered_summary_even_with_updated_checksum(
    pilot_release: Path, tmp_path: Path
) -> None:
    tampered = tmp_path / "tampered"
    shutil.copytree(pilot_release, tampered)
    summary_path = tampered / "summary.json"
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    summary["design"]["episodes"] = 299
    summary_path.write_bytes(canonical_json(summary) + b"\n")

    checksum_path = tampered / "checksums.sha256"
    lines = []
    import hashlib

    for name in CORE_FILES:
        digest = hashlib.sha256((tampered / name).read_bytes()).hexdigest()
        lines.append(f"{digest}  {name}")
    checksum_path.write_text("\n".join(lines) + "\n", encoding="ascii", newline="\n")
    with pytest.raises(VerificationError, match="summary does not match"):
        verify_release(tampered)
