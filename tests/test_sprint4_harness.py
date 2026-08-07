"""Development-only tests for the deterministic Sprint 4 six-cell harness."""

from __future__ import annotations

import hashlib
import importlib.metadata
import shutil
from pathlib import Path

import pytest

from crosstrace_sketch.protocol import canonical_json, content_id, loads_strict
from preaward.crosstrace_sprint4.fixtures import (
    fixture_manifest_path,
    load_fixture_configs,
)
from preaward.crosstrace_sprint4.harness import (
    HarnessRun,
    _forbidden_gate_input_fields,
    run_matrix,
)
from preaward.crosstrace_sprint4.model import CELL_SPECS
from preaward.crosstrace_sprint4.runner import (
    INTEGRITY_FILES,
    SOURCE_PATHS,
    _normalised_source_bytes,
    write_release,
)
from preaward.crosstrace_sprint4.verify import VerificationError, verify_release


@pytest.fixture(scope="module")
def run() -> HarnessRun:
    return run_matrix()


@pytest.fixture(scope="module")
def release_dir(tmp_path_factory: pytest.TempPathFactory) -> Path:
    path = tmp_path_factory.mktemp("sprint4_release") / "release"
    return write_release(output_dir=path)


def _execution(run: HarnessRun, case_id: str, cell_id: str) -> dict:
    return next(
        row
        for row in run.executions
        if row["case_id"] == case_id and row["cell_id"] == cell_id
    )


def _bundle(run: HarnessRun, case_id: str, representation: str) -> dict:
    return next(
        row
        for row in run.bundles
        if row["case_id"] == case_id and row["representation"] == representation
    )


def _rewrite_checksums(directory: Path) -> None:
    lines = [
        f"{hashlib.sha256((directory / name).read_bytes()).hexdigest()}  {name}"
        for name in INTEGRITY_FILES
    ]
    (directory / "checksums.sha256").write_text(
        "\n".join(lines) + "\n", encoding="ascii", newline="\n"
    )


def test_gate_input_metadata_filter_is_prefix_aware() -> None:
    value = {
        "safe": {"oracle-hint": "hidden", "future_value": 1},
        "delivery_schedule": {},
        "representation": "PR",
    }
    assert _forbidden_gate_input_fields(value) == {
        "oracle-hint",
        "future_value",
        "delivery_schedule",
        "representation",
    }


def test_exact_48_row_matrix_and_invariants(run: HarnessRun) -> None:
    assert len(run.bundles) == 24
    assert len(run.executions) == 48
    assert run.invariance["violation_count"] == 0
    assert all(check["passed"] for check in run.invariance["checks"])
    assert {row["cell_id"] for row in run.executions} == {
        cell.cell_id for cell in CELL_SPECS
    }


def test_neutral_transport_and_enforcement_bundle_invariance(run: HarnessRun) -> None:
    for case_id in {row["case_id"] for row in run.executions}:
        bundles = [row for row in run.bundles if row["case_id"] == case_id]
        for field in (
            "neutral_trace_hash",
            "action_hash",
            "slot_manifest_hash",
            "transport_projection_hash",
        ):
            assert len({row[field] for row in bundles}) == 1
        for representation in ("SL", "CR", "PR"):
            pair = [
                row
                for row in run.executions
                if row["case_id"] == case_id and row["representation"] == representation
            ]
            assert len({row["bundle_id"] for row in pair}) == 1


def test_sender_records_match_and_pr_endpoint_copies_are_equal(run: HarnessRun) -> None:
    for case_id in {row["case_id"] for row in run.executions}:
        sl = _bundle(run, case_id, "SL")
        cr = _bundle(run, case_id, "CR")
        pr = _bundle(run, case_id, "PR")
        assert sl["endpoint_sender_bytes_b64"] == cr["endpoint_sender_bytes_b64"]
        assert pr["pr_copy_pairs_equal"] is True


def test_one_retained_receipt_copy_is_the_only_intended_representation_difference(
    run: HarnessRun,
) -> None:
    case_id = "one-leaf-receiver-locally-withheld"
    assert (
        _execution(run, case_id, "SL-GATE")["gate"]["decisions"][0]["verdict"]
        == "PAUSE"
    )
    assert (
        _execution(run, case_id, "CR-GATE")["gate"]["decisions"][0]["verdict"]
        == "PAUSE"
    )
    assert (
        _execution(run, case_id, "PR-GATE")["gate"]["decisions"][0]["verdict"]
        == "ALLOW"
    )
    for representation in ("SL", "CR", "PR"):
        assert (
            _execution(run, case_id, f"{representation}-AUDIT")["audit_validation"][
                "chain_status"
            ]
            == "COMPLETE"
        )


def test_equivalent_complete_evidence_has_identical_gate_result(
    run: HarnessRun,
) -> None:
    for case_id in (
        "complete",
        "status-delayed-locally-audit-visible",
        "higher-revocation",
        "out-of-scope",
        "replay",
    ):
        signatures = {
            tuple(
                (decision["verdict"], tuple(decision["reasons"]))
                for decision in _execution(run, case_id, f"{representation}-GATE")[
                    "gate"
                ]["decisions"]
            )
            for representation in ("SL", "CR", "PR")
        }
        assert len(signatures) == 1


def test_status_scope_conflict_and_missing_evidence_branches(run: HarnessRun) -> None:
    expected = {
        "both-leaf-copies-locally-withheld": {"LEAF_MISSING"},
        "status-delayed-locally-audit-visible": {"STATUS_MISSING"},
        "higher-revocation": {
            "AUTHORITY_REVOKED",
            "AUTHORITY_VERSION_STALE",
            "REVOCATION_STATUS_STALE",
        },
        "out-of-scope": {"ACTION_OUT_OF_SCOPE"},
        "authenticated-conflicting-leaf": {"EQUIVOCATION"},
    }
    for case_id, reasons in expected.items():
        for representation in ("SL", "CR", "PR"):
            decision = _execution(run, case_id, f"{representation}-GATE")["gate"][
                "decisions"
            ][0]
            assert decision["verdict"] == "PAUSE"
            assert set(decision["reasons"]) == reasons


def test_replay_consumes_once_then_pauses_without_second_adapter_call(
    run: HarnessRun,
) -> None:
    for representation in ("SL", "CR", "PR"):
        row = _execution(run, "replay", f"{representation}-GATE")
        assert [item["verdict"] for item in row["gate"]["decisions"]] == [
            "ALLOW",
            "PAUSE",
        ]
        assert row["gate"]["decisions"][1]["reasons"] == ["REPLAY_DETECTED"]
        assert [item["attempted"] for item in row["adapter_attempts"]] == [True, False]
        assert row["engineering_counts"]["adapter_calls"] == 1


def test_pause_never_reaches_adapter_and_audit_never_mutates_permits(
    run: HarnessRun,
) -> None:
    for row in run.executions:
        if row["enforcement"] == "AUDIT":
            assert row["gate"]["invoked"] is False
            assert row["gate"]["permit_reservations"] == 0
            assert row["gate"]["permit_store_mutations"] == 0
        else:
            for decision, attempt in zip(
                row["gate"]["decisions"], row["adapter_attempts"], strict=True
            ):
                if decision["verdict"] == "PAUSE":
                    assert attempt["attempted"] is False
                    assert attempt["committed"] is False


def test_common_gate_input_has_no_evaluator_or_representation_labels(
    run: HarnessRun,
) -> None:
    for row in run.executions:
        assert row["gate"]["common_input_forbidden_fields"] == []
        counts = row["engineering_counts"]
        assert counts["model_calls"] == 0
        assert counts["runtime_network_calls"] == 0


def test_reversing_encoder_inputs_is_byte_deterministic(run: HarnessRun) -> None:
    reversed_run = run_matrix(reverse_input_order=True)
    assert reversed_run.bundles == run.bundles
    assert reversed_run.executions == run.executions
    assert reversed_run.invariance == run.invariance
    assert reversed_run.summary == run.summary


def test_fixture_loading_and_hashing_are_line_ending_invariant(tmp_path: Path) -> None:
    original = fixture_manifest_path().read_bytes().replace(b"\r\n", b"\n")
    lf = tmp_path / "lf.json"
    crlf = tmp_path / "crlf.json"
    lf.write_bytes(original)
    crlf.write_bytes(original.replace(b"\n", b"\r\n"))
    assert load_fixture_configs(lf) == load_fixture_configs(crlf)
    assert _normalised_source_bytes(lf) == _normalised_source_bytes(crlf)


def test_release_verifies_and_regenerates(release_dir: Path) -> None:
    result = verify_release(release_dir, regenerate=True)
    assert result == {
        "release_id": "crosstrace-six-cell-development-v0.1",
        "cells": 6,
        "fixtures": 8,
        "executions": 48,
        "invariant_violations": 0,
    }
    environment = loads_strict(
        (release_dir / "environment.json").read_bytes().removesuffix(b"\n")
    )
    assert environment["cryptography"] == importlib.metadata.version("cryptography")
    assert environment["jsonschema"] == importlib.metadata.version("jsonschema")


def test_tampering_fails_even_after_checksums_are_rewritten(
    release_dir: Path, tmp_path: Path
) -> None:
    tampered = tmp_path / "tampered"
    shutil.copytree(release_dir, tampered)
    rows = [
        loads_strict(line)
        for line in (tampered / "executions.jsonl").read_bytes().splitlines()
    ]
    rows[0]["engineering_counts"]["adapter_calls"] += 1
    body = dict(rows[0])
    body.pop("execution_id")
    rows[0]["execution_id"] = content_id("SPRINT4_EXECUTION", body)
    (tampered / "executions.jsonl").write_bytes(
        b"".join(canonical_json(row) + b"\n" for row in rows)
    )
    _rewrite_checksums(tampered)
    with pytest.raises(VerificationError):
        verify_release(tampered, regenerate=False)


def test_unexpected_release_file_and_nonempty_output_are_rejected(
    release_dir: Path, tmp_path: Path
) -> None:
    stale = tmp_path / "stale-release"
    shutil.copytree(release_dir, stale)
    (stale / "unexpected.txt").write_text("stale", encoding="ascii")
    with pytest.raises(VerificationError, match="file set"):
        verify_release(stale, regenerate=False)

    stale_directory = tmp_path / "stale-directory-release"
    shutil.copytree(release_dir, stale_directory)
    (stale_directory / "unexpected-directory").mkdir()
    with pytest.raises(VerificationError, match="file set"):
        verify_release(stale_directory, regenerate=False)

    nonempty = tmp_path / "nonempty-output"
    nonempty.mkdir()
    (nonempty / "unrelated.txt").write_text("keep", encoding="ascii")
    with pytest.raises(ValueError, match="must not already contain"):
        write_release(output_dir=nonempty)
    assert (nonempty / "unrelated.txt").read_text(encoding="ascii") == "keep"


def test_source_closure_is_explicit_and_contains_no_user_files() -> None:
    assert len(SOURCE_PATHS) == len(set(SOURCE_PATHS))
    assert "src/crosstrace_sketch/__init__.py" in SOURCE_PATHS
    assert "THREAT_MODEL.md" in SOURCE_PATHS
    assert "tests/test_delivery.py" in SOURCE_PATHS
    assert "tests/test_sprint2_evidence.py" in SOURCE_PATHS
    assert "tests/test_sprint3_common_gate.py" in SOURCE_PATHS
    assert "tests/test_sprint4_harness.py" in SOURCE_PATHS
    assert "schema/common-gate-input.schema.json" in SOURCE_PATHS
    assert "schema/common-gate-decision.schema.json" in SOURCE_PATHS
    assert "schema/neutral-permit-state.schema.json" in SOURCE_PATHS
    assert not any(
        path in {"RELEASE_CHECKLIST.md", "docs/LICENSING.md"} for path in SOURCE_PATHS
    )
