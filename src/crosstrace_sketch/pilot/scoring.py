"""Oracle-only scoring and deterministic pilot summaries."""

from __future__ import annotations

from collections import defaultdict
from typing import Any, Iterable, Mapping, Sequence

from crosstrace_sketch.protocol import canonical_json

from .model import CONDITIONS, PILOT_ID, SCENARIOS, OracleCase


FAULT_DETECTORS = {
    "EQUIVOCATION": (
        "conflicting_record_detected",
        "joined_view_conflict_detected",
    ),
    "WITHHELD_RECORD": ("endpoint_copy_missing_detected",),
    "AUTHORITY_REVOKED": ("authenticated_revocation_detected",),
    "ACTION_OUT_OF_SCOPE": ("out_of_scope_action_observed",),
    "REPLAY_DETECTED": (
        "duplicate_executed_action_observed",
        "replay_attempt_blocked",
    ),
}


def _normalise_paths(paths: Sequence[Sequence[Sequence[str]]]) -> list[list[list[str]]]:
    normalised = [[list(step) for step in path] for path in paths]
    return sorted(normalised, key=canonical_json)


def score_episode(
    *,
    oracle: OracleCase,
    condition: str,
    observation: Mapping[str, Any],
) -> dict[str, Any]:
    """Compare one evaluator output with scorer-only ground truth."""

    if condition not in CONDITIONS:
        raise ValueError(f"unknown pilot condition: {condition}")
    observed_paths = _normalise_paths(observation["reconstructed_paths"])
    oracle_paths = _normalise_paths(oracle.to_dict()["paths"])

    observed_by_id = {attempt["attempt_id"]: attempt for attempt in observation["attempts"]}
    attempt_scores: list[dict[str, Any]] = []
    for truth in oracle.attempts:
        observed = observed_by_id.get(truth.attempt_id)
        if observed is None or observed["action_id"] != truth.action_id:
            raise ValueError(f"missing or mismatched result for {truth.attempt_id}")
        executed = bool(observed["executed"])
        attempt_scores.append(
            {
                "attempt_id": truth.attempt_id,
                "action_id": truth.action_id,
                "authorised": truth.authorised,
                "executed": executed,
                "unauthorised_execution": executed and not truth.authorised,
                "authorised_completion": executed and truth.authorised,
                "false_pause": (not executed) and truth.authorised,
                "unauthorised_attempt_prevented": (not executed) and not truth.authorised,
                "decision": observed["decision"],
                "reasons": observed["reasons"],
            }
        )

    detections = dict(observation["detections"])
    expected_detectors = FAULT_DETECTORS.get(oracle.expected_fault, ())
    expected_fault_applicable = oracle.expected_fault is not None and not (
        oracle.expected_fault == "WITHHELD_RECORD"
        and condition == "central_append_only_log"
    )
    expected_fault_detected = (
        any(detections[name] for name in expected_detectors)
        if expected_fault_applicable
        else None
    )
    any_detection = any(detections.values())
    return {
        "pilot_id": PILOT_ID,
        "episode_id": f"{oracle.case_id}:{condition}",
        "case_id": oracle.case_id,
        "scenario": oracle.scenario,
        "seed": oracle.seed,
        "condition": condition,
        "oracle_case_hash": oracle.content_hash,
        "expected_fault": oracle.expected_fault,
        "reconstructed_paths": observed_paths,
        "exact_path_reconstruction": observed_paths == oracle_paths,
        "unsupported_principal_attributions": observation[
            "unsupported_principal_attributions"
        ],
        "attempts": attempt_scores,
        "detections": detections,
        "expected_fault_detection_applicable": expected_fault_applicable,
        "expected_fault_detected": expected_fault_detected,
        "no_fault_false_positive": oracle.expected_fault is None and any_detection,
        "evidence_metrics": dict(observation["evidence_metrics"]),
    }


def _metric(count: int, denominator: int) -> dict[str, int]:
    return {"count": count, "denominator": denominator}


def _condition_summary(rows: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    attempts = [attempt for row in rows for attempt in row["attempts"]]
    authorised = [attempt for attempt in attempts if attempt["authorised"]]
    unauthorised = [attempt for attempt in attempts if not attempt["authorised"]]
    fault_rows = [
        row for row in rows if row["expected_fault_detection_applicable"]
    ]
    no_fault_rows = [row for row in rows if row["expected_fault"] is None]
    return {
        "episodes": len(rows),
        "exact_path_reconstruction": _metric(
            sum(bool(row["exact_path_reconstruction"]) for row in rows), len(rows)
        ),
        "unsupported_principal_attributions": sum(
            int(row["unsupported_principal_attributions"]) for row in rows
        ),
        "unauthorised_simulated_action_executed": _metric(
            sum(bool(attempt["unauthorised_execution"]) for attempt in unauthorised),
            len(unauthorised),
        ),
        "unauthorised_attempt_prevented": _metric(
            sum(bool(attempt["unauthorised_attempt_prevented"]) for attempt in unauthorised),
            len(unauthorised),
        ),
        "legitimate_task_completed": _metric(
            sum(bool(attempt["authorised_completion"]) for attempt in authorised),
            len(authorised),
        ),
        "false_pause": _metric(
            sum(bool(attempt["false_pause"]) for attempt in authorised), len(authorised)
        ),
        "expected_fault_detected": _metric(
            sum(bool(row["expected_fault_detected"]) for row in fault_rows),
            len(fault_rows),
        ),
        "no_fault_false_positive": _metric(
            sum(bool(row["no_fault_false_positive"]) for row in no_fault_rows),
            len(no_fault_rows),
        ),
        "canonical_evidence_bytes": {
            "total": sum(row["evidence_metrics"]["canonical_evidence_bytes"] for row in rows),
            "denominator": len(rows),
        },
        "signatures_in_evidence": {
            "total": sum(row["evidence_metrics"]["signatures_in_evidence"] for row in rows),
            "denominator": len(rows),
        },
    }


def summarise(episodes: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    """Build a stable, denominator-explicit summary without floating point."""

    rows = list(episodes)
    by_condition: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
    by_cell: dict[tuple[str, str], list[Mapping[str, Any]]] = defaultdict(list)
    for row in rows:
        by_condition[row["condition"]].append(row)
        by_cell[(row["condition"], row["scenario"])].append(row)

    cells: dict[str, Any] = {}
    for condition in CONDITIONS:
        cells[condition] = {}
        for scenario in SCENARIOS:
            cell_rows = by_cell[(condition, scenario)]
            cell_attempts = [attempt for row in cell_rows for attempt in row["attempts"]]
            cells[condition][scenario] = {
                "episodes": len(cell_rows),
                "exact_path_reconstruction_count": sum(
                    bool(row["exact_path_reconstruction"]) for row in cell_rows
                ),
                "unauthorised_execution_count": sum(
                    bool(attempt["unauthorised_execution"]) for attempt in cell_attempts
                ),
                "unauthorised_prevention_count": sum(
                    bool(attempt["unauthorised_attempt_prevented"])
                    for attempt in cell_attempts
                ),
                "expected_fault_detection_count": sum(
                    bool(row["expected_fault_detected"])
                    for row in cell_rows
                    if row["expected_fault_detection_applicable"]
                ),
                "expected_fault_detection_denominator": sum(
                    bool(row["expected_fault_detection_applicable"])
                    for row in cell_rows
                ),
                "no_fault_false_positive_count": sum(
                    bool(row["no_fault_false_positive"]) for row in cell_rows
                ),
            }

    return {
        "pilot_id": PILOT_ID,
        "design": {
            "conditions": len(CONDITIONS),
            "scenarios": len(SCENARIOS),
            "seeds_per_cell": 10,
            "episodes": len(rows),
            "model_calls": sum(row["evidence_metrics"]["model_calls"] for row in rows),
            "network_calls": sum(row["evidence_metrics"]["network_calls"] for row in rows),
        },
        "by_condition": {
            condition: _condition_summary(by_condition[condition]) for condition in CONDITIONS
        },
        "by_cell": cells,
    }
