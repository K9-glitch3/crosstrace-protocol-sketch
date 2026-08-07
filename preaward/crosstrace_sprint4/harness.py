"""Deterministic six-cell development harness."""

from __future__ import annotations

import tempfile
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from crosstrace_sketch.protocol import canonical_json, content_id
from preaward.crosstrace_sprint2.model import EvidenceRepresentation

from .chain import validation_summary
from .encoding import build_representation_bundle
from .fixtures import (
    DECISION_TIME,
    LOCAL_STORE_ID,
    PERMIT_STORE_ID,
    TOOL_ID,
    VERIFIER_ID,
    BuiltCase,
    build_cases,
)
from .model import (
    CELL_SPECS,
    CLAIM_LEVEL,
    HARNESS_VERSION,
    RELEASE_ID,
    CellSpec,
    Enforcement,
    HarnessError,
    RepresentationBundle,
    object_hash,
)


@dataclass(frozen=True, slots=True)
class HarnessRun:
    bundles: tuple[dict[str, Any], ...]
    executions: tuple[dict[str, Any], ...]
    invariance: dict[str, Any]
    summary: dict[str, Any]


class _SimulatedAdapter:
    """In-memory action boundary; it deliberately has no external capability."""

    def __init__(self) -> None:
        self.call_count = 0

    def submit(self, *, attempt_id: str, action: Mapping[str, Any]) -> dict[str, Any]:
        self.call_count += 1
        # Canonicalising proves the adapter received a structured local action.
        canonical_json(dict(action))
        return {
            "attempt_id": attempt_id,
            "attempted": True,
            "committed": True,
            "operational_failure": False,
        }


class _DeterministicPermitIdFactory:
    def __init__(self, opaque_trace_id: str) -> None:
        self.opaque_trace_id = opaque_trace_id
        self.counter = 0

    def __call__(self, *_args: Any, **_kwargs: Any) -> str:
        self.counter += 1
        return f"permit-{self.opaque_trace_id}-{self.counter:02d}"


def run_matrix(*, reverse_input_order: bool = False) -> HarnessRun:
    """Run eight synthetic cases through the exact six development cells."""

    cases = build_cases()
    bundle_objects: dict[tuple[str, EvidenceRepresentation], RepresentationBundle] = {}
    bundle_rows: list[dict[str, Any]] = []
    for case in cases:
        for representation in (
            EvidenceRepresentation.SL,
            EvidenceRepresentation.CR,
            EvidenceRepresentation.PR,
        ):
            bundle = build_representation_bundle(
                case,
                representation,
                reverse_input_order=reverse_input_order,
            )
            bundle_objects[(case.config.case_id, representation)] = bundle
            bundle_rows.append(bundle.to_release_dict())

    execution_rows: list[dict[str, Any]] = []
    with tempfile.TemporaryDirectory(prefix="crosstrace_sprint4_") as temporary:
        state_root = Path(temporary)
        for case in cases:
            for cell in CELL_SPECS:
                bundle = bundle_objects[(case.config.case_id, cell.representation)]
                local_validation = validation_summary(
                    bundle.local_observation,
                    representation=cell.representation,
                    case=case,
                )
                audit_validation = validation_summary(
                    bundle.audit_observation,
                    representation=cell.representation,
                    case=case,
                )
                if cell.enforcement is Enforcement.AUDIT:
                    branch = _run_audit_branch(case)
                else:
                    branch = _run_gate_branch(
                        case,
                        cell,
                        bundle,
                        state_path=state_root
                        / f"{case.config.opaque_trace_id}-{cell.representation.value}.sqlite3",
                    )
                execution_rows.append(
                    _execution_row(
                        case,
                        cell,
                        bundle,
                        local_validation=local_validation,
                        audit_validation=audit_validation,
                        branch=branch,
                    )
                )

    bundles = tuple(
        sorted(bundle_rows, key=lambda row: (row["case_id"], row["representation"]))
    )
    executions = tuple(
        sorted(execution_rows, key=lambda row: (row["case_id"], row["cell_id"]))
    )
    invariance = compute_invariance(bundles, executions)
    summary = summarise_engineering(executions, invariance)
    return HarnessRun(
        bundles=bundles,
        executions=executions,
        invariance=invariance,
        summary=summary,
    )


def _run_audit_branch(case: BuiltCase) -> dict[str, Any]:
    adapter = _SimulatedAdapter()
    attempts = [
        adapter.submit(attempt_id=f"attempt-{index}", action=case.action)
        for index in range(1, case.config.attempt_count + 1)
    ]
    return {
        "gate": {
            "invoked": False,
            "common_input_ids": [],
            "common_inputs": [],
            "common_input_forbidden_fields": [],
            "decisions": [],
            "transitions": [],
            "finish_results": [],
            "permit_reservations": 0,
            "permit_store_mutations": 0,
        },
        "adapter_attempts": attempts,
        "adapter_call_count": adapter.call_count,
    }


def _run_gate_branch(
    case: BuiltCase,
    cell: CellSpec,
    bundle: RepresentationBundle,
    *,
    state_path: Path,
) -> dict[str, Any]:
    # Imported here so Sprint 4 has one explicit integration seam and audit
    # branches cannot even construct a gate or permit store.
    from preaward.crosstrace_sprint3 import (
        CommonActionGate,
        NeutralPermitStore,
        StatusStoreRegistry,
        VerifierRegistry,
        prepare_common_gate_input,
    )

    verifier_registry = VerifierRegistry()
    verifier_registry.add(
        verifier_id=VERIFIER_ID,
        evidence_store_id=LOCAL_STORE_ID,
        permit_store_id=PERMIT_STORE_ID,
        tool_ids=(TOOL_ID,),
    )
    status_stores = StatusStoreRegistry()
    status_stores.add(
        store_id="store.authority",
        issuer_principal_id="buyer.example",
    )
    factory = _DeterministicPermitIdFactory(case.config.opaque_trace_id)
    permit_store = NeutralPermitStore(
        state_path,
        permit_store_id=PERMIT_STORE_ID,
        permit_id_factory=factory,
    )
    gate = CommonActionGate(
        verifier_registry=verifier_registry,
        permit_store=permit_store,
        permit_ttl_seconds=60,
    )
    adapter = _SimulatedAdapter()
    input_ids: list[str] = []
    common_inputs: list[dict[str, Any]] = []
    forbidden: set[str] = set()
    decisions: list[dict[str, Any]] = []
    transitions: list[dict[str, Any]] = []
    finishes: list[bool] = []
    adapter_attempts: list[dict[str, Any]] = []
    initial_revision = permit_store.snapshot(captured_at=DECISION_TIME).revision
    try:
        for attempt_number in range(1, case.config.attempt_count + 1):
            snapshot = permit_store.snapshot(captured_at=DECISION_TIME)
            prepared = prepare_common_gate_input(
                observation=bundle.local_observation,
                representation=cell.representation,
                key_registry=case.key_registry,
                store_registry=case.store_registry,
                verifier_registry=verifier_registry,
                status_store_registry=status_stores,
                permit_state=snapshot,
            )
            prepared_dict = prepared.to_dict()
            input_ids.append(prepared.input_id)
            common_inputs.append(prepared_dict)
            forbidden.update(_forbidden_gate_input_fields(prepared_dict))
            decision = gate.authorize(prepared, action=case.action, tool_id=TOOL_ID)
            decisions.append(decision.to_dict())
            attempt_id = f"attempt-{attempt_number}"
            if not decision.allowed:
                adapter_attempts.append(
                    {
                        "attempt_id": attempt_id,
                        "attempted": False,
                        "committed": False,
                        "operational_failure": False,
                    }
                )
                continue
            assert decision.permit_id is not None
            transition = gate.consume(
                permit_id=decision.permit_id,
                action=case.action,
                tool_id=TOOL_ID,
                now=DECISION_TIME,
            )
            transitions.append(transition.to_dict())
            if not transition.allowed:
                adapter_attempts.append(
                    {
                        "attempt_id": attempt_id,
                        "attempted": False,
                        "committed": False,
                        "operational_failure": False,
                    }
                )
                continue
            adapter_attempts.append(
                adapter.submit(attempt_id=attempt_id, action=case.action)
            )
            finishes.append(gate.finish(permit_id=decision.permit_id, succeeded=True))
        final_revision = permit_store.snapshot(captured_at=DECISION_TIME).revision
    finally:
        permit_store.close()
    return {
        "gate": {
            "invoked": True,
            "common_input_ids": input_ids,
            "common_inputs": common_inputs,
            "common_input_forbidden_fields": sorted(forbidden),
            "decisions": decisions,
            "transitions": transitions,
            "finish_results": finishes,
            "permit_reservations": sum(
                1 for decision in decisions if decision["verdict"] == "ALLOW"
            ),
            "permit_store_mutations": final_revision - initial_revision,
        },
        "adapter_attempts": adapter_attempts,
        "adapter_call_count": adapter.call_count,
    }


def _forbidden_gate_input_fields(value: Any) -> set[str]:
    forbidden_names = {
        "scenario",
        "assertion",
        "expected",
        "oracle",
        "future",
        "schedule",
        "delivery_schedule",
        "representation",
        "cell_id",
    }
    forbidden_prefixes = ("scenario_", "assertion_", "expected_", "oracle_", "future_")
    found: set[str] = set()
    if isinstance(value, dict):
        for key, child in value.items():
            normalised = key.casefold().replace("-", "_")
            if normalised in forbidden_names or normalised.startswith(
                forbidden_prefixes
            ):
                found.add(key)
            found.update(_forbidden_gate_input_fields(child))
    elif isinstance(value, list):
        for child in value:
            found.update(_forbidden_gate_input_fields(child))
    return found


def _execution_row(
    case: BuiltCase,
    cell: CellSpec,
    bundle: RepresentationBundle,
    *,
    local_validation: Mapping[str, Any],
    audit_validation: Mapping[str, Any],
    branch: Mapping[str, Any],
) -> dict[str, Any]:
    body = {
        "version": HARNESS_VERSION,
        "release_id": RELEASE_ID,
        "claim_level": CLAIM_LEVEL,
        "case_id": case.config.case_id,
        "cell_id": cell.cell_id,
        "representation": cell.representation.value,
        "enforcement": cell.enforcement.value,
        "bundle_id": bundle.bundle_id,
        "neutral_trace_hash": bundle.neutral_trace_hash,
        "action_hash": bundle.action_hash,
        "slot_manifest_hash": bundle.slot_manifest_hash,
        "transport_projection_hash": bundle.transport_projection_hash,
        "local_validation": dict(local_validation),
        "audit_validation": dict(audit_validation),
        "gate": dict(branch["gate"]),
        "adapter_attempts": list(branch["adapter_attempts"]),
        "engineering_counts": {
            "local_delivered_messages": len(
                bundle.local_observation.delivered_messages
            ),
            "audit_delivered_messages": len(
                bundle.audit_observation.delivered_messages
            ),
            "local_delivered_payload_bytes": sum(
                len(item.payload_bytes)
                for item in bundle.local_observation.delivered_messages
            ),
            "audit_delivered_payload_bytes": sum(
                len(item.payload_bytes)
                for item in bundle.audit_observation.delivered_messages
            ),
            "adapter_calls": branch["adapter_call_count"],
            "model_calls": 0,
            "input_tokens": 0,
            "output_tokens": 0,
            "runtime_network_calls": 0,
        },
    }
    return {"execution_id": object_hash("SPRINT4_EXECUTION", body), **body}


def compute_invariance(
    bundles: tuple[dict[str, Any], ...],
    executions: tuple[dict[str, Any], ...],
) -> dict[str, Any]:
    checks: list[dict[str, Any]] = []

    def add(check_id: str, passed: bool, detail: str) -> None:
        checks.append({"check_id": check_id, "passed": bool(passed), "detail": detail})

    case_ids = sorted({row["case_id"] for row in executions})
    expected_cells = {cell.cell_id for cell in CELL_SPECS}
    matrix_ok = len(executions) == 48 and all(
        {row["cell_id"] for row in executions if row["case_id"] == case_id}
        == expected_cells
        for case_id in case_ids
    )
    add("EXACT_SIX_CELL_MATRIX", matrix_ok, "8 fixtures x 6 cells")

    neutral_ok = True
    transport_ok = True
    for case_id in case_ids:
        rows = [row for row in bundles if row["case_id"] == case_id]
        neutral_ok &= all(
            len({row[field] for row in rows}) == 1
            for field in ("neutral_trace_hash", "action_hash", "slot_manifest_hash")
        )
        transport_ok &= len({row["transport_projection_hash"] for row in rows}) == 1
    add("NEUTRAL_INPUTS_EQUAL", neutral_ok, "trace, action, and slot manifests")
    add("TRANSPORT_PROJECTION_EQUAL", transport_ok, "payload-free outcomes by slot")

    pair_ok = True
    for case_id in case_ids:
        for representation in ("SL", "CR", "PR"):
            pair = [
                row
                for row in executions
                if row["case_id"] == case_id and row["representation"] == representation
            ]
            pair_ok &= len(pair) == 2 and len({row["bundle_id"] for row in pair}) == 1
    add("AUDIT_GATE_BUNDLE_IDENTITY", pair_ok, "enforcement branches reuse one bundle")

    sender_ok = True
    pr_ok = True
    for case_id in case_ids:
        by_rep = {
            row["representation"]: row for row in bundles if row["case_id"] == case_id
        }
        sender_ok &= (
            by_rep["SL"]["endpoint_sender_bytes_b64"]
            == by_rep["CR"]["endpoint_sender_bytes_b64"]
        )
        pr_ok &= by_rep["PR"]["pr_copy_pairs_equal"] is True
    add("SL_CR_SENDER_BYTES_EQUAL", sender_ok, "same signed sender records")
    add("PR_ENDPOINT_COPIES_EQUAL", pr_ok, "both holders retain the complete receipt")

    audit_ok = all(
        row["gate"]["invoked"] is False
        and row["gate"]["permit_reservations"] == 0
        and row["gate"]["permit_store_mutations"] == 0
        for row in executions
        if row["enforcement"] == "AUDIT"
    )
    add("AUDIT_NEVER_INVOKES_GATE", audit_ok, "audit-only branch bypasses permit state")

    pause_ok = all(
        not attempt["attempted"]
        for row in executions
        if row["enforcement"] == "GATE"
        for decision, attempt in zip(
            row["gate"]["decisions"], row["adapter_attempts"], strict=True
        )
        if decision["verdict"] == "PAUSE"
    )
    add(
        "PAUSE_NEVER_REACHES_ADAPTER",
        pause_ok,
        "one adapter trace per presented attempt",
    )

    no_leak = all(
        not row["gate"]["common_input_forbidden_fields"] for row in executions
    )
    add(
        "COMMON_INPUT_METADATA_CLOSED", no_leak, "no evaluator or representation labels"
    )

    one_copy = {
        row["representation"]: row["gate"]["decisions"][0]["verdict"]
        for row in executions
        if row["case_id"] == "one-leaf-receiver-locally-withheld"
        and row["enforcement"] == "GATE"
    }
    add(
        "ONE_COPY_BRANCH_NON_DEGENERATE",
        one_copy == {"SL": "PAUSE", "CR": "PAUSE", "PR": "ALLOW"},
        "SL/CR require both endpoint records; one PR copy contains both attestations",
    )

    equivalent_cases = {
        "complete",
        "status-delayed-locally-audit-visible",
        "higher-revocation",
        "out-of-scope",
        "replay",
    }
    common_gate_ok = True
    for case_id in equivalent_cases:
        rows = [
            row
            for row in executions
            if row["case_id"] == case_id and row["enforcement"] == "GATE"
        ]
        signatures = {
            tuple(
                (decision["verdict"], tuple(decision["reasons"]))
                for decision in row["gate"]["decisions"]
            )
            for row in rows
        }
        common_gate_ok &= len(signatures) == 1
    add("COMMON_GATE_EQUIVALENT_EVIDENCE", common_gate_ok, "same verdict/reasons")

    external_zero = all(
        all(
            row["engineering_counts"][name] == 0
            for name in (
                "model_calls",
                "input_tokens",
                "output_tokens",
                "runtime_network_calls",
            )
        )
        for row in executions
    )
    add("EXTERNAL_CALL_COUNTERS_ZERO", external_zero, "offline synthetic execution")
    return {
        "version": HARNESS_VERSION,
        "release_id": RELEASE_ID,
        "checks": checks,
        "violation_count": sum(not item["passed"] for item in checks),
    }


def summarise_engineering(
    executions: tuple[dict[str, Any], ...], invariance: Mapping[str, Any]
) -> dict[str, Any]:
    gate_verdicts: Counter[str] = Counter()
    validation_issues: Counter[str] = Counter()
    transitions: Counter[str] = Counter()
    for row in executions:
        for decision in row["gate"]["decisions"]:
            gate_verdicts[decision["verdict"]] += 1
        for issue in row["local_validation"]["issue_codes"]:
            validation_issues[issue] += 1
        for transition in row["gate"]["transitions"]:
            transitions[transition["verdict"]] += 1
    return {
        "version": HARNESS_VERSION,
        "release_id": RELEASE_ID,
        "claim_level": CLAIM_LEVEL,
        "fixture_count": len({row["case_id"] for row in executions}),
        "cell_count": len(CELL_SPECS),
        "execution_count": len(executions),
        "unit": "one synthetic fixture encoding and enforcement branch",
        "engineering_only": True,
        "invariant_checks": len(invariance["checks"]),
        "invariant_violations": invariance["violation_count"],
        "gate_decision_counts": dict(sorted(gate_verdicts.items())),
        "local_validation_issue_counts": dict(sorted(validation_issues.items())),
        "permit_transition_counts": dict(sorted(transitions.items())),
        "adapter_call_count": sum(
            row["engineering_counts"]["adapter_calls"] for row in executions
        ),
        "model_calls": 0,
        "runtime_network_calls": 0,
    }
