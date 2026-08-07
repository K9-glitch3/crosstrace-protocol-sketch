# Pre-award development packages

Code under this directory is engineering work built after the frozen P0 artifact. It is intentionally excluded from P0's source-tree hash and is not installed as part of the `crosstrace-sketch` package.

It is covered by the repository's Apache License 2.0.

Each package must use development-only fixtures and preserve the boundaries in `research/ANALYSIS_PLAN_DRAFT.md`. Promotion into `src/`, calibration, frontier-model execution, or held-out use requires a new versioned baseline and the applicable protocol approval.

- [`crosstrace_sprint1`](crosstrace_sprint1/README.md): deterministic evidence delivery and bounded local observations.
- [`crosstrace_sprint2`](crosstrace_sprint2/README.md): strict SL, CR, and PR evidence validation and representation-neutral handoff normalisation.
- [`crosstrace_sprint3`](crosstrace_sprint3/): a representation-blind common gate, delivered-authority selection, and revision-checked one-attempt permit state.
- [`crosstrace_sprint4`](crosstrace_sprint4/README.md): a deterministic six-cell harness over eight hand-written development cases.

Sprint 3 and Sprint 4 remain development packages outside the frozen P0 source tree. The published [six-cell result](results/six-cell-v0.1/REPORT.md) passed its deterministic verifier, the full test suite, and the frozen P0 verifier. Its 48 branch executions are not trials, calibration data, held-out material, or evidence of a comparative or safety effect. Reviewers should start with the [five-minute reproduction guide](REVIEWER_REPRODUCTION.md) and [claims boundary](DEVELOPMENT_CLAIMS_BOUNDARY.md).

The next step after engineering verification is external methods review, followed by a frozen protocol and preregistration if funding and approvals are obtained. No pre-award frontier-model or held-out run is authorised.
