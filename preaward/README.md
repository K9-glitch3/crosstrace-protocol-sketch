# Pre-award development packages

Code under this directory is engineering work built after the frozen P0 artifact. It is intentionally excluded from P0's source-tree hash and is not installed as part of the `crosstrace-sketch` package.

It is covered by the repository's Apache License 2.0.

Each package must use development-only fixtures and preserve the boundaries in `research/ANALYSIS_PLAN_DRAFT.md`. Promotion into `src/`, calibration, frontier-model execution, or held-out use requires a new versioned baseline and the applicable protocol approval.

- [`crosstrace_sprint1`](crosstrace_sprint1/README.md): deterministic evidence delivery and bounded local observations.
- [`crosstrace_sprint2`](crosstrace_sprint2/README.md): strict SL, CR, and PR evidence validation and representation-neutral handoff normalisation.
