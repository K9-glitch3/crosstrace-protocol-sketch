# Prospective CrossTrace research design

These files are pre-award design records. They do not change the submitted applications and are not evidence that CrossTrace improves safety.

Read them in this order:

1. [`P0_EVIDENCE_BOUNDARY.md`](P0_EVIDENCE_BOUNDARY.md) — frozen P0 identity, reproduction commands, and claim boundary.
2. [`METHODS_BRIEF.md`](METHODS_BRIEF.md) — concise external-review version of the proposed experiment.
3. [`MESSAGE_SEQUENCE.md`](MESSAGE_SEQUENCE.md) — plain-English mechanism and worked local-view failures.
4. [`CANONICAL_PROTOCOL_DRAFT.md`](CANONICAL_PROTOCOL_DRAFT.md) — roles, objects, decision rule, fair factorial, delivery model, and limitations.
5. [`ANALYSIS_PLAN_DRAFT.md`](ANALYSIS_PLAN_DRAFT.md) — outcomes, estimands, inference, held-out policy, and separate funder addenda.
6. [`RELATED_WORK_BOUNDARY.md`](RELATED_WORK_BOUNDARY.md) — primary-source comparison and exact non-novelty boundary.

The detailed local-worktree baseline, submission reconciliation, and pre-award accounting ledger are internal compliance records. They are maintained outside this public research directory and must not be published with the methods pack.

The development-only [Sprint 1 delivery package](../preaward/crosstrace_sprint1/README.md) now implements the deterministic decision-time observation and evidence-delivery interface without changing the frozen P0 source tree. Its fixtures are engineering tests, not research observations.

The development-only [Sprint 2 evidence package](../preaward/crosstrace_sprint2/README.md) now fixes the exact separate-log, cross-referenced-log, and receipt mappings, their representation-specific validators, and the common `ValidatedHandoff` interface. It also supplies adversarial conformance fixtures; it does not contain research outcomes.

The development-only Sprint 3 package adds a versioned, representation-blind common gate boundary. It selects from authority-status evidence delivered by the decision time, checks chain, scope, and action predicates, and uses neutral handoff identity for revision-checked local replay and permit state. It is not promoted into the frozen P0 package.

The [Sprint 4 six-cell harness](../preaward/crosstrace_sprint4/README.md) replays eight hand-written cases through `SL`, `CR`, and `PR`, each in audit-only and gate modes. Its [published result](../preaward/results/six-cell-v0.1/REPORT.md) contains 48 deterministic branch executions and passed deterministic regeneration, the integrated tests, and the frozen P0 verifier. These are engineering conformance fixtures, not independent trials or research outcomes.

The next step is external methods review, then a frozen protocol and preregistration under the applicable funding and approvals. Frontier-model runs, calibration, outcome-generating experiments, and held-out material remain out of scope before that boundary.
