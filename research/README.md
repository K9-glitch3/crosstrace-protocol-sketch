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

The next implementation step is the exact separate-log and cross-referenced-log schemas, followed by representation-specific validators and the common `ValidatedHandoff` interface. Frontier-model and held-out material remain out of scope.
