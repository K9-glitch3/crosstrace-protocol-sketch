# CrossTrace methods brief for external review

**Status:** Pre-award design for criticism; not a preregistration or result

**Applicant:** Michael Owusu, independent technical researcher
**Recorded:** 6 August 2026

## The question

CrossTrace asks whether a small, explicit handoff record helps when AI agents operated by different organisations delegate work to one another.

The proposed mechanism has two parts:

1. the sender and receiver acknowledge the same structured handoff; and
2. a local gate checks the resulting authority chain before a hard-to-reverse simulated action.

The study asks separately whether the receipt improves reconstruction and whether the gate changes what executes. It does not assume either effect is positive.

## The mechanism

A sender creates a proposal stating who is handing work to whom, the permitted action and resource, an amount and expiry where relevant, the current authority version, and the semantic identifier of the preceding handoff. The sender signs the proposal hash. The receiver signs its decision over that same proposal and the sender's complete attestation. Both retain the completed receipt. A receipt-form child records the content identifier of the completed parent receipt; the signed-log baseline records the preceding semantic handoff identifier instead.

A later handoff names the completed earlier receipt. At an action boundary, a local verifier sees only records and authority statuses delivered to it by the decision time. It checks signatures, acceptance, parent links, party continuity, scope narrowing, authority status, timestamps, the exact action, and local replay state. Every required check must pass before it issues a short-lived one-attempt permit.

This is not a blockchain or global consensus protocol. A valid signature shows that a key signed particular bytes; it does not show that the statement is true or that the signer is honest. CrossTrace is not presented as a new signature primitive: the proposed contribution is an empirical systems comparison of binding, retention, partial delivery, linked authority, and local gating.

## Why the current P0 is not the experiment

The repository's P0 artifact is useful feasibility evidence: it deterministically exercises receipt validation, local permit handling, and a known isolated-fork failure without model or network calls.

It cannot support a comparative safety claim. Its current gated condition is handed a complete chain and status directly, while the other conditions have no equivalent gate. It does not model evidence delivery or decision-time partial views. The new study therefore does not treat P0's 300 fixture executions as trials or use them for power calculations.

## The corrected comparison

The main design varies evidence and enforcement independently:

| | Audit only | Local gate |
|---|---|---|
| Separate signed endpoint logs | `SL-AUDIT` | `SL-GATE` |
| Dual-attested receipts | `PR-AUDIT` | `PR-GATE` |

`SL` means separate signed logs; `PR` means the dual-attested receipt representation.

The signed-log condition is concrete. The sender and receiver each sign their own complete local record. The receiver record does not contain or sign the sender's record or signature. A verifier needs both matching records to establish bilateral agreement.

In the receipt condition, the receiver signature binds the sender's exact attestation, and a child links to the completed parent receipt. Either intact endpoint copy contains both attestations.

Both representations begin with the same semantic handoff fields. Both gates use the same action policy, permit rules, and simulated adapter. Representation-specific validators produce a common handoff object while preserving how each fact was authenticated.

A required, stronger control will cross-reference the endpoint logs: the receiver's signed record includes the content identifier of the sender's signed record. If the study finds no clear receipt advantage over that control, it will report only that absence of evidence; without a powered equivalence or non-inferiority test, it will not claim that the two designs are equivalent or that cross-reference is sufficient.

For the primary audit-only representation comparison, agents see the same neutral handoff API and acknowledgements. The assigned encoder and retention layout sit below that interface and are hidden from the agents, so the comparison is not intended to change their behaviour.

## Evidence delivery

The development-only Sprint 1 package implements a deterministic delivery layer. Before representation encoding, the manifest assigns each holder-to-store transmission a neutral delivery slot. Transport draws are derived from that slot, copy index, draw purpose, and seed, so changing payload bytes or representation does not change the assigned loss, duplication, or delay. Each retained copy or status is a separate message that may be delayed, lost, duplicated, reordered, or partitioned. At time `t`, a verifier sees only messages delivered by `t`; it never sees missing-message identifiers, future deliveries, another principal's private view, or the evaluator's schedule. For reconstruction, the evaluator uses a separate condition-neutral inbox containing only holder messages delivered through the same frozen delivery model by the preregistered audit cutoff. Exact representation validators, not the generic transport envelope, are responsible for excluding semantic oracle data from payloads.

The study will report two reconstruction effects:

- a complete-evidence comparison, which isolates signature and parent-binding structure; and
- a holder-level delivery comparison, which also measures the consequence of keeping both attestations in either complete receipt copy.

The proposed Schmidt H1 threshold applies to the second, system-level comparison. This interpretation must be reviewed before formal registration.

## Two studies, not one ambiguous denominator

### Fixed action-boundary replay

The semantic handoff package, authorisation rule, action, evidence-holder reachability, delivery schedule, and cutoffs are frozen before treatment assignment. The package is then encoded into the assigned representation. The oracle scorer is deterministic or blinded to condition and labels the action before gate and adapter outcomes are revealed. This permits a clean attempt-level comparison because the set of proposed actions cannot change when a gate pauses one.

This is the appropriate design for LTFF's submitted attempt-level endpoint.

### End-to-end agent episodes

An independently reset agent episode is assigned to one condition. A gate may change retries, later actions, and task completion. The primary safety outcome is therefore whether an episode contains any unauthorised committed side effect, alongside legitimate task completion.

This is the appropriate design for Schmidt H2 and for deployment-policy conclusions. Attempt counts from these episodes are descriptive because the treatment may change the denominator.

## What is measured

The system records four action states separately:

- gate verdict;
- whether the adapter attempt began;
- whether the simulated side effect committed; and
- whether an operational failure occurred.

This avoids calling a gate allowance an executed action when the adapter later fails. A false pause occurs only when an oracle-authorised attempt receives `PAUSE`. A protocol false alarm is different: it is a fault or conflict signal in a clean control episode where the oracle says no authority fault occurred.

Other outcomes are exact reconstruction of all recorded action paths at a fixed audit cutoff, false attribution of an honest outsider, unsupported attribution, task completion, detection before versus after action, latency, delivered and retained bytes, verifier cost, model use, and compute cost.

The primary reconstructor will be deterministic and frozen before calibration. Representation-specific validators feed one common path builder. Missing, ambiguous, and extra paths fail exact reconstruction.

## Submitted decision rules remain separate

The Schmidt application has two primary tests. Its submitted requirements are:

- at least a 15-point improvement in exact-path reconstruction, with false attribution no more than 5%; and
- at least a 10-point reduction in episode-level unauthorised action from adding the gate to dual-attested receipts (called "paired receipts" in the submitted wording), with legitimate completion falling by no more than five points.

It controls the two tests at alpha 0.025 each.

The LTFF application instead uses one submitted whole-package attempt-level contrast, requiring at least a 15-point reduction, a 95% confidence interval excluding zero, false pauses increasing by no more than five points, and task completion falling by no more than five points at alpha 0.05.

Those thresholds are not averaged. The four-cell design decomposes LTFF's whole-package contrast, but changing that submitted primary contrast requires LTFF approval.

If both awards are offered, the proposed USD 625,000 programme also requires written approval from both funders: Schmidt would fund the primary procurement study, while LTFF would fund a later independent reimplementation and new incident-response domain. No episode, paid hour, invoice, dataset, or milestone would be charged twice.

## Primary scope and limits

The primary benchmark assumes uncompromised keys for honest parties, at least one honest evidence holder, and all target actions routed through the instrumented adapter. Total collusion, shared keys, clones, out-of-band actions, and global fork prevention are separate boundary results, not hidden inside the primary average.

Two isolated verifiers may each receive a locally valid-looking branch and both permit action. Later evidence can reveal that conflict, but later detection is not prevention.

## Immediate engineering work

Before any frontier-model run, the project will implement and test with development-only fixtures:

1. the exact separate-log and cross-referenced-log schemas;
2. the decision-time observation and delivery layer;
3. representation-specific validators and the common handoff interface;
4. the same-policy signed-log gate;
5. separate action-state and cost instrumentation; and
6. a frozen reconstruction procedure and held-out policy.

As of 7 August 2026, item 2 has a development-only implementation and invariant test suite outside the frozen P0 source tree. It has generated no model-study observations and is not evidence of a safety effect.

Frontier-model experiments, confirmatory episodes, held-out cases, paid replication, and Phase II work remain frozen until the relevant funding and protocol approvals exist.
