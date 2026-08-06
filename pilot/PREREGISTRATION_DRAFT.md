# CrossTrace scripted systems pilot v0.1: analysis plan

Status: analysis plan reconstructed and reviewed alongside the local P0 release.
It has no independent pre-run timestamp and must not be described as a
preregistration. It defines a conformance exercise, not a powered safety
experiment.

## Question

Can the present implementation reproducibly encode, reconstruct, and gate a
small set of synthetic delegation faults without credentials or network access,
while preserving its stated failure boundary under isolated equivocation?

## Unit and matrix

The unit is one deterministic condition-scenario-fixture execution. The fixed
matrix contains five conditions, six scenarios, and ten variants per cell: 300
executions. Variants alter identifiers, timestamps, resources, and amounts but
not topology. They are not independent trials.

## Oracle separation

The generator creates a ground-truth delegation path and per-attempt
authorisation labels. It then emits a serialized evidence artifact for one
condition. The evaluator receives only that artifact. It does not receive the
scenario label, expected fault, ground-truth path, or authorisation labels. The
scorer joins the evaluator output to the oracle after execution. A content hash
proves that all five conditions for one case were scored against the same oracle.

## Outcomes

Primary conformance outcomes:

1. Exact recovery of the simulator's ground-truth delegation path.
2. Unauthorised simulated attempts executed or prevented.
3. Authorised simulated attempts completed or falsely paused.
4. Detection of the declared fault, only where the detector is applicable.

Secondary accounting outcomes:

- principal attributions lacking a valid sender attestation;
- canonical retained-evidence bytes;
- signatures present in retained evidence; and
- model, token, and network call counts, which must all be zero.

Withholding detection is applicable to endpoint-local and paired conditions that
expose retained-copy inventory. The central condition is scored on reconstruction
resilience, not on detecting an endpoint copy that its artifact does not model.

## Expected counterfactuals

- Conditions without an online gate execute every presented attempt. Offline
  detection does not count as prevention.
- The gate should complete valid and withheld-copy actions.
- The gate should pause the newer revocation update and the over-limit action.
- The first local attempt should execute and the repeat should pause.
- Two isolated gate stores may both permit conflicting leaves. A later joined
  view should detect the conflict. This is a recorded limitation, not success.

Every gate counterfactual supplies the complete declared receipt chain and the
declared current signed status directly. The P0 run therefore tests the local
checker, not evidence delivery, status propagation, or decision-time partial
observability.

## Analysis

All reported rates are integer counts with explicit denominators. There are no
p-values, confidence intervals, effect estimates, or power claims. A verifier
recomputes the summary from episode rows, checks the full matrix and oracle-hash
invariant, tests the declared gate counterfactuals, and validates release hashes.

## Exclusions and stopping

There are no data-dependent exclusions. Any execution error fails the release.
The matrix is fixed; it is not extended in response to observed outcomes.

## Interpretation

Passing this design shows only that the scripted mechanism and its known local
boundary were reproduced. It does not show that CrossTrace improves real-agent
safety, outperforms a baseline, prevents global forks, or works under collusion,
key compromise, or uninstrumented action paths.
