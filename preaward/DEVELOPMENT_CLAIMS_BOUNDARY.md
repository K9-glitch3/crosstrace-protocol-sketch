# Development claims boundary

## Status

The six-cell release is a deterministic engineering conformance artifact built
from eight hand-written synthetic fixtures. It is not a pilot study,
preregistration, calibration set, held-out evaluation, or deployment trial.

## Statements this release can support

If the published verifier succeeds, it supports the following narrow statements:

- the declared six cells were generated from the released development fixtures;
- each audit/gate pair reused one representation bundle rather than rebuilding
  evidence after the enforcement condition was chosen;
- the `SL`, `CR`, and `PR` encoders used the same neutral handoff semantics and
  payload-free holder/slot delivery projection;
- the current validators and common gate produced the declared local decisions
  for the fixed complete, missing, delayed, revoked, out-of-scope, replay, and
  conflict branches;
- audit cells bypassed the CrossTrace gate, while gate cells used a
  representation-blind policy input and neutral local permit state;
- one intact paired-receipt copy could carry both attestations, whereas separate
  and cross-referenced logs required their distinct endpoint records;
- the released core files can be checksum-checked, recomputed, and regenerated
  deterministically under the recorded software profile; and
- the harness recorded no model, runtime network, wallet, or payment-service
  calls.

These are statements about the released code and fixtures. Counts in the report
describe exercised branches only.

## Statements this release cannot support

The release provides no basis for claiming that:

- CrossTrace improves AI safety, containment, attribution, reliability, or
  availability;
- one evidence representation is superior, inferior, equivalent, or
  non-inferior to another;
- a gate causes fewer unsafe actions or an acceptable rate of false pauses;
- the fixtures are trials, independent observations, a representative sample,
  or evidence of an effect size;
- the results generalise to frontier models, real organisations, adversarial
  populations, live networks, or production workloads;
- the mechanism is production-secure or suitable for real authorisation,
  payments, custody, access control, or legal reliance;
- signatures establish truth, intent, identity of a clone, or honesty; or
- the local mechanism solves collusion, stolen or shared keys, global forks,
  global replay, cumulative budgets, availability under partition, or bypass
  through uninstrumented tools.

No rate, percentage, confidence interval, statistical comparison, or safety
outcome should be calculated from these fixtures.

## Interpretation rules

`AUDIT` means the CrossTrace gate was not consulted. It is an enforcement
control, not a finding that an action was safe or unsafe. `GATE` means the local
common gate evaluated only evidence delivered by its decision cutoff. `ALLOW`
and `PAUSE` are local protocol verdicts, not real-world permissions or safety
labels.

`COMPLETE` or `UNRESOLVED` chain assembly describes what the bounded observation
supports. It is not an exact-path reconstruction outcome. Evidence arriving in
the later audit view cannot be credited with preventing an earlier action.

The one-copy branch demonstrates the retention semantics encoded by the three
formats. It does not estimate how often copies will be lost or whether paired
receipts have a practical availability advantage. Cross-representation
invariance applies to neutral content and holder/slot delivery assignments, not
to byte-identical evidence messages.

## Safe citation

> CrossTrace publishes a deterministic, credential-free six-cell development
> harness showing that three evidence encodings can be passed through the same
> local gate and reproduced from released synthetic fixtures. It contains no
> model-level outcome evidence.

## Next-stage boundary

Do not create or run frontier-model calibration or held-out episodes from this
package. The next funded stage starts only after the scientific protocol,
estimands, delivery distribution, exclusions, stopping rules, and analysis code
have been reviewed and preregistered. New outcome material must receive a new
versioned manifest and must remain separate from these development fixtures.
