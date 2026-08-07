# CrossTrace P0 evidence boundary

**Status:** Reproducible feasibility artifact; not a comparative safety result
**Recorded:** 6 August 2026

## Bound public artifact

| Field | Value |
|---|---|
| Repository | `K9-glitch3/crosstrace-protocol-sketch` |
| P0 commit | `824078b876f23d4d138a9dd2fff3a6c1ff6d5c80` |
| P0 identifier | `crosstrace-scripted-systems-pilot-v0.1` |
| P0 source-tree hash | `sha256:998e1b33ee47a019b3e95bca6b23cf382572720b7b4cbc78fcc175d912ac6850` |

The existing `v0.1.0` tag points to an earlier application-sketch commit and is not the identity of the complete P0 package. It must not be moved.

## Reproduction

From the repository root:

```text
python -m pytest -q
python -m crosstrace_sketch.pilot.verify pilot/results/pilot-v0.1
```

On 6 August 2026, these checks produced:

- 37 passing tests; and
- successful verification of 300 deterministic executions across 60 oracle cases.

The verifier checks the existing release manifest, schemas, hashes, raw fixture rows, summary, report, environment record, and claim boundary. Re-running it is a reproducibility check, not a new experiment.

## What P0 establishes

P0 shows that the repository's scripted, credential-free fixture can reproduce local receipt validation, one-attempt permit handling, and the documented isolated-view failure. It is implementation-feasibility evidence only.

## What P0 does not establish

P0 does not show that:

- dual-attested receipts outperform separate or cross-referenced signed logs;
- CrossTrace improves AI safety;
- the mechanism works with frontier-model agents or independent organisations;
- evidence arrives completely or on time;
- a gate prevents a conflict it has not observed; or
- the 300 executions are independent statistical trials.

No P0 count is used as an effect estimate, power input, or confirmatory observation in the prospective study.
