# Scripted systems pilot

This directory contains a credential-free conformance harness for the current
CrossTrace sketch. It is a bridge between protocol unit tests and a future
multi-model study. It is not that study.

## Run and verify

```shell
python -m crosstrace_sketch.pilot.runner
python -m crosstrace_sketch.pilot.verify pilot/results/pilot-v0.1
```

The runner writes 300 deterministic executions: five evidence conditions,
six fault or control scenarios, and ten fixture variants per cell. The variants
change identifiers, timestamps, resources, and amounts. They are robustness
fixtures, not independent observations, and no statistical inference is made.

No model, wallet, payment service, or network credential is used. “Execution”
means a call to an in-process simulated payment adapter.

## Conditions

| ID | Evidence available to the evaluator | Online action policy |
|---|---|---|
| `ordinary_local_logs` | Unsigned endpoint-local encodings of neutral events | Execute every presented attempt |
| `central_append_only_log` | One hash-linked central encoding of each neutral event | Execute every presented attempt |
| `isolated_signed_logs` | Independently serialized and signed endpoint-local records | Execute every presented attempt |
| `paired_receipts` | Jointly attested CrossTrace receipts retained at the visible endpoints | Execute every presented attempt |
| `paired_receipts_with_gate` | The same paired receipts plus the current local `ActionGate` | Execute only after a one-attempt permit |

Controls are encoded independently from neutral events. They do not inherit
CrossTrace receipt IDs or parent-receipt hashes. The retained-byte measure is
the canonical size of the joined evidence artifact, including each visible
endpoint copy; it is neither network transfer nor runtime cost.

## Scenarios

- a valid, current, in-scope action;
- a broker withholding its endpoint-local copies;
- two conflicting leaves observed first in isolated views and then together;
- a newer signed revocation update;
- an amount above the delegated limit; and
- a repeated local action attempt.

The revocation fixture changes signed state, version, and status reference. It
tests fail-closed handling of a newer contradictory authority update; it is not
a single-variable revocation ablation.

## Result files

- `manifest.resolved.json` binds the declared design to a source-tree hash.
- `episodes.jsonl` contains scorer output for every execution.
- `summary.json` contains integer counts and explicit denominators.
- `REPORT.md` is a human-readable rendering of the summary.
- `environment.json` records runtime and cryptographic library versions.
- `checksums.sha256` covers the five deterministic core files, including the
  resolved-manifest schema.

See the [P0 analysis plan](PREREGISTRATION_DRAFT.md) for the declared questions and
[claims boundary](CLAIMS_BOUNDARY.md) before citing any result.
