# CrossTrace six-cell development harness v0.1

> **Claim boundary:** deterministic pre-award engineering conformance only.
> These hand-written encodings are not trials, calibration data, held-out
> material, or evidence that any representation improves AI safety.

The runner made no model, network, wallet, or payment-service calls. Actions
below are in-memory adapter branches. Counts describe exercised code paths,
not rates or treatment effects.

## Case matrix

| Case | SL-GATE | CR-GATE | PR-GATE | Audit chain (SL/CR/PR) |
|---|---|---|---|---|
| complete | ALLOW | ALLOW | ALLOW | COMPLETE/COMPLETE/COMPLETE |
| one-leaf-receiver-locally-withheld | PAUSE | PAUSE | ALLOW | COMPLETE/COMPLETE/COMPLETE |
| both-leaf-copies-locally-withheld | PAUSE | PAUSE | PAUSE | COMPLETE/COMPLETE/COMPLETE |
| status-delayed-locally-audit-visible | PAUSE | PAUSE | PAUSE | COMPLETE/COMPLETE/COMPLETE |
| higher-revocation | PAUSE | PAUSE | PAUSE | COMPLETE/COMPLETE/COMPLETE |
| out-of-scope | PAUSE | PAUSE | PAUSE | COMPLETE/COMPLETE/COMPLETE |
| replay | ALLOW -> PAUSE | ALLOW -> PAUSE | ALLOW -> PAUSE | COMPLETE/COMPLETE/COMPLETE |
| authenticated-conflicting-leaf | PAUSE | PAUSE | PAUSE | UNRESOLVED/UNRESOLVED/UNRESOLVED |

## Verification

- Cells: 6
- Fixtures: 8
- Deterministic branch executions: 48
- Invariant violations: 0
- Model calls: 0
- Runtime network calls: 0

Run `python -m preaward.crosstrace_sprint4.verify <directory>` to
check integrity, recompute all rows, and compare deterministic artifacts.
