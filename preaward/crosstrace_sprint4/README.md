# Sprint 4 six-cell development harness

This package replays eight hand-written synthetic cases through the exact six
development cells `SL-AUDIT`, `SL-GATE`, `CR-AUDIT`, `CR-GATE`, `PR-AUDIT`,
and `PR-GATE`. It makes no model, network, wallet, or payment-service calls.

For each case, its neutral trace and holder-to-store slot manifest are fixed
before the `SL`, `CR`, and `PR` encoders run. A representation bundle is
constructed once and reused by its audit-only and gate branches. Audit-only
branches submit the synthetic action directly and never call the gate or
reserve a permit. Gate branches use the Sprint 3 common gate and an isolated
neutral permit store.

The fixtures exercise parsing, delivery, validation, strict chain assembly,
authority selection, scope/action checks, permit transitions, and the local
adapter boundary. They are deliberately non-degenerate engineering branches,
not independent trials, calibration data, held-out material, or research
outcomes. Counts in a generated release describe code paths only. They do not
estimate safety, availability, superiority, equivalence, or an effect size.

Generate and verify a temporary or reviewer release from the repository root:

```shell
python -m preaward.crosstrace_sprint4.runner --output-dir <directory>
python -m preaward.crosstrace_sprint4.verify <directory>
```

The published reviewer artifact is under
`preaward/results/six-cell-v0.1`. It passed Sprint 3 integration, the full test
suite, the frozen P0 verifier, schema checks, and deterministic regeneration.
That is an engineering release boundary only; it does not change the research
claim boundary above.
