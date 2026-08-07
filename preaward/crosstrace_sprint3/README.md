# Sprint 3 common action gate

This development-only package applies one representation-blind action policy to the validator-issued Sprint 2 projections for separate logs (`SL`), cross-referenced logs (`CR`), and paired receipts (`PR`). It remains outside `src/` and does not alter the frozen P0 implementation.

## Public flow

1. Configure `VerifierRegistry` with the verifier's exact evidence store, neutral permit store, and allowed tool identifiers.
2. Configure `StatusStoreRegistry` with the status issuers allowed to use each simulated origin store.
3. Create a `NeutralPermitStore` and capture its snapshot at the `LocalObservation.decision_time`.
4. Call `prepare_common_gate_input(...)`. Preparation runs the declared Sprint 2 validator, admits only its process-tagged `PolicyView` objects, authenticates every delivered authority-status message, checks configured stores, and returns a representation-blind `CommonGateInput`.
5. Call `CommonActionGate.authorize(common_input, action=..., tool_id=...)`.
6. Before the adapter acts, call `consume(...)`. Afterwards, call `finish(..., succeeded=True|False)`.

`consume(...)` accepts only a profile-valid permit identifier emitted by `authorize(...)`; malformed identifiers are rejected before state access.

The common gate selects one unambiguous leaf matching the exact payment-action hash. It requires a root delegation, delegation-only intermediates, an action-intent leaf, valid parent and party continuity, one consistent authority lineage and version, strict scope attenuation, current scope times, and action compliance.

All delivered status messages must authenticate under a locally trusted status key and configured origin. For the relevant lineage, distinct authenticated statuses at one version are a conflict. The highest delivered version controls: a higher version makes an older chain stale, and an allowed status must be referenced, active, already issued, fresh at decision time, and causally referenceable by the signed handoffs.

## Neutral permits

Permits bind the leaf neutral handoff, complete neutral chain, controlling status, exact request, tool, replay scope, nonce, issue time, and expiry. The replay scope hashes the authority lineage and version, so equivalent SL, CR, and PR encodings share the same local replay key. SQLite reservation compares a monotonic expected revision and records interaction and structured sender-sequence bindings atomically.

The lifecycle is:

```text
RESERVED -> ATTEMPTED -> SUCCEEDED
                      -> FAILED
```

`ATTEMPTED` is written before the adapter acts. A crash after that transition is not retried automatically. This is one-attempt enforcement in one local database, not global replay prevention or exactly-once execution.

Operational setup assumes one coordinated initializer for a new SQLite store. A simultaneous cross-process first-open may fail closed and must be retried or reconciled by operations; it never authorises an automatic action retry.

## Trust and claim boundary

`CommonGateInput` has a non-serialised process tag. Its JSON form is an audit record; decoded or caller-created inputs must be prepared again. This is an honest-caller misuse barrier, not a portable credential or protection from arbitrary Python code inside the process.

Store registries are trusted simulator configuration. Transport origins are declarations, not cryptographically authenticated network identities. Signatures prove only that a configured key signed particular bytes. The package does not establish semantic truth, honest participants, global fork prevention, cumulative budgets, control of uninstrumented tools, production security, or improved AI safety.

Run the focused checks with:

```shell
python -m pytest -q tests/test_sprint3_common_gate.py
```

Run the complete repository regression and frozen P0 verifier separately before release.
