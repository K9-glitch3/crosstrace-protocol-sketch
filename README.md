# CrossTrace: signed handoff receipts for delegated actions

Before a payment agent acts, it should be able to check who delegated the action, what limits were agreed, and whether that authority is still current.

This repository implements one worked example. A buyer delegates a bounded payment scope to a broker (Receipt A). The broker then asks a payment agent to perform one narrower payment (Receipt B). Each completed receipt contains the exact proposal plus attestations from both sender and receiver. Receipt B links to Receipt A.

A local verifier checks both signatures on each receipt, the parent link, scope narrowing, a fresh signed authority-status statement, the exact action hash, and time limits. It issues a short-lived, one-attempt permit only if every check passes. Missing or invalid evidence returns `PAUSE` and no permit.

This is a runnable design sketch, not a CrossTrace experiment or evidence of improved safety. See [Protocol](docs/PROTOCOL.md) for the object and decision flow, and [Threat model](THREAT_MODEL.md) for its limits.

## Run the example

Requirements: Python 3.11 or newer. The example uses synthetic identities and actions, makes no network request, and performs no payment.

```shell
python -m pip install -e ".[test]"
python -m crosstrace_sketch.demo
```

The buyer -> broker -> payment-agent trace exercises four local decisions, summarised as:

```text
valid gate: ALLOW
first consume: ALLOW
replayed consume: PAUSE
revoked/over-limit gate: PAUSE
```

To run the behaviour tests:

```shell
python -m pytest
```

To run the deterministic scripted systems pilot and independently recompute its
summary:

```shell
python -m crosstrace_sketch.pilot.runner
python -m crosstrace_sketch.pilot.verify pilot/results/pilot-v0.1
```

The pilot uses neutral event inputs to encode five evidence conditions across
six scripted scenarios. Its ten variants per cell are robustness fixtures, not
independent trials. It makes no model or network calls. See the
[`pilot` documentation](pilot/README.md) and read its
[`claims boundary`](pilot/CLAIMS_BOUNDARY.md) before citing the output.

The full deterministic output is in [`examples/expected_output.txt`](examples/expected_output.txt). Permit identifiers are omitted because each run creates them locally.

## Protocol at a glance

Receipt B contains a signed proposal shaped like this abbreviated, non-validating view:

```json
{
  "interaction_id": "handoff-broker-payment-001",
  "event_type": "action_intent",
  "sender": {"principal_id": "broker.example", "agent_id": "broker-agent-1", "key_id": "broker-agent-key-1"},
  "receiver": {"principal_id": "payment.example", "agent_id": "payment-agent-1", "key_id": "payment-agent-key-1"},
  "previous_receipt_id": "sha256:<completed-receipt-a>",
  "scope": {
    "operations": ["payment"],
    "resources": ["urn:crosstrace:payee:supplier-17"],
    "currency": "USD",
    "max_amount_minor": 950000,
    "not_after": "2026-08-05T15:30:00Z",
    "redelegations_remaining": 0
  },
  "authority": {
    "issuer_principal_id": "buyer.example",
    "subject_principal_id": "broker.example",
    "authority_version": 7,
    "revocation_status_id": "sha256:<signed-status>"
  },
  "request_hash": "sha256:<exact-payment-action>"
}
```

The complete proposal also carries creation time, nonce, sender sequence, `not_before`, and the subject key. The [JSON Schema](schema/handoff-receipt.schema.json) is the field reference; the example constructs and verifies complete signed objects locally.

Amounts use integer minor units: `950000` USD means USD 9,500.00.

## Implemented

- Sender and receiver attestations bound to the same proposal.
- A cryptographic link to the claimed parent receipt.
- A structured `payment-v1` scope with integer minor-unit limits.
- A signed authority-status statement checked against local freshness policy.
- Local fail-closed verification: failed or unavailable evidence yields no permit.
- A short-lived permit bound to one exact action and one local attempt.
- Rejection cases for altered, expired, revoked, replayed, conflicting, and out-of-scope evidence.

## Limits

Signatures establish who signed specific bytes; they do not establish that a statement is true or that its signers are honest. This sketch does not solve collusion, stolen or shared keys, indistinguishable clones using one key, partial-view forks, global double-spending, cumulative budgets, or actions taken through uninstrumented tools. Its authority view, key registry, clocks, and permit store are local.

These boundaries are detailed in [THREAT_MODEL.md](THREAT_MODEL.md). Do not use this code to authorise real payments or other consequential actions.

## Repository map

- `schema/` — JSON Schemas for authority status, handoff receipts, and payment actions.
- `examples/` — the buyer -> broker -> payment-agent trace and expected output.
- `src/crosstrace_sketch/` — construction, signing, verification, and local permit logic.
- `tests/` — deterministic acceptance and rejection cases.
- `pilot/` — scripted conformance design, schemas, verifier, and result release.
- `docs/PROTOCOL.md` — field meanings, receipt pairing, and decision flow.
- `THREAT_MODEL.md` — assumptions, security goals, and known limits.
- `SECURITY.md` — safe-use and private vulnerability-reporting guidance.

## Research status

This repository specifies and exercises the mechanism. It contains a
credential-free scripted conformance pilot, but no LLM or frontier-agent outcome
data. The pilot does not support comparative safety, containment, or
operational-cost claims; those require a separate preregistered experiment.

## License

Copyright 2026 Michael Owusu.

Licensed under the [Apache License 2.0](LICENSE).
