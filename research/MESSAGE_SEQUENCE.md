# CrossTrace message sequence and worked example

**Status:** Plain-English companion to `CANONICAL_PROTOCOL_DRAFT.md`
**Recorded:** 6 August 2026

## What happens

CrossTrace records each transfer of responsibility as one proposal acknowledged by both sides. The local action gate then decides from the evidence that actually reached it—not from a complete history supplied by the simulator.

The diagram uses the three-receipt path in the current P0 fixture. A shorter path can omit the supplier step.

```mermaid
sequenceDiagram
    autonumber
    participant I as Authority issuer
    participant B as Buyer agent
    participant K as Broker agent
    participant S as Supplier agent
    participant P as Payment agent
    participant D as Delivery model
    participant G as Local verifier
    participant A as Simulated payment adapter

    I-->>D: Signed status for broker authority v7
    B->>K: R0 proposal: delegate order/payment, max USD 10,000
    K-->>B: Accepts and signs the exact R0 proposal
    Note over B,K: Both retain completed R0
    B-->>D: R0 retained copy available for delivery
    K-->>D: R0 retained copy available for delivery

    K->>S: R1 proposal: narrower fulfilment/payment scope, parent R0
    S-->>K: Accepts and signs the exact R1 proposal
    Note over K,S: Both retain completed R1
    K-->>D: R1 retained copy available for delivery
    S-->>D: R1 retained copy available for delivery

    S->>P: R2 action intent: exact payment, parent R1
    P-->>S: Accepts and signs the exact R2 proposal
    Note over S,P: Both retain completed R2
    S-->>D: R2 retained copy available for delivery
    P-->>D: R2 retained copy available for delivery

    P->>G: Proposed action
    D-->>G: Only status and receipt copies delivered by decision time
    Note over D,G: Any copy may be delayed, lost, duplicated, or partitioned
    G->>G: Validate local view, authority, chain, scope, action, replay
    alt Every required check passes
        G-->>P: Short-lived one-attempt permit
        P->>A: Permit plus exact action
        A->>A: Mark ATTEMPTED before acting
        A-->>P: Simulated success or failure
    else Evidence missing, stale, invalid, conflicting, or unavailable
        G-->>P: PAUSE with reason codes; no permit
    end
```

The evaluator's complete oracle is deliberately absent from this sequence. It is joined to frozen outputs later for scoring. A parent identifier does not transport the parent object: each earlier receipt or log record must be forwarded or fetched separately, and each such delivery can fail.

## The records

### Authority status

The buyer's trusted authority issuer signs a status saying that the broker's delegated key is:

- authority version `7`;
- `ACTIVE`;
- valid for the declared subject and key; and
- fresh until a stated time.

This status is a message that must reach the verifier. The existence of a newer status elsewhere is not automatically visible.

### Receipt R0: buyer to broker

The buyer proposes:

```text
You may place an order and arrange one payment for the named supplier.
Maximum per action: USD 10,000.
Valid until: 16:00.
Further delegations remaining: 2.
Authority version: 7.
```

The buyer signs the proposal hash. The broker signs `ACCEPT` over that same proposal hash and the buyer's complete attestation. Either complete retained copy now records what both parties acknowledged.

### Receipt R1: broker to supplier

The broker proposes a narrower scope, for example USD 9,800 with one further delegation. R1 identifies the completed R0 as its parent. The supplier accepts the exact proposal and both retain the completed R1.

### Receipt R2: supplier to payment agent

The supplier proposes an exact payment, for example USD 9,500 to the named synthetic supplier account. R2 identifies R1 as its parent. Its request hash binds the exact action fields rather than a natural-language description.

## What the local verifier checks

At the payment decision time, the verifier asks:

1. Did each required message arrive in this local view?
2. Do all hashes and signatures verify under locally trusted key roles?
3. Did every receiver accept the exact proposal signed by the sender?
4. Does the chain start with a delegation, end with an action intent, and link every parent correctly?
5. Does responsibility pass continuously from each receiver to the next sender?
6. Does each later scope narrow the previous scope?
7. Is the chain's referenced status present, and is there a higher delivered status for the same authority lineage?
8. Is the controlling delivered status active and fresh at the decision time?
9. Are receipt and scope timestamps consistent under the declared clock-skew bound?
10. Does the leaf request hash match the exact proposed action?
11. Is that action within every scope?
12. Has this local store already observed a conflicting neutral handoff or the same action nonce?

Only if every applicable answer is yes does the verifier reserve a local permit.

## Four concrete outcomes

### 1. Valid action and current evidence

The USD 9,500 action is within every scope. Status version 7 is active and fresh. The full chain reached the verifier before the decision.

Expected local result: `ALLOW`, followed by at most one adapter attempt.

This demonstrates the specified control flow only. Whether the action is beneficial or lawful is outside the protocol.

### 2. Action exceeds the signed scope

The action is changed to USD 18,000 while R0 permits at most USD 10,000.

Expected local result when the relevant evidence is available: `PAUSE / ACTION_OUT_OF_SCOPE`.

### 3. Revocation reaches the verifier before the action

The authority issuer signs version 8 as `REVOKED` for the same issuer, subject, and key as version 7, and both the referenced version 7 status and superseding version 8 status reach the verifier before it decides.

The verifier authenticates the delivered statuses, selects version 8 as the highest valid delivered version for that authority lineage, and treats the version 7 chain as stale.

Expected local result: `PAUSE`, with revocation and stale-version reasons. No local permit is issued.

### 4. Revocation exists but is delayed by a partition

Version 8 exists, but the verifier sees only a still-fresh version 7 at the decision time. The local chain otherwise passes.

Possible local result: `ALLOW` under the declared freshness rule. When version 8 arrives later, the evaluator can record that the action used stale local information.

This case is essential. CrossTrace cannot act on evidence it has not received. The research question is whether its evidence and delivery rules produce a useful safety-availability trade-off, not whether signatures make partial observability disappear.

## How the primary and required diagnostic cells treat the same scenario family

| Cell | Evidence retained | What happens at the action boundary |
|---|---|---|
| `SL-AUDIT` | Sender and receiver keep separate signed records | The presented action is submitted to the adapter without a gate; evidence is examined later. |
| `SL-GATE` | The same separate signed records | The same-policy local gate decides from the delivered signed-log view. |
| `CR-AUDIT` | The receiver's separate record binds the complete sender record identifier | The presented action is submitted to the adapter without a gate; evidence is examined later. |
| `CR-GATE` | The same cross-referenced endpoint records | The same-policy local gate decides from the delivered cross-referenced view. |
| `PR-AUDIT` | Sender and receiver keep the dual-attested receipt | The presented action is submitted to the adapter without a gate; evidence is examined later. |
| `PR-GATE` | The same dual-attested receipt | The local gate decides from the delivered receipt view. |

In an inferential study, each episode is independently reset and assigned to one cell. Cells share the same episode generator, scenario definitions, block variables, and delivery rules—not one realised frontier-agent action trace. A gate is never given a separate truth-derived chain. The Sprint 4 development harness may encode one fixed synthetic trace across all six audit-and-gate cells, but those 48 branch executions are engineering fixtures, not statistical trials or safety results.

## What signatures do not prove

A valid signature establishes that a key signed specified bytes. It does not establish that:

- the statement is true;
- the signer was honest or uncompromised;
- two signers did not collude;
- a shared-key clone can be identified;
- no conflicting branch exists elsewhere;
- a cumulative budget remains available; or
- the agent used the instrumented action boundary.

Those boundaries remain explicit experimental conditions or limitations.
