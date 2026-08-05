# Protocol sketch

## 1. Purpose

This document describes a small, inspectable handoff protocol for the buyer-broker-payment example. Its purpose is to replace ambiguous delegation prose with signed, structured evidence that a local verifier can check before issuing a one-use permit.

The document describes an illustrative feasibility prototype. It is not a standard, a production protocol, or evidence from a CrossTrace experiment.

## 2. Roles

- **Sender:** the agent proposing a handoff. In Receipt A this is the buyer; in Receipt B this is the broker.
- **Receiver:** the agent accepting or rejecting the exact proposal. In Receipt A this is the broker; in Receipt B this is the payment agent.
- **Authority-status issuer:** the party trusted by the local verifier to sign the current authority state for an agent and scope.
- **Verifier:** the local component that validates evidence and may issue a permit.
- **Adapter:** the local action boundary that consumes a valid permit before performing an action. The demonstration adapter does not perform a real payment.

## 3. Evidence objects

The machine-readable schemas define the exact object shape and field types implemented in this repository. Runtime validation additionally enforces sorted arrays, real and ordered timestamps, scope attenuation, signature bindings, and other cross-field rules that JSON Schema alone does not express. Conceptually, the protocol uses an authority-status statement, completed handoff receipts, an exact action, and a local permit.

### 3.1 Signed authority status

An authority-status statement identifies its issuer, the delegated subject and key, authority version, `ACTIVE` or `REVOKED` state, issue time, freshness deadline, and signature. The receipt carries the action scope. The verifier accepts the status only if its issuer is trusted locally, its signature verifies, it matches the root delegation, and it is current under local policy.

"Signed current authority status" therefore means current according to evidence and freshness rules available to this verifier. It does not prove that no newer revocation exists elsewhere.

### 3.2 Handoff proposal and sender attestation

The proposal records:

- the sender and intended receiver;
- an interaction identifier and sender sequence number;
- the parent receipt identifier, or `null` for the root;
- the structured action scope and authority-status reference;
- creation time, request hash, and nonce.

The sender attestation records the proposal hash, sender key ID, and signature algorithm. Its signature commits the sender to those fields and, through the hash, to the complete proposal.

The parent link identifies the prior handoff that this proposal claims to follow. It does not show that the verifier has seen every branch.

### 3.3 Receiver attestation and completed receipt

The receiver attestation records the exact proposal hash and sender attestation it evaluated, its `ACCEPT` or `REJECT` decision, an optional reason code, decision time, key ID, and signature.

The proposal, proposal hash, sender attestation, and receiver attestation form one completed receipt. Receipt B identifies Receipt A by the content hash of the completed Receipt A. Because the receiver signs the exact proposal hash and sender attestation, it cannot silently accept a different resource or amount while retaining a valid-looking signature for the original proposal.

Canonical bytes use this sketch's deliberately narrow deterministic JSON profile: printable ASCII strings, interoperable-range integers, sorted object keys, and no insignificant whitespace. Floats and non-ASCII strings are rejected. Raw JSON ingestion must use the exported `loads_strict` parser to reject duplicate keys before they are collapsed into a mapping; `ActionGate` cannot recover duplicates discarded by a different parser. This prototype does not claim full RFC 8785 conformance.

### 3.4 Local one-use permit

A permit binds the locally approved receipt pair to the action and a short validity interval. The adapter may consume it once. A second consumption, an expired permit, or a permit for different action data is refused.

The permit is an enforcement token only inside this implementation's local storage and adapter boundary. It is not a transferable payment credential, a global lock, or protection against another verifier issuing an equivalent permit.

## 4. Structured `payment-v1` scope

The `payment-v1` scope encodes the operation, permitted resource identifiers, currency, per-action maximum in integer minor units, validity window, and remaining redelegations. In the example, the resource is a synthetic payee URN. Floating-point money is prohibited.

The verifier compares the proposed action to that structure. An action is rejected if, for example, its payee differs, its amount exceeds the per-action bound, its scope has expired, or the requested redelegation is not permitted.

This is a per-action check. It does not calculate cumulative spend across otherwise valid receipts.

## 5. Handoff and decision sequence

1. **Obtain authority evidence.** The buyer issues a signed current status for the delegated broker authority.
2. **Create Receipt A.** The buyer signs a root delegation proposal naming the broker and a maximum scope. The broker signs its decision over that exact proposal and sender attestation.
3. **Create Receipt B.** The broker proposes a narrower exact payment intent linked to the completed Receipt A. The payment agent signs its decision over that proposal and sender attestation.
4. **Verify locally.** The verifier checks parsing, trusted key roles, both signatures on each receipt, causal timestamp order, the completed parent identifier, party continuity, scope attenuation, current authority status, expiry, and the leaf request hash against the exact action.
5. **Issue or withhold.** If every required check succeeds, the verifier creates a short-lived local permit bound to the receipt pair and action. Otherwise it returns a refusal and creates no permit.
6. **Consume once.** The local adapter verifies that the permit is unexpired, unconsumed, and bound to the action, then marks it consumed before returning the demonstration result. Reuse is refused locally.

Unavailable evidence is treated as a failed check. The verifier does not infer missing authority from natural-language context.

The local key registry distinguishes ordinary receipt-signing keys from keys trusted to issue authority status. Merely registering a key for a principal does not let that key issue revocation state. Receipt and status signatures use canonical unpadded base64url encoding so one signature byte string has one accepted textual representation.

Permit state moves from `RESERVED` to `ATTEMPTED` before the simulated adapter acts, then to `SUCCEEDED` or `FAILED`. A crash after `ATTEMPTED` is not retried automatically. This is one-attempt local gating, not exactly-once execution.

## 6. Buyer-broker-payment example

The repository's example trace represents a buyer delegating payment authority to a broker, followed by the broker asking a payment agent to attempt one payment within a narrower `payment-v1` scope. The valid path has:

- a trusted buyer issuer's signed active authority status for the broker's delegated key;
- Receipt A signed by the buyer and accepted by the broker;
- Receipt B linked to completed Receipt A, signed by the broker, and accepted by the payment agent;
- a narrower child scope and an exact action hash;
- one successful local permit consumption.

Rejection variants alter conditions such as the amount, resource, signature, parent link, status, expiry, receipt pairing, or permit-use state. The headline blocked scenario combines a USD 18,000 request with revoked version-7 authority after Receipt A allowed at most USD 10,000. These are demonstrations of specified control flow, not measurements of adversarial robustness.

## 7. Fail-closed conditions

The verifier must not issue a permit if a required object or field is missing, a signature fails, a signer is unknown, the authority-status issuer is not locally trusted, the status is inactive or not current, a parent link cannot be validated under the demonstrated evidence set, the receipts do not form an exact pair, the structured scopes conflict, the receiver did not accept, or any relevant time bound has failed.

The adapter must refuse a permit that is invalid, expired, already consumed locally, or bound to different action data.

## 8. Security interpretation

The protocol makes a claimed delegation trace more explicit and locally checkable. It does not prove the statements are true, prevent collusion, identify clones sharing a key, reconcile partial-view forks, provide global replay prevention, enforce cumulative budgets, control out-of-band tools, or make stale status fresh. It relies on a local key registry and local trust configuration.

See [the threat model](../THREAT_MODEL.md) for the complete claim boundary.
