# Threat model

## Status and scope

This document defines the narrow security boundary of the CrossTrace protocol sketch. The artifact is an illustrative feasibility prototype, not a production authorisation system and not a CrossTrace safety experiment.

The demonstrated setting contains a buyer agent, a broker agent, a local payment adapter, a local key registry, and a source of signed authority-status statements. The action language is limited to the structured `payment-v1` scope.

## Protected decisions

The prototype aims to prevent one local adapter from issuing an execution permit when the evidence presented to it is incomplete or locally invalid. Specifically, it tries to make the following failures detectable at that adapter:

- a sender or receiver attestation is missing or its signature does not verify;
- the receiver attestation does not pair with the sender attestation;
- the claimed parent receipt does not match the recorded parent link;
- the requested payment differs from the signed `payment-v1` scope;
- the relevant authority status is revoked, expired, stale under local policy, or incorrectly signed;
- the request exceeds the per-action scope represented in the evidence;
- a local one-use permit is presented for a second consumption.

Failure of any required check results in no permit. This is the sense in which the sketch is "fail closed." It is a local decision rule, not a claim that every system or participant stops.

## Trust assumptions

The demonstration assumes that:

- private signing keys used by honest participants have not been disclosed;
- the verifier's local mapping from identity and key identifier to verification key and permitted signing role is correct;
- the authority-status signer is trusted to state current authority for the demonstrated domain;
- canonicalisation and signature verification are implemented consistently;
- raw JSON crosses the trust boundary through the strict duplicate-key-rejecting parser;
- the payment adapter accepts only permits issued and consumed through this verifier;
- local storage used to mark a permit as consumed is intact for the life of the demonstration;
- clock and freshness inputs used by the verifier are sufficiently accurate for the configured policy.

These assumptions are inputs to the sketch, not properties established by it.

## Adversary capabilities considered

An adversary may alter, omit, reorder, replay, or substitute receipt data; supply an expired or revoked authority status; change the requested payee or amount after a receipt is signed; break a parent link; or reuse a permit at the same local verifier. The deterministic rejection examples exercise some of these cases.

The prototype does not assume that natural-language instructions can safely define payment authority. It checks only the fields in the structured `payment-v1` scope.

## Explicit limitations

### Signatures are not truth

A valid signature shows that the holder of a signing key signed particular bytes. It does not prove that the statement is factually correct, that the signer understood it, that the signer was uncompromised, or that the underlying action is beneficial or lawful.

### Collusion

Participants that collude can sign mutually consistent false receipts. Requiring both attestations improves attribution of the claimed handoff; it does not create an independent source of truth when both signers cooperate maliciously.

### Shared or stolen keys and clones

If agents share a key, a key is stolen, or multiple clones use the same key, this protocol cannot distinguish which process produced a valid signature. Key lineage and secure key custody require mechanisms outside this sketch.

### Partial-view forks and equivocation

Different verifiers can be shown different, individually valid-looking branches. Parent links expose inconsistencies only when the conflicting evidence is brought together. The prototype has no distributed gossip, transparency log, quorum, consensus, or global fork detector.

### Global replay and double-spending

The permit store reserves an action nonce within one delegated authority and adapter, independently of which leaf receipt carries it, and marks a permit attempted before the adapter acts. It prevents a second use only within that demonstrated local database boundary. It does not stop the same request or equivalent permits being used at another verifier, after local state loss, or through another payment rail. A crash after the attempted transition requires manual reconciliation rather than automatic retry. This is not exactly-once execution or a global double-spend solution.

### Per-action scope, not cumulative budget

`payment-v1` constrains the demonstrated action. Passing an amount check for one receipt does not maintain or prove a cumulative daily, project, account, or cross-agent budget. Repeated individually valid payments may exceed an intended aggregate limit unless a separate shared accounting system enforces it.

### Out-of-band tools

An agent may call an uninstrumented API, use another credential, instruct a human, or otherwise bypass the local adapter. CrossTrace can fail closed only at an integration point that actually requires its permit.

### Status freshness, clocks, and networks

A correctly signed status can still be old. Clock skew can change expiry decisions, and delayed or partitioned networks can hide a newer revocation. A production design would need a defined freshness source, maximum staleness policy, revocation distribution model, and behaviour under partition. The offline demo supplies local inputs and does not solve these problems.

### Local key registry

The verifier trusts a local key registry, including its distinction between receipt-signing and authority-status-signing roles. It does not implement certificate issuance, key rotation, recovery, revocation of identity keys, hardware-backed custody, or an independently auditable public-key directory. A wrong registry entry or role can make a valid participant appear invalid or an attacker appear valid.

## Out of scope

The sketch does not attempt to establish:

- semantic truth or quality of an agent's reasoning;
- bank, card-network, legal, or organisational authorisation;
- confidentiality of receipt contents;
- availability during network or authority-service failure;
- Byzantine consensus or a globally consistent ledger;
- protection of the host, process memory, or private-key storage;
- automatic containment outside the local payment adapter;
- improved safety, lower incident rates, or any other empirical outcome.

## Claim boundary

The strongest supported statement is: under the stated local assumptions, the sketch demonstrates two linked handoff receipts, each signed by both participants, and a deterministic verifier that withholds a local one-attempt permit for specified invalid inputs. Any claim about real-world containment or comparative safety requires separate research.
