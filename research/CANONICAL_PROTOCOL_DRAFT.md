# CrossTrace canonical protocol draft

**Document version:** `preaward-0.1`

**Status:** Provisional design snapshot; not a standard, preregistration, or funded protocol

**Recorded:** 6 August 2026
**P0 baseline:** commit `824078b876f23d4d138a9dd2fff3a6c1ff6d5c80`

## 1. Research question

CrossTrace asks two separate questions:

1. Does a dual-attested handoff receipt improve reconstruction of the recorded path set by which authority moved between independently controlled agents, compared with information-matched separate signed endpoint logs?
2. Within each evidence representation, does a local pre-action gate applying the same policy reduce unauthorised simulated actions without causing an unacceptable loss of legitimate task completion?

The protocol does not assume either answer is positive.

## 2. Core idea in plain English

When one agent asks another agent to take responsibility for a task, the sender signs the exact proposed handoff. The receiver then signs its decision over that same proposal and the sender's attestation. The completed record is retained by both sides.

A later handoff identifies the completed earlier receipt. This produces a chain from an initial delegation to an exact proposed action. Before a hard-to-reverse action, a local verifier examines only the evidence delivered to it by that time. It issues a short-lived, one-attempt permit only if the chain, authority status, scope, signatures, timing, and proposed action all pass its checks. Missing or contradictory evidence causes that local action to pause.

The preferred term is **dual-attested handoff receipt**. The earlier phrase “peer-witnessed causal evidence” is avoided because the two signers are the handoff participants, not independent witnesses. The receipt asserts a parent link. Timestamps are used only for freshness, expiry, and declared temporal consistency under the clock assumption; they do not prove real-world causation.

CrossTrace is not proposed as a new signature primitive. Its claimed research contribution is the systems comparison of exact cross-party binding, retention, delivery under partial views, linked authority, and local gating—including comparison with a stronger countersigned-log control.

## 3. System boundary

The study models agents operated by separate principals. A principal may be an organisation, team, or accountable individual. Each principal controls its own agents, keys, evidence store, and action boundary. There is no assumed universal monitor or single controller.

CrossTrace is evaluated at one instrumented action boundary. It does not stop an agent from using an uninstrumented tool or another credential. The evaluator maintains a complete synthetic ground-truth record, but agents, evidence conditions, and gates cannot access it.

## 4. Terms

| Term | Meaning in this protocol |
|---|---|
| Principal | The organisation, team, or person accountable for an agent. |
| Agent | A process acting for a principal. |
| Sender | The agent proposing a handoff. |
| Receiver | The agent accepting or rejecting that exact proposal. |
| Authority issuer | A locally trusted party that signs the status of a delegated authority. |
| Dual-attested receipt | One proposal, signed by the sender and then accepted or rejected by the receiver over the same proposal and sender attestation. |
| Parent receipt | The completed earlier handoff named by a later handoff. |
| Scope | Structured limits on operations, resources, amount, time, and further delegation. |
| Authority version | A number identifying the authority state referenced by the handoff. A replacement or revocation can advance the version. |
| Local view | Evidence delivered to one verifier no later than its decision time. |
| Gate | A local policy component that validates its local view before issuing a permit. |
| Permit | A short-lived token bound to one action, tool, and local attempt. |
| Pause | Refusal to issue or consume a permit. It means the local evidence did not justify execution; it is not a claim of guilt or malicious intent. |
| Oracle | Evaluator-only ground truth used after execution for scoring. |

## 5. Evidence objects

### 5.0 Implementation status

| Component | Current status; P0 remains frozen |
|---|---|
| Parties, structured payment scope, action identity, authority reference | Implemented |
| Dual-attested receipts and variable-length receipt verification | Implemented |
| Signed authority status and local key roles | Implemented |
| Selection among multiple delivered authority statuses | Development-only Sprint 3 implementation verified in synthetic fixtures; P0 still accepts one supplied status |
| Local one-attempt permit and simulated adapter | Implemented |
| Decision-time observation object | Development-only Sprint 1 implementation; not promoted into frozen P0 |
| Deterministic message delivery, loss, partition, and stale-view layer | Development-only Sprint 1 implementation; no research outcomes generated |
| Origin-store registry binding evidence to an endpoint principal and role | Development-only Sprint 2 implementation |
| Exact `SL`, `CR`, and fair-profile `PR` validators | Development-only Sprint 2 implementation; no research outcomes generated |
| Common `ValidatedHandoff` interface for all three evidence formats | Development-only Sprint 2 implementation; representation-blind evidence policy only |
| Verifier binding to authorised evidence store, permit store, and tools | Development-only Sprint 3 implementation verified in synthetic fixtures |
| Representation-blind authority, chain, scope, action, replay, and permit gate | Development-only Sprint 3 implementation verified in synthetic fixtures |
| Six-cell `SL`/`CR`/`PR` audit-and-gate harness | Published development-only Sprint 4 release over eight synthetic cases; not a study |
| Frontier-model, multi-principal, or confirmatory experiment | Not run |

### 5.1 Party

A party reference contains:

- `principal_id`;
- `agent_id`; and
- `key_id`.

The local key registry maps a key to a principal and permits it to sign either receipts, authority status, or both. Registration is a trust input, not a fact established by CrossTrace.

### 5.2 Structured scope

The implemented `payment-v1` scope contains:

- permitted operations;
- permitted resource identifiers;
- currency;
- maximum amount for one action, in integer minor units;
- start and expiry times; and
- remaining redelegations.

Every later delegation must narrow, not expand, the earlier scope. The current prototype checks a per-action maximum; it does not maintain a cumulative budget.

### 5.3 Exact action

An action contains an action nonce, operation, resource, currency, and amount. Its identifier is derived from the complete structured action. Natural-language similarity is not used to decide whether two actions match.

### 5.4 Authority reference and signed status

Each proposal identifies the authority issuer, delegated subject, subject key, authority version, and the signed status it relies on. The signed status states `ACTIVE` or `REVOKED`, when it was issued, and when it becomes stale.

“Current authority” always means current within the verifier's delivered local view and freshness policy. The protocol cannot prove that a newer revocation does not exist elsewhere.

The development observation may contain zero or more statuses. For one authority lineage—defined by issuer, subject, and subject key—versions are positive integers that increase monotonically. `status_id` is the content identifier of the complete status payload. A valid higher version supersedes every lower version whether its state is `ACTIVE` or `REVOKED`; an old handoff chain must be reissued against the higher version before it can proceed. Two different valid payloads at any one delivered version are equivocation and cause `PAUSE`.

The verifier authenticates all statuses for the lineage delivered by the decision time. Two distinct authenticated statuses at any one delivered version cause `PAUSE`; otherwise the unique highest delivered version controls. The gate also pauses if that status is issued in the future, stale, revoked, not referenced by the chain, or newer than the chain's authority version. Statuses that arrive later cannot change the earlier verdict, but they remain available for post-event scoring.

The Sprint 3 development gate applies this selection rule to the authenticated statuses in one decision-time local view and passed its synthetic integration checks. P0 does not implement the collection rule: it receives one status object and requires its version and identifier to match the chain.

### 5.5 Handoff proposal

A proposal records:

- sender and receiver;
- interaction identifier and sender sequence;
- `delegation` or `action_intent` event type;
- parent receipt identifier, or no parent for the root;
- structured scope and authority reference;
- creation time, nonce, and exact request hash.

### 5.6 Completed receipt

A completed receipt contains:

1. the proposal;
2. the proposal hash;
3. the sender's signature over that proposal hash; and
4. the receiver's signed decision over the same proposal hash and complete sender attestation.

The content-derived receipt identifier covers the completed object. A later proposal names that identifier as its parent.

### 5.7 Receipt chain

A valid candidate chain has:

- exactly one root delegation with no parent;
- zero or more intermediate delegations;
- exactly one action-intent leaf; and
- party continuity: the receiver of each receipt is the sender of the next.

The implementation accepts variable-length chains. The smallest worked example uses two completed receipts; the P0 fixture adds an intermediate supplier and therefore uses three. P0 checks the root and leaf event types but does not yet enforce that every intermediate receipt is a delegation. The Phase I implementation must add that check before protocol freeze. Chain length is not itself a treatment.

### 5.8 Decision-time observation

Sprint 1 adds an explicit development-only observation object outside P0. It contains:

- verifier identity and local evidence-store identity;
- decision timestamp;
- records delivered by that timestamp;
- authority statuses delivered by that timestamp;
- local permit-store state;
- metadata and payload hashes for messages actually delivered by that timestamp; and
- no scenario label, expected fault, future record, or oracle value.

The local view never reveals missing-message identifiers, future deliveries, the global delivery schedule, or another principal's undelivered records. It declares both the evidence-store and permit-store identifiers and rejects a permit snapshot bearing a different store identifier. Sprint 3 adds a development verifier registry that binds each verifier to an evidence store, neutral permit store, and allowed tools. The formal study must freeze and review that registry rather than infer ownership from identifier text. Every gate input must be derived from the observation through the representation-specific validator. A test harness must not construct a separate complete chain for the gate.

### 5.9 Local permit

A Sprint 3 development permit is bound to the leaf neutral handoff, neutral chain, controlling authority status, exact request hash, action nonce, tool, local replay scope, issue time, and expiry. This replaces P0's receipt-named permit field at the common-gate boundary without changing P0. Its local lifecycle is:

```text
RESERVED -> ATTEMPTED -> SUCCEEDED
                      -> FAILED
```

Reservation compares the decision-time permit-store revision and records neutral interaction and sender-sequence observations atomically. A changed revision, conflicting observation, or duplicate replay key causes `PAUSE`. The adapter marks the permit `ATTEMPTED` before acting. A crash after that point requires reconciliation and is not retried automatically. This is one-attempt local gating, not globally exactly-once execution.

## 6. Protocol sequence

1. An authority issuer signs the status of a delegated key.
2. A sender creates a structured handoff proposal and signs its hash.
3. The receiver checks the proposal and signs `ACCEPT` or `REJECT` over the exact proposal and sender attestation.
4. Both endpoints retain the completed receipt.
5. A later sender creates a narrower proposal that names the completed parent receipt.
6. At an action boundary, the delivery simulator constructs the verifier's local view using only messages delivered by the decision time.
7. The representation-specific validator verifies the delivered record signatures and normalises the evidence under the declared simulator store mapping.
8. If the gate is enabled, the common policy engine applies the decision rule below. If the gate is disabled, the presented action proceeds and the evidence is retained for audit only.
9. An allowed permit is consumed once by the local adapter. A paused action is not executed at that boundary.
10. Evidence delivered after the decision may support later diagnosis, but cannot be counted as prevention.

## 7. Local decision rule

The gate returns `ALLOW` only if all applicable predicates succeed:

1. Every required object parses under the strict canonical profile.
2. Each key is trusted locally for the role in which it signs.
3. Content hashes, sender signatures, receiver signatures, and authority-status signatures verify.
4. Every receiver decision is `ACCEPT`.
5. The root is a delegation and the leaf is an action intent.
6. Parent links and party continuity hold; declared timestamps are consistent under the study's explicit clock-skew bound.
7. The authority issuer, subject, key, and version remain consistent through the chain.
8. Every child scope narrows the parent scope.
9. The referenced signed status is present, and no higher delivered version for the same authority lineage makes the chain stale; the controlling status is active and fresh at decision time.
10. Handoff and scope time bounds are valid at decision time.
11. The leaf request hash equals the exact action identifier.
12. The action is permitted by every scope in the chain.
13. No conflicting neutral handoff observation or local replay has already been recorded in that permit store.
14. Local permit state is available and reservation succeeds.

Any failed, missing, contradictory, stale, or unavailable requirement yields `PAUSE` with one or more machine-readable reasons. Unexpected verifier errors also yield `PAUSE`.

The permit expires at the earliest of the configured permit lifetime, the earliest scope expiry, and the controlling status freshness bound. Consumption checks the permit, tool, request hash, nonce, state, and time again.

## 8. Fair receipt-by-gate experiment

The primary design changes two factors independently:

| Evidence representation | Audit only; no gate | Same-policy local gate |
|---|---:|---:|
| Separate signed endpoint logs | `SL-AUDIT` | `SL-GATE` |
| Dual-attested CrossTrace receipts | `PR-AUDIT` | `PR-GATE` |

`SL` denotes separate signed logs. `PR` denotes the dual-attested receipt representation.

### 8.1 Information-matching rule

One inferential episode is assigned to one cell. The four cells use the same episode generator, scenario definitions, block variables, fault distributions, and delivery rules; they are not four encodings of one realised frontier-agent episode. Frontier agents may produce different actions after treatment assignment, and the oracle scores what each independent episode actually produces.

For the primary H1 comparison between the two audit-only cells, agents receive the same neutral handoff API and acknowledgements. Representation encoding, retention, and audit delivery occur below that API and are not revealed to the agents. There is no gate in either cell. The implementation must test and record this masking boundary. If representation-specific information reaches an agent, that is a protocol deviation; the affected result cannot be described as a pure representation-and-retention effect.

The Sprint 4 development replay may encode one fixed neutral trace in all six primary and required-control cells to test conformance. Those branch executions are not independent trials and do not enter effect estimates.

Each handoff begins with the same neutral semantic fields:

- interaction identifier;
- sender and receiver party references;
- event type and sender sequence;
- structured scope and authority lineage/version;
- creation time and exact request hash; and
- the prior semantic interaction identifier, if any.

The two evidence representations encode those fields differently.

**Separate signed endpoint logs** produce two independently signed records:

- the sender record signs the sender's local handoff body; and
- the receiver record signs the receiver's local copy, decision, and decision time.

Neither endpoint signature binds the other endpoint's complete signed record. The parent reference names the earlier semantic handoff, not a completed bilateral object. A verifier needs matching valid sender and receiver records to establish bilateral agreement.

The development-only Sprint 2 signed-log body is fixed as:

```text
SignedEndpointRecordBody = {
    record_version: "crosstrace-evidence/0.1",
    record_type: "signed_endpoint_record",
    holder: Party,
    role: "SENDER" | "RECEIVER",
    handoff: NeutralHandoff,
    sender_record_id: null | sha256,
    decision: null | "ACCEPT" | "REJECT",
    reason_code: null | string,
    decided_at: null | timestamp
}

NeutralHandoff = {
    interaction_id,
    sender: Party,
    receiver: Party,
    event_type,
    sender_sequence,
    previous_interaction_id,
    scope,
    authority_lineage,
    authority_version,
    referenced_status_id,
    created_at,
    request_hash
}
```

The sender form requires `role=SENDER` and null decision and cross-reference fields. An `SL` receiver also has a null `sender_record_id`; a `CR` receiver requires the content identifier of the complete signed sender record. Every body has a derived `body_id`. The endpoint signature covers a fixed domain and the canonical `{algorithm, key_id, body_id}` attestation body, and the final `record_id` covers the body, body identifier, and attestation including its signature. An `SL` receiver therefore does not bind the sender record, while a `CR` receiver binds that exact signed record identifier. The same sender record bytes are valid in both representations.

The neutral generator assigns each semantic handoff an `interaction_id` and, where applicable, a `previous_interaction_id`. The separate-log representation signs those identifiers directly. In the fair P0-receipt mapping, `scope_profile` is fixed to `payment-v1`, the otherwise redundant P0 `nonce` equals `interaction_id`, and the authority fields map one-for-one into the neutral lineage, version, and referenced status. The receipt representation keeps the same `interaction_id` but replaces the semantic parent reference with `previous_receipt_id`, the content identifier of the completed encoded parent. After receipt verification, the normaliser maps an exact delivered and validated parent receipt back to its proposal's `interaction_id`. If that receipt is absent, the child remains unresolved; the implementation neither consults global evidence nor converts it into a root. This mapping is the exact parent-binding difference under study.

**Dual-attested receipts** produce one proposal signed by the sender, followed by a receiver signature that binds the same proposal hash, the complete sender attestation, the receiver decision, and decision time. A child names the content identifier of the completed parent receipt. Each endpoint retains an identical complete receipt, so either intact retained copy contains both attestations.

For delivery, each endpoint may forward or serve its retained record to the action verifier. Separate-log messages carry different endpoint records. Receipt messages from the two endpoints may carry identical complete receipt copies. Each copy is scheduled, delayed, lost, duplicated, or delivered independently. The pre-treatment manifest assigns a representation-neutral `delivery_slot_id` to each holder-to-store copy. The transport draw uses that slot, the copy index, the draw purpose, and the seed; it does not use the representation-specific message identifier or payload bytes. Reusing a slot across representations is mandatory, and changing its route or send time after assignment is a protocol deviation.

The core complete-evidence comparison uses a pre-treatment neutral delivery stratum: both endpoint-to-audit channels and the required authority-status channel are reachable by the cutoff, and no transport-corruption fault is assigned. Eligibility is fixed before representation assignment. The assigned representation is then encoded and scored; eligibility does not require the unassigned representation to validate. A separate delivery-stress analysis applies the same frozen holder-level reachability mapping to each assigned representation and measures the resulting availability difference.

For the core representation comparison:

- all three required formats are normalised to a common `ValidatedHandoff` interface that retains the verified record and message identifiers, signature-binding relation, configured source-store provenance, and how the parent was established; raw signatures remain in the source observation;
- all gate-on cells use the same policy, permit-store semantics, adapter, time-to-live, and verdict categories.

The development-only common interface contains the neutral handoff, authenticated sender/receiver flags, bilateral-agreement result, receiver decision, parent-relation result, configured delivered-holder set, source-record and message identifiers, source-delivery provenance, stable validation reasons, and representation-specific binding facts. `bilateral_agreement` is true for signed logs only when two valid endpoint records contain the same neutral handoff and the receiver record accepts it; for a receipt it is true only when the nested attestations validate and the receiver accepts. A rejected but fully authenticated handoff remains available for audit with `bilateral_agreement=false`. Partial, conflicting, or parent-unresolved candidates remain validation issues and are not emitted as policy-eligible handoffs. The shared evidence policy consumes the representation-blind `policy_view()`, not a CrossTrace-only flag or the binding metadata. The observation's origin store is a trusted simulator declaration checked against the configured store registry, not a cryptographically authenticated network identity. The transport envelope cannot determine whether an innocently named payload field semantically reveals the evaluator's ground truth, so only allow-listed representation schemas may feed these validators.

The development implementation adds a non-serialised process-local tag to validator-issued handoffs and policy views. A JSON-decoded normalised object is an audit record and must be revalidated from its source observation before policy use. This prevents accidental treatment of caller-authored all-true fields as validator output; it is not a portable signature or production trust mechanism.

Normalisation must not erase the difference being tested. The implemented evidence-admission policy checks authenticated bilateral agreement and a valid parent relation. The Sprint 3 development gate consumes only the representation-blind policy projection and additionally checks chain shape, party continuity, scope attenuation, the exact action, current delivered authority, neutral replay state, and permit-store revision. Representation-specific validators still determine whether their delivered records establish the evidence predicates. This is an engineering implementation boundary, not a result; the schemas, registry, reason codes, and mapping rules must be reviewed and frozen before outcome data.

### 8.2 Gate-off rule

In `SL-AUDIT`, `CR-AUDIT`, and `PR-AUDIT`, every presented action is submitted to the simulated adapter without a CrossTrace gate. The adapter may still fail for an operational reason. Offline detection or later reconstruction does not count as prevention.

### 8.3 Gate-on rule

In `SL-GATE`, `CR-GATE`, and `PR-GATE`, the validator and policy engine receive only the decision-time local observation. A scenario label, complete source chain, future joined view, and oracle label are prohibited inputs.

### 8.4 Required competent-baseline control

A stronger cross-referenced-log control is required. In that control, the receiver's signed endpoint record contains the content identifier of the sender's signed record, while the two records remain separate and children still link by semantic interaction identifier. `CR-AUDIT` and `CR-GATE` use the audit-only and same-policy-gate treatments respectively. They test whether the study finds evidence of a receipt-structure-specific advantage over a competent countersigned-log baseline. A null or imprecise contrast supports only "no evidence of a receipt-structure-specific advantage in this study"; it does not establish that the controls are equivalent or that cross-reference is sufficient.

### 8.5 Optional diagnostic controls

Ordinary local logs, a central append-only log, checkpoint variants, and an always-pause control may be included as secondary reference conditions. They are removed before the required cross-referenced-log control if the approved cap is tight.

### 8.6 Development-only six-cell harness

Sprint 4 fixes eight hand-written synthetic cases: complete evidence; one locally withheld leaf-receiver channel; both locally withheld leaf channels; a status delayed past the gate decision but available at the audit cutoff; a higher delivered revocation; an out-of-scope action; a replay attempt; and an authenticated conflicting leaf. The harness encodes each case into `SL`, `CR`, and `PR` and runs it in audit-only and gate modes, for 48 deterministic branch executions.

One neutral trace and holder-to-store slot manifest are assigned before representation encoding. The audit and gate branch for one representation reuse the same encoded evidence bundle. Audit-only branches do not call the gate or reserve a permit. Gate inputs contain no case label, expected result, oracle value, future delivery, global schedule, or representation-specific binding metadata.

The harness records parser and validator branches, delivered-record counts and bytes, chain state, gate reasons, permit transitions, and adapter state. These are engineering conformance fields, not estimands. The cases are not independent trials, calibration data, held-out material, evidence of superiority or equivalence, or a safety result. A reviewer release is admissible only after deterministic regeneration, schema checks, the integrated test suite, and the frozen P0 verifier pass.

## 9. Delivery and local-view model

The development-only Sprint 1 deterministic delivery layer represents each evidence message with an origin, destination, send time, scheduled delivery time, payload hash, and delivery state. It supports:

- bounded delay;
- loss or withholding;
- duplication;
- reordering;
- partitions between specified principals;
- stale authority status; and
- later merge of previously isolated views.

At decision time `t`, a verifier may observe only messages whose delivery event completed at or before `t`. The evaluator's oracle and delivery schedule are immutable scorer inputs. They are never passed to an agent or gate.

## 10. Outcomes

The common outcome vocabulary is:

- **gate verdict:** `ALLOW`, `PAUSE`, or `NOT_APPLICABLE` for an audit-only cell;
- **adapter attempted:** the action reached the simulated adapter and an attempt began;
- **side effect committed:** the simulated external state change completed;
- **unauthorised execution:** an oracle-unauthorised side effect committed;
- **false pause:** an oracle-authorised action received a `PAUSE` verdict; a later adapter failure is not a false pause;
- **legitimate task completion:** the episode's preregistered legitimate objective completed within its limits;
- **operational failure:** an allowed or ungated adapter attempt failed without committing its side effect;
- **exact path reconstruction:** the reconstructed set of ordered action paths equals the oracle's recorded path set at the fixed audit cutoff;
- **unsupported attribution:** a principal is attributed to a path step without the evidence required by that representation;
- **false attribution:** an honest principal outside the oracle path set is attributed to at least one step;
- **decision-time detection:** the relevant fault is detected using only evidence available by the decision time;
- **post-merge detection:** a fault is detected only after previously isolated evidence is combined;
- **decision latency:** time spent from completed local observation to verdict;
- **transferred bytes:** bytes delivered over simulated channels; and
- **retained bytes:** canonical bytes retained in the evidence view.

Statistical estimands and funder-specific decision thresholds are defined in `ANALYSIS_PLAN_DRAFT.md`, not in this mechanism specification.

## 11. Threats considered

The study may inject omitted or delayed evidence, altered fields, invalid signatures, broken parent links, receiver disagreement, equivocation across local views, stale or revoked authority, scope violations, local replay, crashes, and partitions.

The evidence and gate may make some of these failures attributable or locally actionable. That is an empirical question, not an assumed guarantee.

## 12. Explicit limitations

CrossTrace does not establish:

- that a signed statement is true;
- that a signer understood or honestly intended it;
- safety when all relevant parties collude;
- which clone acted when multiple processes share one key;
- global fork prevention or consensus;
- global replay protection or cumulative spending limits;
- availability when evidence is delayed or unavailable;
- correctness of the local key registry, clock, or authority issuer;
- control of uninstrumented tools or external action paths; or
- improved safety in a real deployment.

Two isolated verifiers can each receive a locally valid-looking branch and both permit action. A later merge may reveal the conflict, but that is detection after execution, not containment.

## 13. Phase boundary

### P0: frozen pre-award feasibility artifact

P0 checks deterministic encoding, signature validation, local gating, and known fork behaviour with complete supplied evidence. It is not part of any confirmatory sample.

### Development-only pre-award layers

Sprint 1 supplies deterministic delivery and bounded local observations; Sprint 2 supplies the exact `SL`, `CR`, and `PR` validators and neutral policy view; Sprint 3 supplies the common gate and neutral permit state; and Sprint 4 supplies the published six-cell integration harness. These layers do not alter the P0 baseline. Their integrated checks and deterministic release verifier passed, and their synthetic executions are permanently excluded from calibration and confirmation.

### Proposed Phase I

Phase I is the procurement-and-settlement mechanism study described in the Schmidt/joint-call application. It introduces independent trust domains, the delivery model, the corrected factorial, an excluded calibration pilot, frontier-model agents, held-out confirmation, and an external evaluator who reruns the frozen primary analysis and a representative scenario subset under a written acceptance test. Those activities begin only after an award and formal protocol registration.

### Proposed Phase II

Phase II is a subsequent independent reimplementation and external-validity study in a software-change and incident-response domain. It proceeds only if both funders approve the revised non-overlapping programme and Phase I's transfer package is frozen.

## 14. Freeze criteria

This draft is ready for formal methods review only when:

- the common observation and `ValidatedHandoff` schemas are specified;
- every primary cell is generated from one frozen neutral schema, target distribution, and holder-level delivery mapping; one-trace/four-cell encodings are confined to development-only replay fixtures;
- outcome definitions have executable tests using development-only fixtures;
- the Schmidt and LTFF statistical addenda remain separate;
- the held-out policy is documented before held-out material exists; and
- an external reviewer has had the opportunity to identify identification, missing-data, and inference failures.

The immediate next step is external methods review, followed by resolution of review comments and a frozen preregistration under the applicable award and approvals. Until then, this remains a prospective pre-award design snapshot and must not be described as preregistered. No further pre-award model, calibration, or held-out run is authorised.
