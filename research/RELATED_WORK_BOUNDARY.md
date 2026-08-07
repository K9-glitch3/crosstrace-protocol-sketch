# CrossTrace related-work and novelty boundary

**Status:** Pre-award scoping note; not a systematic review
**Recorded:** 6 August 2026

## Claim boundary

CrossTrace does not claim to invent digital signatures, countersignatures, provenance, trace propagation, delegated authority, append-only transparency logs, or distributed accountability. The proposed contribution is narrower: a controlled systems study of whether evidence representation, independent retention, partial delivery, linked authority status, and a local action gate change specified safety and utility outcomes in a multi-principal agent sandbox.

The study may find no evidence that the receipt format improves on a competent countersigned-log baseline. That is an informative result, not a failure to report, but it is not proof that the two designs are equivalent.

## Closest established mechanisms

| Area and primary source | What the source establishes | Boundary for this study |
|---|---|---|
| [COSE Countersignatures, RFC 9338](https://www.rfc-editor.org/rfc/rfc9338.html) | A standard construction for a second party to sign data associated with an existing protected object. | The receiver's signature over the sender's attestation is an application of established countersignature structure, not a new primitive. CrossTrace must be compared with cross-referenced signed logs. |
| [W3C PROV-O](https://www.w3.org/TR/prov-o/) | A standard ontology for representing provenance involving entities, activities, and agents. | CrossTrace can map released records to established provenance concepts. It does not claim a new general provenance vocabulary. |
| [OpenTelemetry context propagation](https://opentelemetry.io/docs/concepts/context-propagation/) | A deployed observability mechanism for carrying trace context across service boundaries. | Trace correlation is a relevant baseline for reconstructing distributed activity. The study separately tests authenticated bilateral agreement, authority status, partial retention, and pre-action policy. |
| [Macaroons](https://www.ndss-symposium.org/ndss2014/ndss-2014-programme/macaroons-cookies-contextual-caveats-decentralized-authorization-cloud/) | Decentralised authorisation credentials with contextual caveats that can attenuate how authority is exercised. | CrossTrace does not claim to invent scoped delegation. Its receipts record a handoff and feed a local policy; the experiment must distinguish evidence effects from ordinary credential enforcement. |
| [Certificate Transparency v2, RFC 9162](https://www.rfc-editor.org/rfc/rfc9162.html) | Publicly auditable append-only logging with inclusion and consistency mechanisms for certificate activity. | A central transparency log is a relevant architectural comparator. CrossTrace does not claim to replace transparency systems or provide global fork prevention. |
| [in-toto](https://www.usenix.org/conference/usenixsecurity19/presentation/torres-arias) | Cryptographically verifiable evidence about authorised steps in a software supply chain involving independent actors. | It is a close practical precedent for chained, actor-signed evidence. The proposed study uses dynamic agent handoffs and a simulated action boundary; it does not claim that this setting is automatically novel or that in-toto is inadequate. |
| [PeerReview](https://doi.org/10.1145/1294261.1294279) | A distributed-systems accountability design using signed records and witnesses to detect attributable faults. | CrossTrace does not claim to originate witnessed accountability. The empirical question is whether the declared representations and local gate alter outcomes under the study's agent, delivery, and authority model. |

## Exact empirical question retained

The study asks whether, under one frozen target distribution and explicit local-view delivery model:

1. dual-attested receipts change exact path-set reconstruction relative to separate signed logs;
2. any apparent receipt benefit survives a stronger cross-referenced-log control;
3. the same local gate policy changes unauthorised committed side effects within each evidence representation;
4. safety changes occur without exceeding the registered false-attribution, false-alarm, false-pause, and task-completion guardrails; and
5. any effect remains after reporting evidence availability, latency, storage, verification, model, and compute costs.

The required competent-baseline cells are `CR-AUDIT` and `CR-GATE`. If the study does not find a clear `PR` advantage over `CR`, it reports no evidence of a receipt-structure-specific advantage in the tested setting. It does not call the mechanisms equivalent or cross-reference sufficient unless a separate equivalence or non-inferiority test is powered and registered. If no gate cell improves safety within its utility guardrails, the study does not recommend deployment.

## Review still required

This note is a bounded starting comparison, not evidence that the research question is absent from the literature. Before preregistration, a named methods or security reviewer must check the search scope, add material omitted work, and approve or narrow every novelty statement. The final report must cite contrary and null evidence as well as supporting work.
