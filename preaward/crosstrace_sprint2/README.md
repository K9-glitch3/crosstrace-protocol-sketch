# Sprint 2 evidence normalisation

This package is a development-only implementation of the evidence boundary described in the prospective CrossTrace protocol. It remains outside `src/` so the frozen P0 source identity is unchanged. Its fixtures are engineering conformance checks, not calibration data, trials, or evidence that one representation is safer.

Sprint 2 fixes one representation-neutral `NeutralHandoff` and three exact encodings:

- `SL`: independently signed sender and receiver endpoint records. Both valid, matching records must be delivered.
- `CR`: the same sender record used by `SL`, plus a receiver record that signs the complete sender record identifier. Both records must be delivered.
- `PR`: the P0 dual-attested receipt, constrained to a fair `payment-v1` mapping. Either intact endpoint-retained receipt copy can carry both attestations.

The validators accept only Sprint 1 `LocalObservation` or `AuditObservation` objects. Within this trusted simulator boundary, an explicit store registry authorises which principal and endpoint role a declared origin store may represent; it does not cryptographically authenticate transport origin. The key registry is applied with the same `receipt` role in every representation.

Valid evidence is normalised to `ValidatedHandoff`. This object preserves source record identifiers, every independent contributing message, signed endpoint identity, configured origin-store provenance, the encoded parent reference, and representation-specific binding facts. The source observation retains the raw signed records; the normalised object records the identifiers and relations that validation established rather than embedding every signature again. Its `policy_view()` deliberately removes the representation and binding metadata. The small common evidence policy consumes only that representation-blind projection.

`ValidatedHandoff` and its `PolicyView` carry a non-serialised, process-local validator tag. JSON round trips remain available for audit, but deserialised or caller-constructed objects cannot be passed to policy through the public interface; their source observation must be validated again. This is an honest-caller, in-process misuse barrier, not a portable verifier signature or a production authorisation credential. Arbitrary Python code inside the process is within the trust boundary and can inspect private module state.

The normaliser never chooses a convenient record from conflicting authenticated candidates. Missing endpoints, mismatched bodies, a wrong cross-reference, an unavailable exact parent, invalid signatures, unknown stores or keys, future decisions, and equivocation produce stable issues and no policy-eligible handoff. A signed rejection is retained as an authenticated handoff but cannot establish bilateral agreement.

Receipt children resolve `previous_receipt_id` only through a delivered, validated parent receipt. They are never converted into false roots and the validator does not consult a global semantic oracle. Endpoint-log children encode the semantic parent interaction identifier directly.

The exact wire objects are specified by:

- `schema/neutral-handoff.schema.json`;
- `schema/signed-endpoint-record.schema.json`;
- `schema/cross-referenced-record.schema.json`; and
- `schema/validated-handoff.schema.json`.

`PR` retains the existing `schema/handoff-receipt.schema.json` wire object. Its fair comparison profile is the executable Sprint 2 constraint that the signed P0 nonce equals `interaction_id`, together with the delivered-parent receipt mapping described above.

This package does not select authority status, check scope narrowing or action compliance, reconstruct complete paths, issue permits, call frontier models, or generate research outcomes. The current Sprint 1 permit schema still binds `leaf_receipt_id`; a later versioned baseline must migrate replay identity to `neutral_handoff_id` before a genuinely representation-common gate can be implemented.
