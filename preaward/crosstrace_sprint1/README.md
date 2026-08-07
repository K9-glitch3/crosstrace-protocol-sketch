# Sprint 1 deterministic delivery layer

This package implements the pre-award decision-time evidence-delivery boundary using development-only fixtures. It is deliberately outside `src/` because the frozen P0 verifier binds every Python file under `src/`; promoting this code there would create a new source baseline.

The layer provides:

- content-bound evidence messages addressed to explicit stores;
- a representation-neutral `delivery_slot_id` for the pre-treatment holder/channel map;
- hash-derived, input-order-independent delivery schedules keyed by slot, copy, and draw purpose;
- independent loss and duplication per transmission;
- directional partitions that buffer until a fixed healing time;
- explicit permanent withholding that fixture overrides cannot defeat;
- immutable local and audit-inbox projections, including an explicitly named local permit store;
- canonical schedule and observation serialization; and
- strict executable decoders that verify payload bytes, sizes, hashes, derived IDs, timestamps, and schedule completeness.

A local projection contains only messages delivered to its own store by its cutoff. The transport envelope adds no future delivery, missing-message identifier, seed, partition, disposition, fault label, scenario label, or oracle field. Independently retained copies remain distinct messages even when their payload bytes match.

The permit snapshot mirrors the current P0 store fields needed for local replay and conflict checks: leaf receipt, replay scope, request hash, action nonce, tool, lifecycle, times, and the retained `(observation_kind, observation_key) -> receipt_id` bindings. Its store identifier must equal the `permit_store_id` declared by the local observation. A later verifier registry must still bind each verifier to its authorised evidence and permit-store identifiers.

The JSON Schemas enforce the serialized structure. The Python `from_dict()` decoders enforce relations that JSON Schema cannot compute, including byte length, SHA-256 bindings, derived identifiers, cutoff consistency, and recompilation of every schedule transmission.

The generic payload constructor rejects obvious evaluator-metadata field names as a development safeguard. It cannot determine whether an innocently named field semantically leaks ground truth. Exact representation schemas and validators must therefore use allow-listed fields before any observation can be treated as a gate input; this transport package is not an information-flow security boundary.

For a fair representation comparison, the episode manifest must assign a neutral delivery slot before encoding the evidence format and reuse that slot across conditions. Changing a slot, route, or send time after treatment assignment is a protocol deviation.

Delay and audit offsets are bounded to 31,536,000 seconds in this development profile so malformed fixtures fail with a domain error instead of overflowing platform datetime arithmetic.

This layer does not validate receipts or logs, resolve competing authority statuses, issue permits, reconstruct paths, or produce research outcomes. Those are later interfaces. Development fixtures in `tests/test_delivery.py` are permanently excluded from calibration and confirmation.
