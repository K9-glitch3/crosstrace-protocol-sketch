# Five-minute reviewer reproduction

## Purpose

This release is a small, offline check of the current CrossTrace engineering
path. Eight hand-written synthetic fixtures are replayed through six cells:

| Evidence form | Audit only | Common gate |
|---|---|---|
| Separate signed endpoint logs | `SL-AUDIT` | `SL-GATE` |
| Cross-referenced endpoint logs | `CR-AUDIT` | `CR-GATE` |
| Dual-attested paired receipts | `PR-AUDIT` | `PR-GATE` |

For each case, its neutral trace and holder-to-store delivery slots are fixed
before the three evidence forms are encoded. Within each evidence form, one
representation bundle is reused by its audit and gate cells. The comparison
therefore checks the implementation boundary between recording evidence and
enforcing a local decision; it is not an experiment on agent behaviour.

## Run it

From the repository root, using Python 3.11 or newer:

```shell
python -m pip install -e ".[test]"
python -m preaward.crosstrace_sprint4.verify preaward/results/six-cell-v0.1
```

The verifier checks the release manifest and checksums, validates the published
schemas, recomputes the summaries and invariance statements, and regenerates
the deterministic files in a temporary directory. A successful exit means the
published release matches the implementation in that checkout.

To make a separate copy and verify it:

```shell
python -m preaward.crosstrace_sprint4.runner --output-dir .reviewer-reproduction
python -m preaward.crosstrace_sprint4.verify .reviewer-reproduction
```

Installing dependencies may contact a package index. The harness itself makes
no model, runtime network, wallet, or payment-service calls. Its adapter records
only synthetic local state changes.

## What the fixtures cover

The eight cases are: complete evidence; one locally withheld leaf endpoint
copy; both locally withheld leaf copies; an authority status delayed from the
decision-time local view but later visible to the audit view; a higher signed
revocation; an out-of-scope action; a repeated local attempt; and an
authenticated conflicting leaf.

The release shows whether those fixed cases pass through parsing, delivery,
representation-specific validation, strict chain assembly, authority and scope
checks, neutral permit handling, and the simulated adapter as declared. It also
checks that audit and gate cells reuse the same representation bundle and that
the three encodings share the same neutral semantics and payload-free
holder/slot delivery projection.

An audit cell does not call the gate or reserve a permit. It presents the action
to the synthetic adapter and retains evidence for later inspection. A gate cell
uses only its decision-time local observation. Missing, contradictory, stale,
revoked, out-of-scope, or replayed evidence can therefore produce `PAUSE` and no
permit.

The one-copy case exposes a structural difference, not a result about safety.
An intact paired-receipt copy contains both endpoint attestations. Separate and
cross-referenced logs still require the distinct sender and receiver records;
the cross-reference does not contain the missing record. Whether that difference
matters under a real delivery distribution remains untested.

## Independent reproduction checklist

1. Use a clean checkout of the published reviewer release and Python 3.11 or
   newer.
2. Install the declared test dependencies and run the release verifier above.
3. Confirm that the verifier identifies six cells and eight development
   fixtures, reports no invariant violation, and reports zero model and runtime
   network calls.
4. Inspect the resolved manifest, neutral fixtures, decision-time observations,
   execution traces, invariance record, summary, environment record, report,
   and checksum list under `preaward/results/six-cell-v0.1`.
5. Generate a second result directory and verify it. Deterministic core files
   should match the published release; platform details in the environment file
   may differ.
6. For a deeper code check, run:

   ```shell
   python -m pytest -q
   python -m crosstrace_sketch.pilot.verify pilot/results/pilot-v0.1
   ```

7. Record the checkout identity, operating system, Python version, verifier
   output, and any deviation. Do not interpret a successful reproduction as an
   independent safety result.

## Trust and known limits

The harness trusts its synthetic keys, local key and store registries, clock,
authority-status source, permit store, and instrumented adapter. A configured
store mapping is simulator provenance, not cryptographic proof of network
origin. Process-local validator tags prevent ordinary API misuse; they are not
portable authorisation credentials or protection against arbitrary code in the
same process.

Signatures show that particular bytes were signed. They do not establish that a
statement is true or that a signer is honest. The implementation does not solve
collusion, shared or stolen keys, indistinguishable clones, isolated-view forks,
global replay, cumulative budgets, unavailable evidence, or actions taken
through an uninstrumented route. The audit inbox is another bounded delivered
view, not a global truth service.

## Stop rule

This is the end of pre-award mechanism-development work; it does not generate
research outcomes. These fixtures remain development-only and must not enter
calibration or confirmation. Frontier-model episodes, calibration, held-out
material, or treatment-effect analysis should begin only after funding, a
frozen reviewed protocol, preregistration, and the required operational
approvals.
