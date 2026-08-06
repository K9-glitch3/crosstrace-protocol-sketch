# CrossTrace scripted systems pilot v0.1

> **Claim boundary:** This is a deterministic, credential-free protocol
> conformance pilot over synthetic fixtures. It uses no LLM or frontier-agent
> traffic and is not evidence that CrossTrace improves real-world AI safety.

## Design

Five evidence conditions were exercised against six declared scenarios and ten
deterministic fixture variants per cell (300 executions). The variants change
identifiers, times, resources, and amounts; they are not independent statistical
trials. The hidden oracle was used only by
the scorer; it was not passed to the evidence conditions or ActionGate.

## Aggregate scripted outcomes

| Condition | Exact path | Unauthorised simulated action | Attempt prevented | Legitimate completion | False pause | Unsupported attributions | Mean retained bytes |
|---|---:|---:|---:|---:|---:|---:|---:|
| ordinary local logs | 100.0% | 100.0% | 0.0% | 100.0% | 0.0% | 190 | 6002.8 |
| central append only log | 100.0% | 100.0% | 0.0% | 100.0% | 0.0% | 190 | 3416.7 |
| isolated signed logs | 100.0% | 100.0% | 0.0% | 100.0% | 0.0% | 10 | 7317.7 |
| paired receipts | 100.0% | 100.0% | 0.0% | 100.0% | 0.0% | 0 | 14423.0 |
| paired receipts with gate | 100.0% | 25.0% | 75.0% | 100.0% | 0.0% | 0 | 14423.0 |

Every rate is stored as an integer count and denominator in `summary.json`.
Action denominators are attempt-level because replay and equivocation contain
two attempts. Retained bytes are the serialized joined evidence, including
each visible endpoint copy; they are not network-transfer or runtime costs.

## What this run can establish

- the declared fixtures execute reproducibly without credentials or network access;
- controls are independently encoded from neutral events; only the paired
  conditions retain CrossTrace receipt IDs and jointly attested proposal bytes;
- the current verifier accepts valid evidence and pauses on the scripted
  revocation, limit, and local-replay cases when supplied a complete receipt
  chain and the declared current signed status;
- two isolated stores can both authorise conflicting leaves, while a merged
  local view detects the conflict after observation; and
- every episode carries the hash of the same per-case oracle across conditions.

## What this run cannot establish

It does not model evidence delivery, status propagation or decision-time
partial observability. It does not estimate real-agent failure rates, provide
independent trials, solve global fork prevention, model collusion or key
compromise, establish external validity, or support a
claim of improved safety. Those are proposed research questions, not results.

Run `python -m crosstrace_sketch.pilot.verify <result-directory>` to
recompute the summary and verify the release checksums.
