# Security policy

## Prototype status

CrossTrace protocol sketch is research demonstration code. It is not supported for production use, real payments, custody, access control, or any other consequential authorisation decision. It has not received an independent security audit.

Do not place production credentials, private keys, personal data, payment details, or confidential traces in this repository or its examples. The included identities and actions must remain synthetic.

## Reporting a vulnerability

Use GitHub's private [Report a vulnerability](https://github.com/K9-glitch3/crosstrace-protocol-sketch/security/advisories/new) form. Do not include live credentials or personal data, and do not publish exploit details in a public issue.

A useful report includes:

- the affected commit and file;
- the expected and observed decision;
- a minimal synthetic reproducer;
- the security impact within this prototype's stated threat model;
- any assumptions required for exploitation.

No bug bounty or response-time commitment is offered.

## Supported versions

Only the latest tagged pre-release and `main` are reviewed on a best-effort basis. This prototype has no production-support or service-level commitment.

## Safe testing

- Use only synthetic keys, identities, receipts, and payment values.
- Do not connect the demo to a wallet, bank, exchange, payment processor, or live agent tool.
- Do not test against systems or accounts without explicit authorisation.
- Treat an `ALLOW` result as a local protocol result, not permission to execute a real action.
- Review [THREAT_MODEL.md](THREAT_MODEL.md) before interpreting any result.

## Disclosure and fixes

Security fixes should include a regression test and a clear explanation of which local invariant failed. Claims should remain bounded: a corrected test does not establish production security or an empirical safety result.
