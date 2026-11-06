# Contributing

Development and use require authorization under the [license](LICENSE).

Keep changes focused and describe the behavior they change. Include a regression
test for a defect or a new protocol transition. Changes to signed transcripts,
wire schemas, trust inputs, feature defaults, or crate APIs need an explicit
compatibility review of their callers.

Run the [workspace checks](README.md#build-and-test) before submitting a change.
Keep `Cargo.lock` in version control; update dependencies only when the change
requires it. Unit tests belong beside their modules, and cross-crate flows belong
in the existing integration test directories. Generate test signing keys in
memory and keep credentials, issuer databases, quotes, and private deployment
configuration out of the repository.

Document the exact scope of validation. Signature and state-machine tests do not
establish hardware attestation, content custody, or observed execution. Report
security issues through the [private reporting guidance](SECURITY.md).
