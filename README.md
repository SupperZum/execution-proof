# Execution Proof Prototype

Rust libraries for signed workload launch authorization, policy admission, and
one-use guest context in an encrypted-image execution proof workflow. They connect
an independent launch authority, a Key Broker Service (KBS) policy producer, and a
guest runtime through explicit signatures and context bindings.

The workspace authenticates software statements and enforces local state
transitions. It does not produce evidence that an application executed.
`prepare_launch` and `GuestAdmissionGate::validate_for_preparation` reject content
preparation until the required content and runtime adapters are available.

## Workspace

| Crate | Responsibility |
| --- | --- |
| [`execution-proof-contract`](contract/) | Bounded wire types, domain-separated signing transcripts, and verification of launch, policy, credential, and admission statements. |
| [`execution-proof-handoff`](handoff/) | Guest-owned admission, one-use accepted context, and boot-local reference/task bookkeeping. |
| [`execution-proof-issuer`](issuer/) | Software authority with signed bootstrap/grant issuance, durable SQLite state, and atomic policy admission. This is a library, not a network service. |
| [`execution-proof-client`](client/README.md) | Memory-only KBS launch protocol client and optional HTTPS transport. |

The client, issuer, and handoff crates depend on `contract`. The issuer's
integration tests also use `handoff`. All path dependencies are inside this
workspace; a checkout can build without the guest runtime or KBS source trees.
Runtime integrations belong in those components and must preserve the
[trust boundaries](docs/design.md#trust-boundaries).

## Build and test

Use Rust 1.90 or newer with Cargo. Building `ring` and bundled SQLite requires a C
compiler and the platform's native linker/build tools. SQLite is built from the
locked dependency; a system SQLite installation is not required. Formatting and
linting use the `rustfmt` and `clippy` toolchain components.

Run from the repository root:

```sh
cargo build --workspace --locked
cargo test --workspace --locked
cargo test --workspace --all-features --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo fmt --all --check
cargo doc --workspace --all-features --no-deps --locked
```

Dependencies are resolved by the committed `Cargo.lock`. Add `--offline` to Cargo
build, test, lint, or documentation commands when the locked dependencies are
already cached. These tests need no VM, cloud account, root privileges, external
service, or credentials. They exercise software contracts, not a deployed
attestation or execution proof chain.

Default features are empty. `execution-proof-client/https` enables the HTTPS
transport; `execution-proof-handoff/software-lab` exposes association-only lab
constructors and their lifecycle fixtures. `--all-features` tests both. The
[CI workflow](.github/workflows/ci.yml) checks default and all-feature builds on
stable Rust and checks all targets with all features on Rust 1.90.0, on Linux.

## Use the admission API

These crates expose libraries; there is no command-line program or issuer daemon.
Configure public keys and expected identities/policies from a trusted source
outside the request. The [design document](docs/design.md) describes the signed
objects and authority-time model, and the [client guide](client/README.md)
describes the KBS exchange.

For a guest attempt, construct a `GuestAdmissionGate` with a trusted
`GuestAdmissionConfig` containing the expected grant and policy aggregate. Send
`gate.challenge_nonce()` to the trusted issuer for admission pinning before it
issues the receipt. Retain that same gate for the lifetime of the pending attempt.
Once the signed grant, aggregate, and receipt arrive, authenticate the bundle and
transfer its context:

```rust
use execution_proof_handoff::admission::{
    AcceptedAttemptContext, GuestAdmissionError, GuestAdmissionGate,
};

fn accept_authorization(
    gate: &GuestAdmissionGate,
    signed_grant: &[u8],
    signed_aggregate: &[u8],
    signed_receipt: &[u8],
) -> Result<AcceptedAttemptContext, GuestAdmissionError> {
    gate.verify_bundle(signed_grant, signed_aggregate, signed_receipt)?;
    gate.take_accepted_attempt()
}
```

`take_accepted_attempt` succeeds once. Retrying the exact bundle authenticates
historical metadata and cannot replenish the context. `BootTable::register`
consumes the context for reference bookkeeping; neither operation authorizes
content preparation or container start. See the
[issuer-to-guest integration tests](issuer/tests/policy_admission.rs) for complete
software fixtures, including duplicate, expiry, and conflict cases.

## Documentation and development

- [Design and trust boundaries](docs/design.md)
- [Client protocol and HTTPS transport](client/README.md)
- [Contribution guidelines](CONTRIBUTING.md)
- [Security reporting](SECURITY.md)

API documentation is generated by `cargo doc`; open
`target/doc/execution_proof_handoff/index.html` after the documentation command
above. The packages have `publish = false` and no release or deployment pipeline.

## License

Copyright (c) 2026 QLAD, Inc. All rights reserved. This software is proprietary;
use requires separate authorization. See [LICENSE](LICENSE).
