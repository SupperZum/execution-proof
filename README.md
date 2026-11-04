# Execution Proof Prototype

Rust libraries for signed workload launch authorization, policy admission, and
boot-local handoff bookkeeping in an encrypted-image execution proof workflow.
They authenticate software statements and constrain state transitions between a
launch authority, a Key Broker Service (KBS) policy producer, and a guest runtime.
They do not produce evidence that an application executed.

Content preparation is unavailable: `prepare_launch` and
`GuestAdmissionGate::validate_for_preparation` always reject it. The workspace
contains libraries, with no issuer daemon, command-line program, or deployment
configuration.

## Workspace

| Crate | Responsibility |
| --- | --- |
| [`execution-proof-contract`](contract/) | Bounded signed objects, domain-separated transcripts, and verification of launch, bootstrap, session, policy, credential, and admission statements. |
| [`execution-proof-handoff`](handoff/) | Guest-owned bundle verification and boot-local preparation-reference/task bookkeeping. |
| [`execution-proof-issuer`](issuer/) | Software authority with signed intent/bootstrap verification, grant issuance, durable SQLite state, and policy admission. |
| [`execution-proof-client`](client/README.md) | Memory-only KBS launch protocol client and optional HTTPS transport. |

The client, issuer, and handoff crates depend on `contract`. All path dependencies
are inside this workspace. Building these libraries does not require the guest
runtime or KBS source trees. Runtime and attester adapters belong in those
components.

## Build and test

The manifests declare Rust 1.90 and edition 2021. Native dependencies `ring` and
bundled SQLite require a C compiler and the platform's linker/build tools. A
system SQLite installation is not required. Formatting and linting use the
`rustfmt` and `clippy` toolchain components.

Run from the repository root:

```sh
cargo build --workspace --locked
cargo test --workspace --locked
cargo test -p execution-proof-client --features https --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo clippy -p execution-proof-client --all-targets --features https --locked -- -D warnings
cargo fmt --all --check
cargo doc --workspace --features execution-proof-client/https --no-deps --locked
```

Dependencies are resolved by the committed `Cargo.lock`. Add `--offline` when
the locked dependencies are already cached. Tests use ephemeral in-memory signing
keys and temporary issuer databases; they need no VM, cloud account, root
privileges, external service, or credentials. They exercise software contracts,
not a deployed attestation or execution proof chain. These commands alone do not
establish a supported platform or minimum-toolchain matrix.

API documentation is generated under `target/doc/`. See the
[client guide](client/README.md) for protocol sequencing, transport limits, and
feature-specific checks. `https` is optional and disabled by default. All packages
have `publish = false`.

## Signed objects

Trust roots and exact expected identities, policies, and inputs come from the
relying party's configuration, never from the submitted bundle. Signing uses
Ed25519, explicit purposes, ordered length framing, and SHA-384 commitments.
Unsupported schemas and malformed, unknown, or duplicate fields are rejected.

| Object | What authentication establishes |
| --- | --- |
| Launch grant (`LaunchGrant`, v3) | Authority authorization bound to tenant/workload/attempt, boot/channel, selected manifest, effective launch, profile, policies, bootstrap context, and a signed validity window. |
| Appraisal (`ProofAppraisal`, v3) | An AS-signed association with the grant and evaluation commitments. KBS hashes in this object are AS assertions, not independently authenticated KBS decisions. |
| Tenant intent and bootstrap (v2) | Signed tenant scope, authority challenge, bootstrap context, and recorder proof of possession used by the software issuer. They do not establish an attested boot or hardware key origin. |
| Recorder session (v1) | Possession of the grant's recorder key bound to the session nonce and exact canonical runtime/evidence bytes. The KBS recipient key remains separate. |
| Policy aggregate (v1) | A KBS producer's combined AS/KBS policy statement bound to grant/session/runtime/evidence and the typed resource request. This profile trusts that producer for both evaluations, without an independent AS signature or key-delivery claim. |
| Credential delivery (v1) | KBS publication bound to the producer, grant, aggregate, request, session, recipient key, exact JWE ciphertext digest, and validity window. The receipt contains no plaintext or plaintext hash. |
| Admission receipt (v1) | Authority acceptance of the exact grant/aggregate, authority/KBS key fingerprints, guest nonce, admission configuration, and unchanged launch binding/window. |

`verify_launch_grant` authenticates a grant and checks a supplied trusted current
time without requiring an appraisal. `verify_statements_at` checks the signed
grant/appraisal pair and time. `verify_statements` and
`verify_launch_grant_historical` support historical authentication without a new
authorization. `VerifiedStatements` proves signatures and configured bindings;
it does not become a policy aggregate, admission capability, or execution proof.

## Issuer state and time

`SoftwareIssuer` verifies signed tenant intent, signed bootstrap statements, and
recorder proof of possession before signing a grant. Open its SQLite store
explicitly as new or existing. Missing, corrupt, wrong-identity, or incompatible
state is rejected. Signing keys are supplied separately by the caller on creation
and reopen; the database stores no private signing keys and provides no key
recovery service.

Policy-admission constructors use schema3 with a constructor-owned KBS root and
static policy scope. The operator must pin the complete expected aggregate and
guest nonce with `pin_policy_admission` before redemption. Request fields cannot
select these expectations. Recorder proof of possession covers the admission
context. Receipt publication and the consume slot shared with grant/appraisal
redemption commit atomically. For an already published policy receipt, exact
retry/status returns its original bytes without new authorization. Schema2
constructors retain their separate store identity; they do not migrate into
schema3.

`IssuerClock` is a trusted constructor dependency; requests cannot supply `now`.
New issue/redeem operations check time after acquiring the SQLite write lock.
`ValidityWindow` uses Unix seconds and `not_before <= now < expires`. The issuer
bounds the configured TTL to 1–3600 seconds and tenant-intent expiry. Grants copy
the committed challenge window; retries do not extend it. Clock regression or
unavailability rejects new authorization. The schema2 store retains clock
high-water even on expected expiry denial. Historical `Existing`,
`AlreadyRedeemed`, and status retrieval do not read the clock or issue another
permission.

The window describes authorization acceptance time, not a physical execution
deadline after delivery or a paused guest. SQLite and its parent directory belong
to the trusted issuer domain. Retained tombstones protect continuity within that
store; restoring or cloning a database, or losing trusted state, lies outside
this replay boundary.

## Guest verification and handoff

Construct `GuestAdmissionGate::new(config, clock)` with trusted
`GuestAdmissionConfig` and an injected `GuestClock`. The gate creates a fresh
32-byte nonce. Send `gate.challenge_nonce()` to the trusted issuer for admission
pinning before it issues the receipt, and retain the same gate for the attempt.
The first bundle verification checks the signed grant and receipt against the
injected trusted guest clock. An ordinary guest wall clock controlled by the host
is not a substitute for that dependency.

```rust
use execution_proof_handoff::admission::{
    AdmissionCheck, GuestAdmissionError, GuestAdmissionGate,
};

fn verify_admission(
    gate: &GuestAdmissionGate,
    signed_grant: &[u8],
    signed_aggregate: &[u8],
    signed_receipt: &[u8],
) -> Result<AdmissionCheck, GuestAdmissionError> {
    gate.verify_bundle(signed_grant, signed_aggregate, signed_receipt)
}
```

`FirstVerified` and `Historical` are metadata, not preparation permissions. The
gate retains exact raw bytes; an exact retry is historical, skips a new time
check, and cannot authorize preparation. A changed bundle conflicts. Its clock
high-water is boot-local and does not provide rollback or clone resistance.
`validate_for_preparation` always returns `ContentPreparationUnavailable` after
successful verification; it creates no preparation reference or execution permit.

`BootTable` separately registers a caller-supplied `PreparationReference` against
`VerifiedStatements`, binds a task generation, and returns one `ReleasePermit`
from a successful consume transition. A reference is an identifier and context
commitment, not a protected rootfs handle. Status retrieval and repeated consume
cannot produce another permit. The table retains grant/attempt/generation
reservations and terminal tombstones, rejecting conflicts and capacity exhaustion
rather than evicting records. Its trusted owner must retain it for the enrolled
boot's lifetime; a restart does not provide replay protection.

The table does not open paths, mount filesystems, pull/decrypt images, release a
FIFO, or execute tasks. Aborting changes bookkeeping state without revoking an
already returned permit or stopping a task. See the
[handoff integration tests](handoff/tests/admission_lifecycle.rs) and
[issuer admission tests](issuer/tests/policy_admission.rs) for software fixtures.

## Trust boundaries

The libraries require independently configured roots and expectations outside a
hostile Kubernetes control plane. A control-plane-supplied Pod UID is not an
authoritative workload identity here. Signature verification, policy aggregates,
credential publication, and bookkeeping permits each establish distinct facts;
none establishes protected encrypted-content custody or observed execution.

A complete execution proof requires qualified boot/key-origin and measured
configuration, authenticated authority/AS/KBS integration, fresh encrypted-content
preparation with rootfs custody, authenticated content-to-runtime handoff,
protected record capture with producer isolation, and independent verification.
The guest verification path also requires a qualified trusted clock. The current
software signatures and state-machine tests do not establish those capabilities,
real Cloud KMS use, hardware quotes, rollback/clone resistance, or a deployed
execution proof chain. Until the required adapters and trust boundaries are
qualified, the preparation entrypoints remain closed.
