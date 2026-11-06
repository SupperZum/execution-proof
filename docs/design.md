# Design and trust boundaries

## Components

`contract` defines the signed objects and bounded verification primitives.
`client`, `issuer`, and `handoff` depend on it without depending on each other in
production. The issuer's integration tests exercise the guest gate through a
development dependency on `handoff`.

Module-local tests cover codecs, signatures, binding mismatches and state
transitions. `issuer/tests/` covers persistence, authority time, concurrent
admission and guest verification. `handoff/tests/admission_lifecycle.rs` exercises
the association-only lifecycle behind `software-lab`. Software fixtures generate
ephemeral signing keys in memory; they do not provide hardware evidence.

Trust roots, full expected context, capacities, clock and issuer database paths
are constructor inputs. There is no configuration-file loader, environment-based
trust-root discovery, server process or deployment manifest in this workspace.

## Signed objects

All signing transcripts use explicit purposes, ordered length framing and SHA-384
commitments with Ed25519 signatures. Unknown or duplicate JSON fields and
unsupported schema versions are rejected. Trust roots come from the relying
party's configuration, never from the object being verified.

| Object | Meaning and binding |
| --- | --- |
| Launch grant (`LaunchGrant`, v3) | Authority authorization for an exact tenant/workload/attempt, boot/channel, selected manifest, effective launch, profile and policies, with a signed validity window. |
| Appraisal (`ProofAppraisal`, v3) | AS-signed association with the grant and evaluation commitments. Its KBS hashes are AS assertions, not an independently authenticated KBS decision. |
| Tenant intent and bootstrap (v2) | Tenant authorization, authority challenge, signed bootstrap context and recorder proof of possession used by the software issuer to create a grant. |
| Recorder session (v1) | Proof of possession over the grant digest, nonce, exact canonical runtime and exact evidence bytes. The recorder key must match the grant's channel-key digest; it is separate from the KBS recipient key. |
| Policy aggregate (v1) | KBS-signed combined AS/KBS policy statement bound to the grant, session, runtime, evidence and typed resource request. It does not assert key delivery. |
| Credential delivery (v1) | KBS-signed encrypted publication bound to the producer, grant, aggregate, request, session, recipient key, exact JWE ciphertext digest and validity window. It does not expose plaintext in the receipt. |
| Admission receipt (v1) | Authority-signed acceptance of the exact grant and policy aggregate, authority/KBS fingerprints, guest nonce, admission configuration and unchanged launch binding/window. |

Protocol purpose strings and profiles are compatibility identifiers. In
particular, the admission profile is `onb17.software-policy-admission-only.v1`;
its name does not imply content preparation or execution support.

`verify_launch_grant` authenticates the grant and checks the supplied trusted
current time without needing an appraisal. `verify_statements_at` authenticates
the grant/appraisal pair and checks time. `verify_statements` and the explicit
`*_historical` verifiers authenticate signed context without granting new
authorization. A later admission transition must check its own authority clock.
The earlier appraisal pair cannot substitute for the policy-admission aggregate.

## Issuer state and authority time

`SoftwareIssuer` signs grants and persists challenge, issue, admission and status
state in SQLite. Policy-admission constructors configure a distinct KBS proof key,
static policy scope and receipt audience. The operator pins the complete expected
aggregate and guest nonce with `pin_policy_admission`; raw requests cannot select
trusted expectations. Recorder proof of possession covers the admission context.

Receipt publication and durable consume commit atomically. An exact retry or
status read returns the original receipt without a new acceptance. Status reads
use a coherent SQLite snapshot. The policy-admission profile rejects the earlier
`redeem(VerifiedStatements)` and `status` paths before mutation, so missing
aggregate context cannot enable a fallback.

The trusted `IssuerClock` is a constructor dependency. Request JSON cannot supply
`now`. New issue/redeem operations check time after acquiring the SQLite write
lock. A signed `ValidityWindow` uses Unix seconds and the half-open interval
`not_before <= now < expires`. Grants copy the committed challenge window; a retry
does not extend it. The configured TTL is 1–3600 seconds, bounded by intent expiry.

Clock regression or unavailability denies new authorization. The earlier schema2
store retains its clock high-water even on an expected expiry denial. Historical
`Existing`, `AlreadyRedeemed` and status operations do not read the clock or issue
a new permission. The window describes authority acceptance time, not a physical
execution deadline after delivery or a paused guest.

Open a database explicitly as new or existing. Missing, corrupt, wrong-identity
or incompatible state is rejected; old schemas are not silently migrated.
Policy-admission constructors use schema3 and do not upgrade the earlier schema2
store. Retained tombstones prevent reuse within that store's continuity. SQLite
and its parent directory belong to the trusted issuer domain: database
restore/clone or loss of trusted state is outside this replay boundary. Signing
keys are supplied by the caller on creation and reopen; the database stores no
private signing keys and implements no key recovery service.

## Guest admission and handoff

`GuestAdmissionGate::new` owns the expected grant, aggregate, roots and admission
configuration, and generates a fresh 32-byte nonce. The issuer must commit a
receipt for that nonce before the same pending gate verifies the signed bundle.
The guest authenticates an authority-accepted result without needing a trusted
guest clock. First delivery can therefore complete after the authority window
ends, provided the original pending attempt remains alive.

A gate moves from Pending to Verified to Consumed. `take_accepted_attempt` transfers
`AcceptedAttemptContext` once, including if the caller drops it or preparation
later fails. The context retains authenticated launch, grant/aggregate/root,
workflow/resource and nonce bindings. It has no public constructor, `Clone`,
`Deserialize` or raw `Debug` implementation. An exact bundle retry is historical;
a changed bundle conflicts, and a new gate's nonce rejects the old receipt.

`BootTable::register` consumes this context to associate a preparation reference
with one boot and attempt. It binds a task generation and allows one consume
transition. It retains reference/grant/attempt/generation reservations and
terminal tombstones for the table lifetime, rejects conflicts and fails when
capacity is exhausted rather than evicting records. A preparation reference is
an identifier, not a protected rootfs handle. `ReleasePermit` records a unique
bookkeeping transition; the crate does not release a FIFO, open a path, mount a
filesystem or execute a task. Aborting does not revoke an already returned permit.

`software-lab` exposes the earlier association-only `register_lab` path and its
fixtures. Default runtime registration requires the one-use accepted context.
These are boot-local boundaries. Reconstructing tables or copying guest state is
not prevented by the Rust ownership model.

## Trust boundaries

The implemented software checks establish signatures, exact configured bindings,
atomic issuer state transitions and local one-use ownership. They require roots
and expectations controlled outside a hostile Kubernetes control plane. A
control-plane-supplied Pod UID is not an authoritative workload identity here.

`VerifiedStatements`, a policy aggregate, an authenticated ciphertext, an
admission context and a bookkeeping permit each have distinct meanings. None
alone proves that a guest prepared the encrypted image or executed its
application. The client does not establish hardware recorder-key origin, and the
software issuer's signed bootstrap statements do not establish an attested boot.

`supported_proof_profiles()` is empty. `prepare_launch` fails before launch side
effects and has the uninhabited success type `Infallible`.
`GuestAdmissionGate::validate_for_preparation` may authenticate a bundle but always
returns `ContentPreparationUnavailable`. No public flag or caller boolean opens a
positive preparation path.

A complete execution proof still requires qualified boot/key-origin and measured
configuration, deployed authority/AS/KBS authentication, fresh encrypted-content
preparation with rootfs custody, authenticated content-to-runtime handoff,
protected record capture with producer isolation, and independent verification.
Those capabilities are outside this workspace's current preparation API. Local
signature and lifecycle tests do not qualify cloud KMS use, hardware quotes,
rollback/clone resistance or a deployed execution proof chain.
