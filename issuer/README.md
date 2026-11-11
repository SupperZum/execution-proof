# GCP authority operator

`gcp-authority` is an explicit, default-off local operator entrypoint for
`GcpIssuer`. It reads one JSON request from stdin through EOF and writes one JSON
response to stdout. It does not listen on a network, terminate TLS, obtain cloud
credentials, or sign a producer qualification. A separately owned frontend must
authenticate transport and select the operator files and allowed plan bindings.

Build with `cargo build -p execution-proof-issuer --features gcp --bin gcp-authority`.
The command shape is:

```text
gcp-authority init|request \
  --config /run/authority/config.json \
  --qualification /run/authority/qualification.json \
  --signer /run/authority/authority.pk8 \
  --store /run/authority/issuer.sqlite \
  --collateral /run/authority/dcap-collateral.json \
  --capacity 32
```

These paths are operator-selected examples. `init` creates a new store and fails
if it exists. `request` only opens an existing matching store. Neither command
resets or migrates another profile. Reopening requires the same configuration,
qualification and exact collateral bytes, which participate in store identity.

The config is strict `GcpIssuerConfig` JSON with `collateral_json` omitted or
empty; collateral is loaded only from its explicit operator file. Config is
bounded to 32 KiB, qualification and PKCS#8 to 16 KiB each, collateral and stdin
to 4 MiB each, and stdout to 64 KiB. Public/operator files must be regular, single-link,
owned by the operator or root and not group/world writable. The PKCS8 file must
be operator-owned with no group/world permission. Final-component symlinks are
rejected. The authority directory, database and dependency closure also belong
to the trusted operator; use a sanitized launcher and private directory.

The process disables core dumping and dumpability before loading the key. The
temporary PKCS8 buffer is zeroized. Errors expose fixed codes only. Stdin and
stdout each have a 10-second total I/O deadline. The issuer's owned hardware
worker retains its independent fixed process/resource/deadline policy.

## Request and response

The outer request has exact version 1 and purpose
`qlad.execution-proof.gcp-authority-request.v1`. Its `request` object is tagged
by `operation`; unknown fields and operations are rejected. Signed objects use
JSON byte arrays, preserving the published original bytes.

| Operation | Fields | Public result |
| --- | --- | --- |
| `begin` | `signed_intent_json` | `challenge`, `signed_challenge_json` |
| `issue` | `challenge_id`, typed `submission` | `grant`, `signed_grant_json`, `publication` |
| `startup_plan` | `grant_id`, `aggregate_json`, `container_id`, `trust_snapshot_sha384`, `execution_audience` | `startup_plan`, `signed_plan_json` |
| `pin_policy_admission` | `grant_id`, typed `expected` GCP aggregate, `guest_nonce` | `policy_pinned` |
| `redeem_policy_aggregate` | `grant_id`, `aggregate_json`, `recorder_request_json` | `admission`, `signed_authorization_json`, `publication` |
| `status_policy_aggregate` | same fields, separately signed typed status request | `policy_status`, optional `signed_authorization_json` |

Responses have version 1, purpose
`qlad.execution-proof.gcp-authority-response.v1`, and a `result` object tagged
by `status`. On failure, `result` contains `{"status":"error","code":"..."}` and the
process exits with a nonzero status. The response never contains private keys or credentials. Request
fields cannot override operator roots, worker, configuration files or policy.
There is no request operation for initialization, reset, arbitrary message
signing, caller-provided report data, or producer qualification signing.

`startup_plan` verifies the stored L and actual KBS aggregate under configured
policy, then derives B, grant/aggregate/spec/admission-policy bindings itself.
Its task selector, relying-party audience and trust snapshot are trusted
operator choices; a frontend must pin them instead of blindly forwarding CP
values. The task selector does not establish Kubernetes Pod identity. Each
successful call generates a fresh authority execution nonce; plans are not
persisted for retry. The selected signed plan must be retained outside the
submitted evidence pack and provided to the guest once. An additional call does
not renew L or create another admission/consume permission. A plan is not a live
timestamp or an execution assertion.

Issuing a new grant requires the configured pinned hardware worker. Actual signature,
boot/profile checks and recorder PoP are required; no public software verdict
injection exists. New permissions fail on expired qualification or L. Historical
status can return the already committed authorization without renewing it.

Tests use software operator keys to exercise the real CLI and storage. They do
not prove a hardware-authorized launch or qualify a deployed producer.
