# Launch policy client

`execution-proof-client` implements the memory-only `/kbs/launch/v1` exchange. It
creates recorder proofs of possession, checks server context against its own
signed grant, key, initialization data and evidence, and retains exact request
bytes for explicit retries. HTTP success does not establish policy acceptance.

## Protocol integration

1. Construct `ClientProtocol` with independently configured `GrantExpectations`,
   the signed grant, an in-memory recorder key, a distinct KBS recipient key and
   the expected initialization-data digest. Guest callers use
   `new_authority_time`; `new` additionally checks a caller-supplied trusted clock.
2. Exchange the begin and capture messages with the KBS. Supply exact evidence
   from the selected attester. The client does not generate a hardware quote or
   establish recorder key origin.
3. Request the resource challenge and policy decision. Verify the returned
   aggregate against independently configured roots and exact expectations.
4. Use `credential_request` to authenticate a delivery request for that aggregate.
   Verify the signed delivery receipt before exposing its JWE bytes to a decrypt
   adapter. `verify_credential_response_historical` authenticates the accepted
   publication without trusting the guest clock; `verify_credential_response`
   also checks the supplied trusted current time.

The delivery receipt binds the producer, grant, aggregate, resource request,
session, recipient key, exact ciphertext digest and signed window. Historical
verification authenticates that publication without creating a new authorization.
Aggregate and ciphertext authentication do not create an admission capability.
The guest gate separately owns pending continuity and one-use accepted context;
see the [workspace admission example](../README.md#admission-flow).

## HTTPS transport

The optional `https` feature exposes `https::HttpsTransport`. Construct it with an
explicit HTTPS origin and select a fixed `LaunchRoute`. TLS certificate
verification remains enabled. The transport disables proxies, redirects and
automatic retries, and configures no cookie jar or ambient authorization.
Connect timeout is 5 seconds; the overall request timeout is 10 seconds. Callers
own retry sequencing and attester/decrypt integration.

| Boundary | Maximum size |
| --- | --- |
| Transport request or response | 2 MiB |
| Policy response | 32 KiB |
| Decoded canonical runtime | 16 KiB |
| Evidence | 1 MiB |
| Credential response | 256 KiB |
| Decoded JWE | 128 KiB |

Contract wire objects are bounded at 16 KiB each. The outer response limits allow
for their encoding and associated payloads; a successful transport read still
requires protocol validation.

Run from the workspace root:

```sh
cargo test -p execution-proof-client --features https --locked
cargo clippy -p execution-proof-client --all-targets --features https --locked -- -D warnings
```

The unit tests check protocol handling, bounds and origin/route selection. They
do not connect to a deployed TLS service or exercise a hardware attester.
Workspace checks and native build requirements are in the
[root README](../README.md#build-and-test).
