# Launch policy client

`execution-proof-client` implements the memory-only KBS launch exchange.
The v1 client uses `/kbs/launch/v1`. It
creates recorder proofs of possession, checks server context against its own
signed grant, key, initialization data and evidence, and retains exact request
bytes for explicit retries. HTTP success does not establish policy acceptance.

## Protocol integration

1. Construct `ClientProtocol` with independently configured `GrantExpectations`,
   the signed grant, an in-memory recorder key, a distinct KBS recipient key, and
   the expected initialization-data digest. Guest callers use
   `new_authority_time`; `new` additionally checks a caller-supplied trusted clock.
2. Exchange the begin and capture messages with the KBS. Supply evidence from the
   selected attester; the client does not generate a hardware quote or establish
   recorder key origin.
3. Request the resource challenge and policy decision. Verify the returned
   aggregate against independently configured roots and exact expectations.
4. For credential delivery, verify the signed delivery receipt before exposing
   its JWE bytes to a decrypt adapter. `verify_credential_response_historical`
   authenticates the accepted publication without trusting the guest clock;
   `verify_credential_response` also checks the supplied trusted current time.

Aggregate and ciphertext authentication do not create an admission capability.
The guest gate separately owns the pending attempt and one-use accepted context;
see the [workspace admission example](../README.md#use-the-admission-api).

## HTTPS transport

The optional `https` feature exposes `https::HttpsTransport`. Construct it with an
explicit HTTPS origin and select a fixed `LaunchRoute`. TLS certificate
verification remains enabled. The transport disables proxies, redirects and
automatic retries, and configures no cookie jar or ambient authorization.
Callers retain ownership of retry sequencing and attester/decrypt integration.

| Boundary | Maximum size |
| --- | --- |
| Transport request or response | 2 MiB |
| Policy response | 32 KiB |
| Decoded canonical runtime | 16 KiB |
| Evidence | 1 MiB |
| Credential response | 256 KiB |
| Decoded JWE | 128 KiB |

```sh
cargo test -p execution-proof-client --features https --locked
cargo clippy -p execution-proof-client --all-targets --features https --locked -- -D warnings
```

Run from the workspace root. The unit tests check protocol handling, bounds and
origin/route selection; they do not connect to a deployed TLS service or exercise
a hardware attester. Workspace checks and build requirements are in the
[root README](../README.md#build-and-test).

## GCP credential delivery

`gcp::GcpClientProtocol` uses `/kbs/launch/gcp/v2/` and binds requests to the
selected GCP boot profile. In the measured guest, construct
`gcp::https::GcpHttpsTransport::with_trusted_roots` with the selected CA
certificates and a fixed server address. The transport authenticates the
configured HTTPS name and permits up to 6 MiB per encoded request or response.
The decoded evidence limit remains 1 MiB.
