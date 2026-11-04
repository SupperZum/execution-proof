# Launch policy client

`execution-proof-client` implements the memory-only `/kbs/launch/v1` exchange. It
creates recorder proofs of possession, checks server context against its own
signed grant, key, initialization data, and evidence, and retains exact request
bytes for explicit retries. HTTP success does not establish policy acceptance.

## Protocol integration

1. Construct `ClientProtocol::new` with independently configured
   `GrantExpectations`, the signed grant, a trusted current time, an in-memory
   recorder key, a separate KBS recipient key, and the expected initialization-data
   digest. Construction checks the signed grant's current validity and recorder
   key binding.
2. Exchange the begin and capture messages with the KBS. Supply exact evidence
   from the selected attester; the client neither generates a hardware quote nor
   establishes recorder key origin.
3. Request the resource challenge and policy decision. Verify the returned
   aggregate against independently configured roots and exact expectations.
4. For credential delivery, call `verify_credential_response` with trusted current
   time. It authenticates the signed publication and exact JWE ciphertext before
   exposing bytes to a decrypt adapter. It checks the current signed window even
   for an exact response retry; historical policy authentication does not expose
   ciphertext after expiry.

Grant verification during construction does not replace the server's own current
time and replay checks for a new admission. Aggregate and ciphertext
authentication do not create a guest admission capability, content-preparation
permission, or execution proof. The [workspace guide](../README.md) describes the
separate issuer, guest gate, and handoff boundaries.

## HTTPS transport

The optional `https` feature exposes `https::HttpsTransport`. Construct it with an
explicit HTTPS origin and select a fixed `LaunchRoute`. TLS certificate
verification remains enabled. The transport disables proxies, redirects, and
automatic retries, and configures no cookie jar or ambient authorization. Connect
timeout is 5 seconds; the overall request timeout is 10 seconds. Callers own retry
sequencing and attester/decrypt integration.

| Boundary | Maximum size |
| --- | --- |
| Transport request or response | 2 MiB |
| Policy response | 32 KiB |
| Decoded canonical runtime | 16 KiB |
| Evidence | 1 MiB |
| Credential response | 256 KiB |
| Decoded JWE | 128 KiB |

Run from the workspace root:

```sh
cargo test -p execution-proof-client --features https --locked
cargo clippy -p execution-proof-client --all-targets --features https --locked -- -D warnings
```

The unit tests check protocol handling, bounds, and origin/route selection. They
do not connect to a deployed TLS service or exercise a hardware attester. See the
[root README](../README.md#build-and-test) for build requirements and workspace
checks.
