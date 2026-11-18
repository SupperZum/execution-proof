# Execution evidence verifier

This library and CLI authenticate a local execution evidence graph and invoke a
separately pinned TDX verifier process. A decoded record or assembled pack is
public data; it cannot create an execution, admission, or quote capability.
The worker profile targets Linux x86_64 and requires executable sealed memfds,
`close_range` and seccomp support.

```sh
execution-proof-verifier \
  --pack pack.json \
  --trust trust.json \
  --challenge challenge.json \
  --tdx-worker /opt/execution-proof/tdx-execution-verifier \
  --tdx-worker-sha384 <trusted-worker-sha384>
```

The relying party supplies all five arguments. Trust roots, exact signed policy
expectations, guest measurements, producer-isolation qualification, and the
expected quote challenge come from that party's configuration, never the pack.
The worker path and digest select a trusted implementation; its executable is
copied into a sealed memfd before execution. A feature-disabled TDX worker
returns `unproven`; there is no sample-attestation fallback.

`EvidencePack::from_protected_export` converts the bounded public Kata export
wire plus a credential metadata receipt and supporting objects into a pack.
It checks transport bounds and canonical Base64 only. `verify_graph` then
authenticates historical launch/admission signatures, recomputes referenced
commitments, and checks P/provenance/R/quote bindings. The final verdict additionally
requires the pinned worker's quote verification, the configured measurements,
non-debug state, `UpToDate` TCB, unexpired collateral, and a qualified producer
profile. The configured producer profile covers the runtime's preparation and
effective-spec enforcement; the pack excludes image layers, raw spec/env,
credentials, JWE payloads and private keys.

The graph is flat and typed: no arbitrary links, bundle-selected paths, remote
retrieval or compression. Limits are 16 MiB serialized pack, 64 total objects
(including embedded signed statements), 4 MiB serialized/decoded object, 1 MiB
decoded attestation evidence and JSON depth 16. The protected export input has
its own 12 MiB transport bound.

The CLI installs CPU, address-space and elapsed watchdogs before parsing. The
worker supervisor bounds stdin/stdout/stderr, denies socket creation and kills
and reaps its process group on failure. These are operational limits; a library
caller must provide its own process supervision.

Exit status is 0 for `verified_exec`, 1 for `invalid` and 2 for `unproven`.
Missing evidence or an unavailable backend does not establish that no execution
occurred. A positive verdict concerns an authorized workload attempt and its
initial `exec_committed`, not readiness or authoritative Kubernetes Pod identity.

Authorization signatures are checked historically without renewing their windows.
TDX collateral is evaluated using the local worker's observed current clock;
the response must fit the current verification window. That timestamp is neither
exact QVL evaluation time nor execution time. Historical DCAP snapshot validation
is a separate profile. Unit-test quote/claim fixtures do not establish hardware
attestation or deployed producer isolation.

## GCP TDX

Use `gcp-execution-proof-verifier` for the GCP evidence graph. Supply the
pack, trust configuration, and challenge as above, plus the exact hashes and
paths of both hardware workers.

```sh
gcp-execution-proof-verifier \
  --pack pack.json --trust trust.json --challenge challenge.json \
  --tdx-worker "$EXECUTION_WORKER" --tdx-worker-sha384 "$EXECUTION_SHA384" \
  --gcp-bootstrap-worker "$BOOTSTRAP_WORKER" \
  --gcp-bootstrap-worker-sha384 "$BOOTSTRAP_SHA384"
```

The bootstrap worker checks the historical boot evidence. The execution worker
checks the quote bound to the protected execution record. The verdict applies
to an authorized workload attempt.
