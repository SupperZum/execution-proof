# Dedicated GCP trusted service

The optional service runs on the trusted authority host. The management host
receives public artifacts and RPC access. Keep authority and KBS signing keys,
TLS private keys, issuer state, and Google credentials on the trusted side.

Build the HTTPS service with `--features server --bin gcp-trusted-kbs`. The
composition uses the Trustee GCP evidence, policy, resource and credential
implementations. It selects Intel TDX at the service boundary. Requests cannot
select a verifier backend. The service accepts one process-local launch session
and exposes only the five operations under `/kbs/launch/gcp/v2/`.

## Configuration

Use separate Ed25519 keys for the authority and KBS proofs and a P-256 TLS key
for the HTTPS listener. Set the server name to the certificate's SAN. Select the
expected Compute instance identity independently of the quote.

[render-policies.py](render-policies.py) renders AS and KBS policies for one or
two distinct workload prefixes.

```sh
python3 render-policies.py --authority AUTHORITY --tenant TENANT \
  --container-role ROLE --workflow-id WORKFLOW \
  --resource-path REPOSITORY/TYPE/TAG \
  --workload-prefix WORKLOAD_PREFIX --output selected-policies
```

The AS policy requires the selected GCP TDX profile, a non-debug CPU quote,
`UpToDate` TCB, and current collateral. The KBS policy also binds the authority,
tenant, role, resource, workflow, method, and empty query. The AS authenticates
the quote and checks the boot, module, and report data before policy evaluation.

Fill [service.template.json](service.template.json) from authenticated C/D/A/V
and independent boot and module references. Match the AS policy digest with C
and the issuer configuration. Match the KBS policy, proof root, audiences,
issuers, resource, and workflow with the preparation configuration. The
`offline_collateral` input uses Trustee's `PlatformCollaterals` schema and must
contain the TDX early identity and collateral for the selected FMSPC.

## Build the private runtime

Place the matching Trustee checkout at `../trustee-launch-dev` relative to this
repository. Select an x86-64 GNU Rust toolchain, an SGX SDK include directory,
and the QVL library required by the build recipe. Provide its linker aliases
in the same directory. The build uses the Cargo cache selected by `CARGO_HOME`
and creates no network requests.

```sh
python3 build-workers.py --cargo "$(rustup which cargo)" \
  --sgx-sdk "$SGX_SDK" --qvl-library "$QVL_LIBRARY" --output worker-build
python3 package-runtime.py --workers-build worker-build \
  --experiment "$EXPERIMENT_BINARY" --hosts-file "$TRUSTED_HOSTS" \
  --output trusted-runtime
```

The experiment executable must be named `onb17-qualification-experiment`.
Supply a hosts file with literal addresses for the private service endpoints.
The packager checks the selected worker binaries and source digests before
copying them, verifies that debug stripping preserves loadable bytes, and
copies the GNU loader and recursive shared-library dependencies into the
package. Workers use the fixed lookup path `/opt/onb17/trusted/lib` when
executed from sealed memfds. The selected software QVL profile consumes
explicit collateral. QvE, URTS and quote-provider modes are outside that profile.

## Start the service

Verify the package inventory before preparing an operator-owned chroot. Mount
proc and a private `/run`, provide `/dev/null`, and keep `/tmp` private. The
configuration and collateral paths must remain immutable for the service
lifetime. Keep private keys in owner-only files on the `/run` memory filesystem.
The Ed25519 proof loader requires PKCS#8 v2 with the public key.

```sh
env -i /usr/sbin/chroot "$ROOT" /opt/onb17/trusted/bin/gcp-trusted-kbs \
  --check-config /run/onb17/trusted/service.json
env -i /usr/sbin/chroot "$ROOT" /opt/onb17/trusted/bin/gcp-trusted-kbs \
  --check-startup /run/onb17/trusted/service.json
env -i /usr/sbin/chroot "$ROOT" /opt/onb17/trusted/bin/gcp-trusted-kbs \
  --serve /run/onb17/trusted/service.json --credential-stdin
```

Send the Google service-account JSON through a non-TTY pipe as a four-byte
big-endian length (1–65536), followed by the bytes and EOF. A local initializer
can alternatively provide a read-only, fully sealed memfd in the descriptor
range 128–4095 with `--credential-fd`. Keep credential bytes out of files,
arguments, environment, and logs. Supervise the foreground service and confirm
it has exited before removing private runtime state. The `https_listening`
marker indicates successful configuration and bind.

## Export policy evidence

Provide an empty owner-only archive directory. Before returning the signed
aggregate, the service persists the original captured AS and KBS inputs and
policies. Credential delivery adds the original signed public receipt to that
archive. The archive excludes credential bytes and their hashes. Exact retry
bytes preserve the existing record. Restart requires a new empty archive and
the issuer's durable authorization state.

Preserve the original bytes for the [GCP verifier](../../verifier/README.md#gcp-tdx).
A complete evidence pack also needs the signed boot artifacts, bootstrap,
image and admission evidence, producer qualification, and protected export.

[test-startup.py](test-startup.py) exercises TLS startup and rejected requests
on loopback. Pass `--binary`, `--collateral`, `--qvl-library-dir`, and
`--output`. The test uses ephemeral software keys and a deny policy.
