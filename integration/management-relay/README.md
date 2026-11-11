# Closed management TLS relay

This explicit entrypoint carries the existing CAA TCP byte stream to the fixed
proof-enabled Kata Unix socket `/run/onb17/kata-agent.sock`. It does not run APF,
the CAA interceptor, PodSetup, network/module/mount helpers, or a protocol-aware
proxy. Kata must enforce its own proof-required RPC gate before side effects.

`New(Config, Credentials)` accepts trusted startup inputs and allocates bounded
copy buffers. `Relay.Run(ctx)` listens on the configured literal IPv4 address at
TCP 15150. It completes a bounded TLS 1.3 mutual-authentication handshake before
opening the fixed Unix backend. TLS 1.2 and plaintext are unsupported. TLS peer
identity is management identity, not tenant authority or attested guest identity.

The TLS profile uses PEM certificates and PKCS8 private keys. Endpoint keys
must be ECDSA P-256, separating them from Ed25519 proof signing keys. It accepts the
existing CAA client shape: self-signed ECDSA P-256 with clientAuth and no SAN.
The guest pins both the client trust PEM and the exact client leaf DER hash;
the server certificate PEM and its expected SAN are independently pinned. CAA
custom-CA mode verifies `podvm-server`; automatic mode verifies its instance
server name. The operator must configure the same server trust/name at CAA.

The executable requires real/effective UID/GID1001 with no other supplementary
groups. It accepts no arguments or environment-based trust configuration. It reads
strict JSON only at `/onb17/management/relay.json`: root-owned components, no
symlinks, and a read-only `/onb17` filesystem. The measured startup owner must
authenticate these exact bytes against C/D, then supply CA/certificate/private
key through three reserved inherited high descriptors. The credential hint
is `ONB17_MANAGEMENT_TLS_FDS=128:129:130`: exactly three distinct decimal values
in 128–4095, without padding or whitespace. An absent/invalid hint fails closed;
it selects no config, content, root, or backend. Startup reserves the aliases
before spawning, preserving the exec error pipe; the executable never uses
`dup2`. Each FD must be read-only and a bounded regular sealed file
with `F_SEAL_SEAL|F_SEAL_SHRINK|F_SEAL_GROW|F_SEAL_WRITE`. All three descriptors
are consumed and closed. A separate `ONB17_MANAGEMENT_READY_FD=131` locates one
reserved write-only FIFO in the same descriptor range. After TLS configuration
validation and successful TCP listen, `Relay.RunReady` writes exactly `R` and
closes this pipe. The startup parent requires that byte followed by EOF within
10 seconds; failure or timeout kills and joins the relay before returning an
error. The readiness marker grants no proof authority. Both hints select only
owned descriptor locations. The remaining environment is cleared after reading
them. No private key belongs in JSON, the PE, C/D, or proof
supporting objects. Core dumps are disabled before reading credentials.

The file/FD checks and the library constructor do not create a trusted boot
capability. The startup supervisor remains responsible for immutable provenance,
the role's separate UID/capabilities/FD/environment/seccomp policy, socket path
custody, and separation from proof/issuer/KBS signing keys. Go retains parsed
private key copies for the process lifetime; clearing input bytes is not a
guarantee of complete memory erasure.

Bounds are configured in strict JSON and checked before listening: 1–8 accepted
connections, two 16 KiB copy buffers per connection, final kernel backlog equal to
the connection ceiling, handshake wire ≤64 KiB per direction, handshake ≤10s,
backend dial ≤5s, idle ≤30s, total session ≤300s, and a combined forwarded payload
budget ≤64 MiB. Copy goroutines, handshake, dial, listener watcher, and active
sockets remain owned and are joined on shutdown. One EOF half-closes the other
writer while the reverse direction remains bounded by idle/total deadlines.

Local validation uses actual TCP, TLS, AF_UNIX, and sealed memfds. Raw ttrpc
fixtures follow containerd/ttrpc v1.2.7's ten-byte big-endian headers, including
fragmented/coalesced/multiple streams and half-close. This tests transport
compatibility with the inspected CAA TLS/wire profile; it is not a deployed CAA
or Kata acceptance run, producer qualification, or GCP hardware evidence.

```sh
GOTOOLCHAIN=local GOPROXY=off go test -race -count=1 ./...
GOTOOLCHAIN=local GOPROXY=off go vet ./...
CGO_ENABLED=0 GOTOOLCHAIN=local GOPROXY=off go build -trimpath ./cmd/management-relay
```
