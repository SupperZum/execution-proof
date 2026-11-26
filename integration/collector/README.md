# Local execution-proof collector

The sender queues a completed GCP proof bundle in SQLite. A separate worker can deliver it after the application exits or the collector restarts. The collector independently verifies the pack against trust and challenge files registered by the relying party. It commits the original bytes, verdict and signed receipt in one SQLite transaction before acknowledging the request.

## Access and inputs

Use Linux with Python 3, the Python `cryptography` package, SQLite and Bubblewrap. Run the following commands from this directory. Use persistent, owner-only directories on a filesystem that supports SQLite locking and synchronous writes. The Unix socket and both databases belong to a trusted local account.

Set `STATE` and `SPOOL` to separate absolute directories. Set `KEY` to a private Ed25519 PEM signing key owned by the collector account with mode 0600. Provision its matching public key independently at the sender as `PUB`. Keep the same private key across restarts. Set `ROOTFS` and `MANIFEST` to an operator-provisioned verifier runtime and SHA-384 manifest. The runtime includes the GCP execution verifier, the TDX hardware and bootstrap-history workers, and their dependencies.

The operator runs the service and the sender under the trusted local Unix account. A user with access to that account can use the socket to read and submit proofs. To use an existing instance, ask its operator for the host, approved account access, socket path and attempt ID. For independent verification on another machine, the operator can export the public artifacts. The reader needs their own trusted verifier runtime, trust file and challenge for the attempt. The collector signing key stays with the operator.

For a new installation, obtain the vetted Linux x86-64 runtime and binary pins from the operator, or follow the repository's [runtime build instructions](../gcp-trusted-services/README.md#build-the-private-runtime). With a trusted build receipt, the following extracts the required manifest from the recorded inventory. Run this once with a new manifest path. The collector checks these hashes at startup.

```sh
ROOTFS="$PACKAGE/rootfs"
jq -r '.rootfs_inventory | to_entries[] | select(.key | startswith("opt/onb17/trusted/bin/")) | "\(.value.sha384)  \(.key)"' \
  "$PACKAGE/package.json" > "$MANIFEST"
```

For a fresh deployment, create a key pair in a new owner-only key directory. Set `KEY` and `PUB` to distinct, unused paths there. Keep a recoverable copy of the private key in the operator's protected key storage. An existing collector database requires its original key. The commands below use a POSIX shell, OpenSSL, curl and jq.

```sh
( set -euC; umask 077
  openssl genpkey -algorithm Ed25519 > "$KEY"
  openssl pkey -in "$KEY" -pubout > "$PUB"
)
```

## Start the service and send a bundle

Register each attempt using the relying party's selected inputs. Start the collector in the foreground.

```sh
install -d -m 700 "$STATE" "$SPOOL"
python3 collector.py --state "$STATE" register --trust "$TRUST" --challenge "$CHALLENGE"
python3 collector.py --state "$STATE" serve --key "$KEY" --runtime "$ROOTFS" --manifest "$MANIFEST"
```

On the sender side, set `BUNDLE` to the directory containing `pack.json`, `trust.json` and `challenge.json`. Enqueue can finish while the collector is unavailable. Run the retry worker separately. Add `--watch` to keep it in the foreground and poll every five seconds. A one-shot flush exits with code 1 if deliveries remain pending.

```sh
attempt=$(python3 outbox.py --state "$SPOOL" enqueue "$BUNDLE")
python3 outbox.py --state "$SPOOL" flush --socket "$STATE/collector.sock" --public-key "$PUB"
python3 outbox.py --state "$SPOOL" status "$attempt"
```

## Receipts and retrieval

`PUT /v1/attempts/{attempt}/pack` accepts up to 16 MiB. The stored receipt binds the attempt ID, event ID and SHA-384 digests of the execution record, pack, trust, challenge and verdict. Ed25519 signs the bytes of `execution-proof.collector.receipt.v1` followed by one NUL byte and the compact, sorted-key JSON statement. The sender checks the pinned public key, verdict and submitted context before saving the receipt and releasing its queued copy. Replaying identical bytes returns the stored receipt. A different pack for an archived attempt receives HTTP 409. An invalid proof receives HTTP 422.

Read the delivery state by attempt ID. After archival, download the artifacts by adding `/pack`, `/trust`, `/challenge`, `/verdict` or `/receipt` to the attempt URL.

```sh
# Set attempt to the requested attempt ID, and SOCKET to the operator's socket path.
base="http://localhost/v1/attempts/$attempt"
curl --fail --unix-socket "$SOCKET" "$base"
# Once delivery is archived, use a fresh directory for this attempt.
download=$(mktemp -d)
for name in pack verdict receipt trust challenge; do
  curl --fail --silent --show-error --unix-socket "$SOCKET" "$base/$name" \
    -o "$download/$name.json" || exit 1
done
```

A registered attempt starts as `pending`. A relying party that establishes the evidence is missing can run `python3 collector.py --state "$STATE" mark-missing "$attempt"` to report `unproven`. A later verified delivery archives it. For independent review, run the verifier on the retrieved pack with the relying party's trusted context. The collector's receipt attests to archival. For GCP guests with receipt enforcement, put the collector's 32 raw Ed25519 public-key bytes in the measured preparation configuration as the JSON array `collector_public_key`. Set the operator's `collector_socket` to the collector's absolute Unix socket path. An independent sender must register and deliver the bundle while the guest waits. The normal controller polls the collector for the signed receipt and sends it over the existing serial control stream. The guest checks its authenticated attempt, execution event and locally computed record digest. Once the guest confirms the signed pack digest, the controller records the receipt in `archive-ack.json` and sends Stop. A missing receipt leaves the guest waiting within its original watchdog. The legacy profile uses its existing shutdown protocol.

## Independently verify the download

Run this from `integration/collector/` on the reader's Linux machine. Supply `TRUST` and `CHALLENGE` selected independently for this attempt. Use the verifier runtime and manifest obtained through the reader's trusted provisioning path. The command runs the verifier offline, then compares its execution verdict and record identity with the downloaded verdict. Evaluation timestamps can differ.

```sh
python3 - "$download" "$ROOTFS" "$MANIFEST" "$TRUST" "$CHALLENGE" <<'PYTHON'
import json
import sys
from pathlib import Path
from collector import Verifier

download, runtime, manifest, trust, challenge = map(Path, sys.argv[1:])
actual = Verifier(runtime, manifest)(
    (download / "pack.json").read_bytes(), trust.read_bytes(), challenge.read_bytes()
)
stored = json.loads((download / "verdict.json").read_bytes())
fields = ("status", "claim", "event_id", "record_sha384", "identity_scope")
if (actual["status"], actual["claim"]) != ("verified_exec", "exec_committed"):
    raise SystemExit("Execution proof did not verify")
if any(actual[k] != stored[k] for k in fields):
    raise SystemExit("Archived verdict differs from independent verification")
print(json.dumps({k: actual[k] for k in fields}))
PYTHON
```

## Back up and restore

The operator maintains `STATE/collector.sqlite` (original packs, verdicts and receipts), `SPOOL/outbox.sqlite` (pending deliveries), the original signing key and the trusted runtime configuration. For a consistent backup of both databases, pause submissions, the sender and the collector. Set `BACKUP` to a new private directory on backup storage and run the example after both databases have been initialized.

```sh
( set -eu; umask 077
  mkdir -m 700 "$BACKUP"
  python3 - "$STATE/collector.sqlite" "$SPOOL/outbox.sqlite" "$BACKUP" <<'PYTHON'
from contextlib import closing
from pathlib import Path
import sqlite3
import sys

collector, outbox, backup = map(Path, sys.argv[1:])
for path in (collector, outbox):
    with closing(sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True)) as src:
        with closing(sqlite3.connect(backup / path.name)) as dst:
            src.backup(dst)
            if dst.execute("PRAGMA integrity_check").fetchall() != [("ok",)]:
                raise SystemExit(f"Backup failed integrity check for {path.name}")
PYTHON
)
```

Restore into **two new, empty directories** owned by the service account. With the service and sender stopped, set `STATE` and `SPOOL` to those new paths.

```sh
( set -eu
  mkdir -m 700 "$STATE" "$SPOOL"
  install -m 600 "$BACKUP/collector.sqlite" "$STATE/collector.sqlite"
  install -m 600 "$BACKUP/outbox.sqlite" "$SPOOL/outbox.sqlite"
)
```

Start the collector with the restored state, the same signing key, runtime and manifest. Point the sender at the restored spool and the new socket, then run `flush`. Retrieve a previously archived attempt by ID, compare its pack and signed receipt byte for byte with the saved originals, and repeat the independent verification above. Replaying a pending delivery after recovery is safe for an identical bundle.

## Qualification export receipts

During qualification, the collector can archive the raw protected export before the guest shuts down. Set `GRANT` to the experimental launch grant and `EXPORT` to the original export file. Preserve its exact bytes, including whitespace. The command writes the signed receipt to standard output after committing the export and receipt in SQLite.

```sh
python3 collector.py --state "$STATE" archive-qualification --key "$KEY" --grant "$GRANT" --export "$EXPORT"
```

The receipt binds the experimental attempt ID, grant ID and SHA-384 digest of the export. The guest checks those fields and the signature against its measured collector key before accepting Stop. An identical retry returns the stored receipt. The receipt proves archival of the raw bytes. Execution verification and qualification review use their own evidence. Normal workload grants require the full pack receipt described above.

## Verify recovery

Run the unit tests from the repository root. For process recovery, supply at least two distinct genuine GCP bundle directories and their corresponding pinned runtime. The check enqueues the bundles offline, discards a response, kills the collector, retries against its reopened database and independently verifies every retrieved bundle. It uses temporary databases and a disposable Ed25519 key.

```sh
python3 -m unittest discover -s integration/collector
python3 integration/collector/check_recovery.py --runtime "$ROOTFS" --manifest "$MANIFEST" "$BUNDLE1" "$BUNDLE2"
```

### Verify the signed receipt and replay the archived proof

Use the original public collector key, runtime and manifest provisioned for
the profile. Supply trust and challenge from the relying party's independent
selection. This command checks the archived context, runs both pinned TDX
workers through the offline verifier, compares verdicts, and verifies the
Ed25519 signature over the attempt, event and artifact hashes.

```sh
python3 -B verify_download.py --download "$download" --runtime "$ROOTFS" \
  --manifest "$MANIFEST" --trust "$TRUST" --challenge "$CHALLENGE" --public-key "$PUB"
```

The collector Dockerfile installs Bubblewrap and runs the service as UID
65532. Mount the separately provisioned verifier runtime, manifest, archive
volume and collector key for that identity. Test the reader command in the
target container runtime with a known original pack before accepting new
submissions. It requires Bubblewrap to create its isolated network namespace.

### Verify new submissions in a restricted Pod

Use the [collector Pod](sidecar/pod.yaml) to verify new submissions and issue
receipts through the private HTTPS endpoint. Build the collector from this
directory, then build the verifier using the same vetted runtime and manifest
as the reader. The verifier build context needs `rootfs/opt/onb17/trusted/`
and `context/trusted-runtime-bins.sha384`.

```sh
docker build -t "$COLLECTOR_IMAGE" .
docker build --build-arg COLLECTOR_IMAGE="$COLLECTOR_IMAGE" -f sidecar/Dockerfile \
  -t "$VERIFIER_IMAGE" "$VERIFIER_CONTEXT"
```

Pin both images by digest in the Pod, including the collector init container.
Provision the archive PVC, the original Ed25519 signing key as Secret entry
`signer.pem`, and the server TLS keypair and client CA under `/tls`. The
collector ConfigMap contains the independent manifest and `server.json`
with the TLS paths, client grants and port 8443. Use one writer per archive.
The init container copies the signing key into an owner-only file in memory.

With `serve --pod-verifier --manifest …`, the collector writes only the pack
and registered trust and challenge to a dedicated memory volume. The verifier
mounts that volume read-only and uses a separate writable `/tmp` for TDX
verification. Keep the Pod's private network namespace and separate PID
namespaces. Reserve UID 65532 for the collector and 65531 for the verifier.
The two processes authenticate these UIDs on a Linux abstract Unix socket.
The verifier checks all three executable pins and applies the offline syscall
filter before accepting requests. Each successful response binds the three
input hashes. The collector checks that binding and the execution verdict,
then commits a signed receipt. An invalid proof returns 422. An unavailable
verifier or mismatched manifest returns 503 and the sender can retry.
An identical retry of an archived attempt returns its stored receipt.

### Run assembly and registration independently of delivery

The authorized profile service supplies a public pack selection and the
independently selected trust and challenge. Run the following as the
assembly or registration identity. Use a persistent owner-only JOBS directory,
a separate SPOOL directory for the sender, and a private WORK directory under
the assembler's compiled public input root. Pin the assembler through the
deployment's trusted configuration. Staging copies and hashes the selected
public inputs in one SQLite transaction. A restart after staging resumes
from those bytes. A repeated enqueue also checks the original bundle hashes.

```sh
python3 assembly.py --state "$JOBS" stage --selection "$SELECTION" \
  --public-root "$PUBLIC_ROOT" --trust "$TRUST" --challenge "$CHALLENGE"
python3 assembly.py --state "$JOBS" resume --assembler "$ASSEMBLER" \
  --assembler-sha384 "$ASSEMBLER_SHA384" --work "$WORK" --spool "$SPOOL" --watch
```

Run the registrar and sender as separate services. Registration replays after
a registrar restart. A submission made before registration stays pending.
Both services retry after an outage. Read registration outcomes in the
service journal and the registrations table in assembly.sqlite. Include this
database in consistent backups along with the sender and archive stores.

```sh
python3 assembly.py --state "$JOBS" register --tls-config "$REGISTRAR_TLS" --watch
python3 outbox.py --state "$SPOOL" flush --tls-config "$SENDER_TLS" --public-key "$PUB" --watch
```

### Private HTTPS endpoint

Add `--tls-config server.json` to the collector serve command to listen for
authenticated HTTPS requests. Configure the listen host, port, server cert
and key, trusted client CA and grants. Index grants by the lowercase SHA-256
fingerprint of the client's DER leaf certificate. Give readers explicit
attempt IDs or a tenant-specific prefix reserved by the issuer. A prefix
grants access to every attempt starting with that string. A client setting
uses `url`, `ca`, `cert` and `key` for the HTTPS origin, trusted server CA,
client certificate and private key respectively. The server certificate
must cover the DNS name or IP used by clients.

```json
{
  "host": "0.0.0.0", "port": 8443,
  "cert": "/run/tls/server.crt", "key": "/run/tls/server.key",
  "client_ca": "/run/tls/client-ca.crt",
  "clients": {
    "0000000000000000000000000000000000000000000000000000000000000000": {
      "roles": ["reader"], "attempts": ["example-attempt"]
    }
  }
}
```

The registrar may PUT `/v1/attempts/{id}/context` with base64 fields `trust`
and `challenge`. Identical bytes return 200, a changed context returns 409.
The sender can PUT pack and GET verdict. The relay can GET receipt; configure
`collector_tls` in its GKE launch settings with the relay client settings
file. A reader can GET status and the five archive objects. A recovery client
can PUT loss with a reason code after confirming loss of an original input.

Readers receive the durable attempt URL from the scheduling receipt's attempt
ID. To download the evidence over HTTPS, use the reader identity and configured
collector CA, then run verify_download.py with the independent context.

```sh
for artifact in pack trust challenge verdict receipt; do
  curl --fail --silent --show-error --cacert "$CA" --cert "$READER_CERT" \
    --key "$READER_KEY" "$ATTEMPT_URL/$artifact" --output "$download/$artifact.json"
done
```
