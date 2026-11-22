# Run on GKE with stock CAA

Follow the [prototype run guide](../../docs/run-prototype.md) to check out the
source branches, build the guest disk and import the Compute image. Run the
commands below from `integration/gke`. Generated charts, images, binaries
and manifests go under `build/` or `rendered/`.

The qualification and launch controllers use the deployment's trusted
signing and TLS roots, signed encrypted workload, KMS key and Intel TDX
collateral. [Controller setup](CONTROLLERS.md) describes the inputs and how
to qualify an image, launch a Pod and collect its execution evidence.

## 1. Build deployment assets and render the profile

Use an x86-64 Linux host with Python 3.11+, PyYAML, cryptography, Helm,
Docker Buildx, gcloud, the GKE authentication plugin, kubectl, jq, SSH,
OpenSSL and the Rust and Go toolchains selected by the source branches.
Set `WORKSPACE` to the parent of the Execution Proof and CAA checkouts.
Use a Docker Buildx builder with OCI export support, such as the
`docker-container` driver. Set `BUILDX_BUILDER` to its name. [OCI exporter documentation](https://docs.docker.com/build/exporters/oci-docker/)

```bash
GKE_DIR=$(pwd -P)
CAA_SRC="$WORKSPACE/cloud-api-adaptor"
./tools/fetch-charts.sh

YQ_VERSION=$(awk '$1 == "YQ_VERSION" { print $3; exit }' "$CAA_SRC/src/cloud-api-adaptor/Makefile.defaults")
test -n "$YQ_VERSION"
caa_revision=$(git -C "$CAA_SRC" rev-parse HEAD)
docker buildx build --metadata-file build/caa-buildx.json --builder "$BUILDX_BUILDER" --platform linux/amd64 \
  --provenance=false --sbom=false \
  --build-arg BUILD_TYPE=release --build-arg RELEASE_BUILD=true \
  --build-arg "YQ_VERSION=$YQ_VERSION" --build-arg VERSION=stock \
  --build-arg "COMMIT=$caa_revision" \
  -f "$CAA_SRC/src/cloud-api-adaptor/Dockerfile" \
  --output "type=oci,name=localhost/execution-proof/caa:stock,dest=$GKE_DIR/build/caa-linux-amd64.oci.tar" \
  "$CAA_SRC/src"
archive_sha=$(sha256sum < build/caa-linux-amd64.oci.tar)
jq -e --arg revision "$caa_revision" --arg archive "${archive_sha%% *}" \
  '{source_revision: $revision, archive_sha256: $archive,
    manifest_digest: (."containerimage.digest" | select(test("^sha256:[a-f0-9]{64}$")))}' \
  build/caa-buildx.json > build/caa-build-receipt.json
cp deployment.example.json deployment.json
# Fill deployment.json with the values from your GCP and registry environment.
python3 -B tools/render.py deployment.json rendered
```

The chart downloader checks the archive digests in `charts.sha256`.
The renderer checks the archive SHA-256 and OCI manifest digest against the
receipt generated from the build. Retain that receipt with the deployment profile.

Use a separate kubeconfig and check the context before applying YAML. Set
`KUBECONFIG`, `CONTEXT`, `PROJECT`, `ZONE`, `CLUSTER`, and `NODE` for
your GKE Standard deployment. Set up the VPC and private paths to the
registry and Authority/KBS. Choose a compatible Ubuntu/containerd amd64
worker and a supported TDX Compute PodVM type. Follow the product guide
to build the measured guest and import the Compute image. Put that image's
name in the profile and retain its numeric image ID.

```bash
export KUBECONFIG
gcloud container clusters get-credentials "$CLUSTER" --project "$PROJECT" --zone "$ZONE"
kubectl --context "$CONTEXT" get node "$NODE" -o wide
kubectl --context "$CONTEXT" apply -f rendered/namespaces.yaml
kubectl --context "$CONTEXT" label node "$NODE" execution-proof-worker=true node.kubernetes.io/worker=
```

## 2. Start Kata and CAA

Install Kata using Helm so its chart hooks run at the appropriate lifecycle
steps. The corresponding `rendered/kata.yaml` is available for inspection.

```bash
helm --kube-context "$CONTEXT" upgrade --install proof-kata build/charts/kata-deploy-4.0.0.tgz \
  --namespace execution-proof-runtime -f templates/kata-values.yaml --wait
kubectl --context "$CONTEXT" get runtimeclass kata-remote
```

Run `worker/check-runtime.sh` in the worker's host mount namespace. If the
runtime-platform entry for image pulls is missing, install
`worker/cri-images.toml` as a drop-in in the worker's active containerd
configuration and reload by restarting containerd on this dedicated node.
Run the readback again. Supply the encrypted workload registry CA through the
worker's containerd registry configuration and check that it is also trusted
by the active image service.

Copy the OCI archive, its independently retained build receipt, the rendered
`caa-image.json` and `worker/import-caa.sh` to the worker. The script verifies
both pins before import and reads back the digest of the containerd image
reference used by the DaemonSet.

```bash
sudo bash import-caa.sh caa-linux-amd64.oci.tar caa-build-receipt.json caa-image.json
```

Create `caa-adc` and `caa-relay-tls` in `execution-proof-runtime`. Prepare
`CAA_ADC_FILE` as the deployment's operator-managed Google ADC file,
`RELAY_CA` as the CA for the guest listener, and `RELAY_CERT` and
`RELAY_KEY` as the pinned CAA client certificate and its private key.
CAA gets scoped Compute and network access. The KMS decrypt credential
belongs to KBS. Avoid printing or archiving either credential.

```bash
kubectl --context "$CONTEXT" -n execution-proof-runtime create secret generic caa-adc \
  --from-file=GCP_CREDENTIALS="$CAA_ADC_FILE"
kubectl --context "$CONTEXT" -n execution-proof-runtime create secret generic caa-relay-tls \
  --from-file=ca.crt="$RELAY_CA" --from-file=client.crt="$RELAY_CERT" --from-file=client.key="$RELAY_KEY"
kubectl --context "$CONTEXT" apply -f templates/peerpod-crd.yaml
kubectl --context "$CONTEXT" wait --for=condition=Established crd/peerpods.confidentialcontainers.org
kubectl --context "$CONTEXT" apply -f rendered/caa.yaml
kubectl --context "$CONTEXT" -n execution-proof-runtime rollout status daemonset/cloud-api-adaptor-daemonset
```

The CAA socket on the worker should be `/run/peerpod/hypervisor.sock`.
Build the worker helpers and qualification client against the CAA Go module.

```bash
mkdir -p "$GKE_DIR/build/bin"
(
  cd "$CAA_SRC/src/cloud-api-adaptor"
  export CGO_ENABLED=0 GOOS=linux GOARCH=amd64
  go build -mod=readonly -trimpath -o "$GKE_DIR/build/bin/worker-readback" "$GKE_DIR/worker/readback.go"
  go build -mod=readonly -trimpath -o "$GKE_DIR/build/bin/caa-heartbeat" "$GKE_DIR/worker/caa-heartbeat.go"
  go build -mod=readonly -trimpath -o "$GKE_DIR/build/bin/qualification-kata" "$GKE_DIR/worker/qualification_kata.go"
)
```

Install `worker-readback` and `caa-heartbeat` on the worker at the configured
paths. Keep `qualification-kata` on the operator host and pin its SHA-384 in
the qualification profile.

## 3. Prepare qualification and the launch controller

Run the following commands from `integration/gke`. Set the three build variables to the
workflow ID and the qualification and workload prefixes independently selected
for the deployment. Set `PROOF_PUBLIC_INPUT_ROOT` to an existing canonical
absolute directory for public evidence only. These values constrain what
the signer and assembler accept.

```bash
export PROOF_WORKFLOW_ID PROOF_QUALIFICATION_PREFIX PROOF_WORKLOAD_PREFIX PROOF_PUBLIC_INPUT_ROOT
cargo build --locked --manifest-path tools/prototype-signer/Cargo.toml
cargo build --locked --manifest-path tools/qualification-signer/Cargo.toml
cargo build --locked --manifest-path tools/pack-assembler/Cargo.toml
```

Use the [guest boot configuration](../gcp-guest/README.md#4-select-the-public-boot-inputs)
and [KBS configuration](../gcp-trusted-services/README.md#configuration) examples.
Fill the signed boot statements and select the matching roots before booting
the PodVM. The statement signer accepts a typed statement, the private key,
the corresponding public key and a fresh absolute output path:

```text
onb17-prototype-statement-signer manifest|reference|tenant-intent STATEMENT PRIVATE_KEY PUBLIC_KEY OUTPUT
```

The qualification signer checks the unsigned Q and its evidence before
signing. It takes the reviewed input set as positional arguments:

```text
onb17-manual-qualification-signer check UNSIGNED_Q SELECTION EVIDENCE_DIR QUALIFICATION_PUBLIC_KEY
onb17-manual-qualification-signer sign UNSIGNED_Q SELECTION EVIDENCE_DIR QUALIFICATION_PUBLIC_KEY QUALIFICATION_KEY SIGNED_Q
onb17-manual-qualification-signer check-signed SIGNED_Q SELECTION EVIDENCE_DIR QUALIFICATION_PUBLIC_KEY
```

Follow [Qualification and launch controllers](CONTROLLERS.md) to configure
and run both stages. The controller collects the protected export and the
public protocol receipts. Use the independent quote checker and reviewed
evidence to sign Q before opening the scheduling gate.

Use the designated worker's CRI socket to verify the application container
ID before issuing the startup plan. The controller must preserve the
protected export and the original Authority and KBS records. Fill `templates/public-selection.example.json` using the worker
readbacks and the relying party's independently selected trust and challenge
when assembling the pack:

```bash
tools/pack-assembler/target/debug/onb17-manual-pack-assembler check "$PUBLIC_SELECTION"
tools/pack-assembler/target/debug/onb17-manual-pack-assembler assemble "$PUBLIC_SELECTION" "$NEW_PACK_DIR"
gcp-execution-proof-verifier \
  --pack "$NEW_PACK_DIR/pack.json" --trust "$NEW_PACK_DIR/trust.json" \
  --challenge "$NEW_PACK_DIR/challenge.json" \
  --tdx-worker "$EXECUTION_WORKER" --tdx-worker-sha384 "$EXECUTION_WORKER_SHA384" \
  --gcp-bootstrap-worker "$BOOTSTRAP_WORKER" --gcp-bootstrap-worker-sha384 "$BOOTSTRAP_WORKER_SHA384"
```

For a deployment that requires a Cloud Storage publication journal, build the
GCP verifier with `--features gcp-journal` and pass `--journal-bucket BUCKET`.
Set `authority_journal_bucket` in the trusted operator configuration to pass the
same bucket to Authority initialization and requests. New stores record the
journal selection and reject a different bucket or mode on reopen. Schema v4
has no journal selection. The operator rejects those stores and preserves their contents. Keep these settings in the relying
party and Authority deployment. Use a new journal with new attempts, or a
journal that already contains the authoritative history for those attempts.
Authority and verifier need read and conditional-create access through their
attached runtime identities. The Storage objects, deployment configuration and
identity grants must be outside the workload restore domain. The runtime needs
access to the metadata credential endpoint and to Cloud Storage through trusted
DNS and TLS.

In journal mode the verifier prints the same verdict schema. It emits
`event_journal_publication=first` or `event_journal_publication=existing` on
stderr only after successful journal readback.


The expected fresh result is `verified_exec / exec_committed` with identity
scope `authorized_workload_attempt`. Match the attempt, container ID, VM and
encrypted manifest digest to the independently collected observations.
