# Qualification and launch controllers

The controllers use the same signed launch and serial protocol for every GCP
project. They operate on explicit deployment inputs, read identities through
authenticated GCP and Kubernetes clients, and stop on a mismatch. Run them
on the trusted operator host. The Authority process runs on that host with a
sanitized environment. Run the matching KBS service on an endpoint reachable
from the guest.

## Build and configure

Follow the Execution Proof run guide to clone the branches, build the measured
PodVM, build the independent TDX workers and import the Compute image. Follow
the [deployment guide](README.md) to deploy Kata and stock CAA. Build the
qualification and normal Authority binaries from this checkout:

```bash
cargo build --locked --manifest-path tools/qualification-experiment/Cargo.toml
cargo build --locked --manifest-path "$WORKSPACE/execution-proof-prototype/Cargo.toml" \
  -p execution-proof-issuer --features gcp --bin gcp-authority
```

Select the TLS endpoint names for Authority, KBS and the OCI registry. Create
new role keys and certificate pins for the deployment, or supply matching
operator-managed credentials. Use the public root set to fill the boot and
service configs. Keep signing keys in their respective trusted domains.

```bash
python3 -B tools/controller/make-roots.py --output "$PUBLIC_ROOTS" --private "$PRIVATE_ROOTS" \
  --authority-dns "$AUTHORITY_DNS" --kbs-dns "$KBS_DNS" --registry-dns "$REGISTRY_DNS"
```

Copy `operator.example.json` to two files owned by the operator with mode 0600.
Use one file for qualification and a second for Pod launch. Keep state files,
archive directories, tenant intents and authority settings distinct. Leave
`archive` and the normal `issuer_store` paths unused before a run. Protect key
directories with mode 0700 and keys with mode 0600. Use the normal GKE kubeconfig
context emitted by `gcloud container clusters get-credentials` for this zonal
deployment. `image_id` is the numeric Compute image ID, encoded as a string.

Use one measured boot profile for both phases. Set `binding` to the boot
expectations JSON containing the `boot_binding` member. Set `manifest`,
`references`, `boot_config` and `producer_core` to the exact bytes shipped
with the image. Use the included effective spec examples to prepare the
qualification spec and the Pod spec for a manually signed intent. Automatic
Pod scheduling and launch derive the effective spec from the selected Pod. Set `serial_host_public_keys` to Google's authenticated
public-key list for the deployment region and pin its SHA-384. Confirm the
serial SSH public key is registered for this deployment's `serial_user`
and instance before opening a connection. Use known host keys and an
independently selected SSH endpoint for the dedicated GKE worker.

Both `launch` and `qualify` report `protected_export_available` once the
original export has been synced. If Stop or local cleanup fails after that
point, the command exits unsuccessfully and the archive retains the export.
Their output reports `"retirement": "external"`. The caller owns Pod or VM
retirement and its absence readbacks.

Use a separate user systemd service for each `qualify` and `launch` command.
Run it with `MemoryAccounting=yes`, `MemorySwapMax=0`, `MemoryZSwapMax=0`,
`LimitCORE=0` and `KillMode=control-group`. Set `unit` to the exact service
name in the form `onb17-private-<32 lowercase hexadecimal digits>.service`.
The controller checks the running service's cgroup before accessing the relay
key. `preflight` checks public input hashes and signatures without GCP calls.

```bash
python3 -B tools/controller/run.py preflight deployment.json qualification-operator.json
```

## Run a qualification VM

1. Create one standalone Intel TDX VM using the selected custom Compute
   image. Use gVNIC, no attached Google service account and an ephemeral
   boot disk. Register the operator serial key for this instance. Point
   `qualification_vm` at its exact instance name. The deployed policy,
   address and CA pins must match the measured profile. Use the output
   below for `boot_policy.expected_instance` in the experiment and KBS
   configs. Copy the integer `instance_id`, integer `numerical_project_id`
   and string `zone`.

   ```bash
   python3 -B tools/controller/run.py describe-qualification deployment.json qualification-operator.json
   ```

2. Fill `templates/experiment.example.json` using the typed
   `ExperimentConfig` in `tools/qualification-experiment/src/lib.rs`. Select the signed intent,
   exact artifact expectations, pre-grant worker and policy scope. Use a
   fresh state path and an experimental retirement cutoff that covers the
   run. Set `authority` to the experiment executable and its SHA-384.
   Configure the qualification Kata caller using
   `templates/qualification-relay.example.json`. Its client certificate
   and server pins must match the guest profile. Start KBS for this exact
   instance with the scoped decrypt credential. After staging these inputs,
   run the qualification controller in the private service:

   ```bash
   python3 -B tools/controller/run.py qualify deployment.json qualification-operator.json
   ```

3. Verify both TDX quotes using `templates/qualification-workers.example.json`
   and the independently constructed boot-binding SHA-384 from the boot
   manifest materialization. Match the worker results to the same measured
   profile and the direct VM you provisioned.

   ```bash
   python3 -B tools/controller/check-quotes.py "$QUALIFICATION_ARCHIVE" "$BOOT_CONFIG" \
     "$EXPERIMENT_CONFIG" "$COLLATERAL" "$BOOT_BINDING_SHA384" "$WORKERS_JSON" "$QUOTE_CHECK_DIR"
   ```

4. Retire the exact experiment VM and boot disk and capture authenticated
   absence readbacks. Prepare the four qualification evidence files and
   the independent acceptance review for that profile. Use the signer
   schemas in `tools/qualification-signer/src/main.rs` for the selection
   and review. Sign Q after the experimental retirement cutoff with the
   selected qualification key. Both TDX quote checks are inputs to this
   review. The signer also requires the retired instance ID, artifact
   closure, firmware causality, producer isolation and no-state-copy
   evidence. Store the independently selected Q public key as 32 raw bytes.

## Launch the gated Pod and archive the proof

For automatic intent issuance, use the [event UID scheduling command](#schedule-with-an-automatically-issued-intent).
The sequence below accepts a previously signed intent.

1. Create `rendered/pod.yaml` with the scheduling gate intact. In the Pod
   operator JSON set `authority` to the normal Authority executable and its
   SHA-384, set the live Q and reviewed selection, and use a new signed
   tenant intent for the Pod spec. Choose a fresh receipt path for each new Pod.
   The scheduler records the Pod UID, context, PodVM image ID and signed Q digest
   before removing the gate.

   ```bash
   kubectl --context "$CONTEXT" create -f rendered/pod.yaml
   python3 -B tools/controller/run.py schedule deployment.json pod-operator.json
   ```

2. When CAA creates the PeerPod and TDX instance, obtain its bound identity
   and set it in the normal Authority and KBS configs. Fill
   `templates/issuer.example.json` using `GcpIssuerConfig` in Execution Proof. Start
   KBS using the matching configuration and scoped decrypt credential.
   Enable serial input for this exact PodVM using the operator's registered
   key, without replacing unrelated SSH metadata. The worker must have the
   two supplied worker tools accessible via the configured, authenticated
   SSH connection.

   ```bash
   python3 -B tools/controller/run.py describe-pod deployment.json pod-operator.json
   ```

3. Run the launch controller in its private service. It rejects an
   attached Google service account and an unexpected source image, starts
   the CAA heartbeat, binds the app CID to authenticated CRI readback, and
   archives the protected export before acknowledging it. After archival it closes
   the heartbeat helper and checks its exit status before sending Stop. A failed
   heartbeat is reported even when the export has already been acknowledged.

   ```bash
   python3 -B tools/controller/run.py launch deployment.json pod-operator.json
   ```

4. Prepare the relying-party trust and challenge from the independent
   readbacks and original Authority selections. Fill the public pack
   selection and assemble the evidence as described in the deployment guide.
   Run the GCP verifier against the assembled pack with both pinned TDX
   workers. Use `verified_exec / exec_committed` for the expected attempt,
   VM, CID and encrypted digest as the acceptance condition.

If scheduling is interrupted, rerun `schedule` with the same operator configuration
and receipt. It checks the receipt against the current Pod UID and deployment inputs.
If the gate is already gone it returns success. If the original gate is present it
retries the guarded patch. A replacement Pod requires a fresh intent and private store.

## Inspect Pod inputs before signing

Run the following command while the Pod still has its scheduling gate.

```bash
python3 -B tools/controller/run.py select-intent-inputs deployment.json pod-operator.json --pod-name proof-1
```

The command reads the named Pod in the `execution-proof` namespace through the
configured Kubernetes context. It checks the single-container profile in
`templates/pod.yaml` and the exact workload image reference in the deployment.
The JSON result includes the Pod UID and resource version, the selected manifest
digest, and the effective OCI spec with the Pod hostname. The SHA-384 covers
the UTF-8 bytes of the decoded `effective_spec` string. This read-only operation
selects inputs for the first container start.

## Issue an intent for a gated Pod

Assign one stable `intent_cluster_id` to the authenticated cluster. Configure
all issuers for that cluster to use the same existing `intent_store` directory
on the trusted controller host. The directory must be owned by the controller
user with mode 0700 on a local filesystem that supports SQLite locking.
Keep its `attempts.sqlite` across restarts for the lifetime of the attempts.

Configure `intent_signer` with the executable path and SHA-384 of the
prototype signer and `tenant_key` with its provisioned `tenant.pk8` path.
The signer expects that file in an owner-only directory directly under
`/tmp` and checks the key against `tenant_public_key`. Set `intent_ttl_seconds`
to 1–3600 seconds. The signed qualification sets the upper expiry bound.
The issuer configuration supplies the tenant, audience, authority, boot
binding and policy hashes. Use the same public key and policy settings when
initializing the Authority for the selected PodVM.

```bash
python3 -B tools/controller/run.py issue-intent deployment.json pod-operator.json --pod-name proof-1
```

The command reads the gated Pod, verifies its selected profile and signed
qualification, and writes the signed tenant intent to stdout after committing
its receipt. The receipt key contains the cluster identity, namespace, Pod
UID, container name and start number. Repeating the command for the same
inputs while the intent is valid returns the original bytes. A change to the
bound inputs or an expired intent stops issuance for that key. A replacement
Pod with a new UID receives fresh workload and attempt IDs. Both IDs start
with the checked qualification selection’s `normal_namespace`, followed by
independent random suffixes. Configure the pack assembler with the same
`PROOF_WORKLOAD_PREFIX`. Recovery rejects a stored intent with an incompatible
ID and preserves its signed bytes.

## Schedule with an automatically issued intent

Pass the name and UID from the Kubernetes event to the controller. Use a distinct
`pod_receipt` path for each Pod UID and retain the shared `intent_store` across
deliveries. Configure the signer and issuer as described above.

```bash
python3 -B tools/controller/run.py schedule deployment.json pod-operator.json \
  --pod-name "$POD_NAME" --pod-uid "$POD_UID"
```

The controller reads that Pod from the configured API, issues or reuses its
committed intent, and persists the intent digest and attempt ID in the
scheduling receipt before patching the gate. The patch tests the Pod UID,
resource version, image and gate. After a lost response, retry with the
original event UID and receipt path. An open gate with matching receipts in
both stores completes the request. A gate still present is patched against
the newly validated resource version. A replacement UID ends the original
request. A successful response reports scheduling for the authorized attempt.

Once CAA creates the PeerPod, use the same event name and UID to identify the
PodVM. Configure the instance pins and worker as described in the launch
procedure, then run the launch command in its private service.

```bash
python3 -B tools/controller/run.py describe-pod deployment.json pod-operator.json \
  --pod-name "$POD_NAME" --pod-uid "$POD_UID"
python3 -B tools/controller/run.py launch deployment.json pod-operator.json \
  --pod-name "$POD_NAME" --pod-uid "$POD_UID"
```

Launch reads the scheduled Pod from the Kubernetes API and derives its effective
OCI spec. It retrieves the original signed intent from `intent_store`, verifies
its signature and validity, and compares the full scheduling receipt before
contacting the Authority. The Authority receives the committed intent bytes
in its normal Begin request. The guest startup protocol uses the verified spec.
This command requires neither a tenant signing key nor external `signed_intent`
and `effective_spec` files.

The default deployment grants CAA permission to update Pod finalizers for
`proof-1`. For another Pod name, grant that permission for its exact name and
install a heartbeat helper built from this version.
