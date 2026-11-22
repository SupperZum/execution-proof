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
qualification and Pod specs. Sign each tenant intent with the independently
configured tenant key over its distinct workload, attempt, digest, spec hash
and boot binding. Set `serial_host_public_keys` to Google's authenticated
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
