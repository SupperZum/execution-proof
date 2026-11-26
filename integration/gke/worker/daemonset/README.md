# Dedicated GKE Standard proof workers

The Kata DaemonSet installs the pinned CAA image, guard, and CRI image
mapping on each eligible Ubuntu node before Kata installs its runtime.
The node pool supplies the isolation labels and taint to replacement nodes.
The guard binds each worker to one Pod UID and one sandbox. Replacing a
consumed worker provides a fresh guard state for a new Pod.

## Cluster inputs

Use an IPv4 GKE Standard cluster with a regular system pool. Select a zonal
`UBUNTU_CONTAINERD` x86-64 proof pool and pin the initial GKE version.
Query zonal availability before provisioning. The pinned Kata and
Nydus setup expects the node's imports to include
`/etc/containerd/conf.d/*.toml` and the effective configuration to use
the containerd v3 CRI tables. Check the runtime on every new GKE node
image or version. [GKE DaemonSet bootstrap](https://docs.cloud.google.com/kubernetes-engine/docs/tutorials/automatically-bootstrapping-gke-nodes-with-daemonsets)

```sh
gcloud container get-server-config --project "$PROJECT" --zone "$ZONE"
gcloud container node-pools create "$POOL" --project "$PROJECT" \
  --cluster "$CLUSTER" --zone "$ZONE" --node-version "$GKE_VERSION" \
  --image-type=UBUNTU_CONTAINERD --machine-type=e2-standard-4 \
  --num-nodes=1 --service-account "$NODE_SERVICE_ACCOUNT" \
  --scopes=cloud-platform \
  --node-labels=execution-proof-worker=true,node-restriction.kubernetes.io/onb17=true \
  --node-taints=execution-proof/worker=true:NoSchedule
```

Give the node service account the GKE default node service account role
and reader access to the private image repository. The installer's init
container uses the existing Kata DaemonSet's host PID namespace and
privileged mode to run host `systemctl` and `ctr`. It has one writable
hostPath for staging. It uses no additional Kubernetes RBAC. Restrict
writes and exec in `execution-proof-runtime` to the cluster's trusted
runtime administrators. Keep the collector on the regular pool under its
restricted namespace policy. The worker taint remains in place.
[GKE node service accounts](https://docs.cloud.google.com/kubernetes-engine/docs/how-to/service-accounts)

The CAA service account can read Pods and image-pull credentials and
write PeerPods and Pod finalizers in `execution-proof`. CAA needs
`get` and `patch` on Nodes and `patch` on Node status for its ownership
annotation and extended resource. CAA startup also has cluster-wide `list` on Pods and lists them across
namespaces with a node-name filter so it can restore connections after
an adaptor restart. The pinned Kata chart retains its
installer RBAC for reconciliation and cleanup. The CAA Google identity
gets only the Compute permissions for the project, configured image,
network, zone, machine type and managed PodVMs. The KBS identity owns
the KMS decrypt permission. [CAA and launch settings](../../README.md)

## Package and install

Start with the pinned chart archives, checked CAA OCI archive and build
receipt from the [GKE build inputs](../../README.md). Supply the three
Linux amd64 binaries `single-guest`, `worker-readback` and
`caa-heartbeat` in `WORKER_BIN`. Record their SHA-384 digests from the
build or an independently obtained release receipt as a JSON object in
`WORKER_PINS`, with binary filenames as keys. Use the deployment
profile fields in [deployment.example.json](../../deployment.example.json).
Place a private workload registry in DNS reach of the worker and the
guest when using one. Add `--registry-ca "$REGISTRY_CA"` to the package
command when the worker needs a private CA. The qualified guest needs its
own pinned trust for that registry.

```sh
python3 worker/daemonset/render.py pack --assets "$ASSETS" \
  --binaries "$WORKER_BIN" --binary-pins "$WORKER_PINS" \
  --output "$IMAGE_CONTEXT" > worker-package.json
docker build --platform linux/amd64 -t "$INSTALLER_TAG" "$IMAGE_CONTEXT"
docker push "$INSTALLER_TAG"
# Set INSTALLER_IMAGE to the private image reference including its pushed digest.
python3 worker/daemonset/render.py manifests --profile "$DEPLOYMENT" \
  --assets "$ASSETS" --pool "$POOL" --installer "$INSTALLER_IMAGE" \
  --worker-sha384 "$(jq -r .worker_sha384 worker-package.json)" --output "$OUT"

kubectl --context "$CONTEXT" apply -f "$OUT/namespaces.yaml"
kubectl --context "$CONTEXT" apply -f templates/peerpod-crd.yaml
kubectl --context "$CONTEXT" wait --for=condition=Established \
  crd/peerpods.confidentialcontainers.org
kubectl --context "$CONTEXT" -n execution-proof-runtime create secret generic caa-adc \
  --from-file=GCP_CREDENTIALS="$CAA_ADC_FILE"
kubectl --context "$CONTEXT" -n execution-proof-runtime create secret generic caa-relay-tls \
  --from-file=ca.crt="$RELAY_CA" --from-file=client.crt="$RELAY_CERT" \
  --from-file=client.key="$RELAY_KEY"
kubectl --context "$CONTEXT" apply -f "$OUT/kata.yaml"
kubectl --context "$CONTEXT" -n execution-proof-runtime rollout status ds/kata-deploy --timeout=10m
kubectl --context "$CONTEXT" apply -f "$OUT/caa.yaml"
kubectl --context "$CONTEXT" -n execution-proof-runtime rollout status \
  ds/cloud-api-adaptor-daemonset --timeout=5m
```

Use a cluster where this deployment owns `kata-remote` and its Kata
chart resources. Use a fresh worker pool for a payload or policy
revision. Wait for protected export and retirement on the old nodes
before removing them. Deleting or restarting a DaemonSet Pod on a node
keeps its guard state. Replace or recreate the node before assigning a
new UID.

## Check a worker

Submit the example Pod with the gate intact. The controller must verify
the target node identity and receive `single-guest ready <pod-uid>`
from that node before selecting it and removing the gate. From a trusted
administrator diagnostic session in the host mount namespace,
`/run/execution-proof/check-runtime.sh --single-guest` checks the active
containerd configuration, Nydus, and the guarded socket. Run
`/run/execution-proof/single-guest ready <pod-uid>` for the gated test
Pod. A successful call reserves the worker for that UID, even while the
Pod is gated. The same UID may repeat the check before creating a guest.
Check that a different UID is refused. Replace the worker through GKE,
compare node UID and Compute instance identity, and repeat with a new
gated Pod. Collect the DaemonSet image digests, runtime readback, and gate
readback for each step.

The current launch worker still takes an explicitly selected hostname
and pinned SSH endpoint when using a static worker configuration.

## Connect the private controller VM

Generate the controller's worker SSH key on its private VM. Pass only the
Ed25519 public key to the build by adding `--controller-public-key
"$CONTROLLER_PUB" --profile "$DEPLOYMENT"` to the `pack` step. The
installer starts a separate SSH listener on the worker's internal address
on TCP 2222. Its forced command accepts `single-guest ready`, CRI
readback and CAA heartbeat. Readback and heartbeat must match the guard's
armed UID. Readback also checks the configured encrypted image digest.
Limit TCP 2222 ingress to the controller identity in the VPC.

Use `worker_pool` in the [launch worker configuration](../../CONTROLLERS.md)
to select from the pool by pool label, isolation label and ready status.
Set `state` to an owner-only directory on the controller's durable disk.
Set `key` to the controller's private SSH key path on the VM.

```json
{
  "worker_pool": {
    "name": "proof-workers",
    "state": "/var/lib/execution-proof/workers",
    "key": "/var/lib/execution-proof/worker-ssh"
  }
}
```

The attached GCE identity needs `compute.instances.get` and
`compute.instances.getSerialPortOutput` for the proof nodes.
The controller needs Kubernetes node read access to compare the
Kubernetes UID, provider ID and internal IP to the Compute instance.
It reads the SSH host key from the matched instance's console and keeps
that pin with its numeric Compute ID. It saves the node assignment per
attempt before checking `ready`. The gate patch pins the chosen
hostname and tests the Pod UID and resource version.

An application test additionally requires a matching image, active signed
qualification, Authority and KBS, and a restricted collector with
persistent storage.
