# Run the execution proof prototype

Use the offline demo to inspect evidence from three executions of one encrypted
image. Use the GKE setup to launch a workload and generate fresh evidence with
the standard Cloud API Adaptor (CAA) GCP provider.

## Verify the offline demo

Use x86-64 Linux. Install Python 3.11+, `jq`, `tar`, `gzip`, and
`sha256sum` using your distribution's package manager. The pinned verifier
executables require glibc and `libgcc_s.so.1`. Obtain the demo archive from the
prototype operator and set `DEMO_ARCHIVE` to its path. The archive includes
the evidence packs, relying-party expectations and verifier executables.
Set `DEMO_EXPECTATIONS_SHA384` to the expectations digest received from the
relying party through a trusted channel.

```bash
mkdir demo
tar -xzf "$DEMO_ARCHIVE" --strip-components=1 -C demo
cd demo
sha256sum -c SHA256SUMS

python3 -B verify-pod-executions.py \
  --expectations relying-party/expectations.json \
  --expectations-sha384 "$DEMO_EXPECTATIONS_SHA384" \
  --packs packs \
  --verifier bin/gcp-execution-proof-verifier \
  --tdx-worker bin/gcp-tdx-hardware-verifier \
  --gcp-bootstrap-worker bin/gcp-tdx-bootstrap-history-verifier \
  > report.json

jq -e '.pods | length == 3 and all(.[]; .verdict.status == "verified_exec"
  and .verdict.claim == "exec_committed")' report.json
jq -r '.pods[] | [.name, .verdict.status, .verdict.claim, .verdict.identity_scope] | @tsv' report.json
```

Expect three `verified_exec / exec_committed` results. Each result identifies the
authorized attempt and its protected execution record. The Pod UID mapping comes
from the relying party's Kubernetes, CAA and CRI observations. The workers
evaluate the archived TDX collateral against the current clock.

## Prepare a GKE deployment

Use an x86-64 Linux operator host with Git, Python 3.11+, Google Auth,
Requests, PyYAML, OpenSSH, OpenSSL, `jq`, `gcloud`,
`gke-gcloud-auth-plugin`, `kubectl` and `helm`. Install the compiler and
build dependencies in the [PodVM build guide](../integration/gcp-guest/README.md).

From a new workspace directory, clone the compatible prototype branches as
siblings. Set each `*_URL` to the repository or fork carrying the prototype
changes and its `*_BRANCH` to the branch selected for the deployment. Use the
directory names shown because the component manifests use relative Cargo paths.

```bash
git clone --branch "$EPP_BRANCH" "$EPP_URL" execution-proof-prototype
git clone --branch "$GC_BRANCH" "$GC_URL" guest-components-prepared-dev
git clone --branch "$KATA_BRANCH" "$KATA_URL" kata-launch-dev
git clone --branch "$TRUSTEE_BRANCH" "$TRUSTEE_URL" trustee-launch-dev
git clone --branch main https://github.com/qlad-secure/cloud-api-adaptor.git cloud-api-adaptor
root=$PWD
mkdir -p build/bin inputs/public
```

Obtain the deployment inputs before creating a Pod:

| Input | Contents |
| --- | --- |
| Kubernetes profile | Kata and PeerPod charts, worker settings for `kata-remote` and Nydus, the CRI readback helper, CAA Helm values and the Pod manifest. Use the GCP CAA OCI image built from `main`. |
| Operator tools | The qualification driver and signer, the stock-CAA launch controller, evidence assembler and their configuration templates. The launch controller ties the Kubernetes Pod to its Compute instance and drives guest boot and admission. |
| Workload and trust | A signed encrypted OCI image with a platform manifest digest, its Cloud KMS key version, Authority/KBS policy, TLS and signing roots, and TDX collateral. Generate private keys and obtain credentials in your deployment. |

The [GKE deployment guide](../integration/gke/README.md) builds the standard
CAA image and the worker helpers from source and downloads the pinned Helm
charts. It also prepares the manifest renderer, signers and evidence
assembler in this repository. Keep deployment-specific configuration and
credentials in a private staging directory.

### Configure the cluster and PodVM

Set up GKE Standard with a dedicated amd64 Linux worker running containerd.
Install Kata with the `kata-remote` RuntimeClass and Nydus image handling. Label the
worker for the Kata and CAA DaemonSets. Configure access to the Kubernetes API,
the worker's CRI socket and the PodVM serial console. Make the registry and
Authority/KBS reachable on the deployment network and install the matching
registry CA on the worker. Select an Intel TDX-capable Compute zone and machine
type for the PodVM.
([GKE cluster setup](https://docs.cloud.google.com/sdk/gcloud/reference/container/clusters/create),
[Intel TDX configurations](https://docs.cloud.google.com/confidential-computing/confidential-vm/docs/supported-configurations))

Build the measured guest disk with the
[PodVM build guide](../integration/gcp-guest/README.md#2-prepare-the-build-tools-and-linux-source).
Keep its boot manifest, references, registry digest and TLS pins together.
Upload the disk archive to a new staging object and create the Compute image
with the features required by the guest profile. Set `PROJECT`, `GCS_URI`
and `PODVM_IMAGE` to the deployment project, staging URI and image name:

```bash
gcloud storage cp build/podvm/disk/disk.tar.gz "$GCS_URI"
gcloud storage objects describe "$GCS_URI" --format='value(generation)'
gcloud compute images create "$PODVM_IMAGE" --project "$PROJECT" \
  --source-uri "$GCS_URI" --architecture X86_64 \
  --guest-os-features TDX_CAPABLE,UEFI_COMPATIBLE,GVNIC,MULTI_IP_SUBNET
gcloud compute images describe "$PODVM_IMAGE" --project "$PROJECT" \
  --format='json(id,status,guestOsFeatures)'
```

Use the returned numeric image ID for the qualification and PodVM readbacks.
Qualify that image on Intel TDX, verify the bootstrap and execution quotes and
the protected export, then obtain independent review of the evidence and sign
the producer qualification (Q). Before opening the scheduling gate, verify the
Q signature, its binding to the selected boot profile and the validity of Q, the
certificates and the attempt credentials.
([Compute image flags](https://docs.cloud.google.com/sdk/gcloud/reference/compute/images/create))

### Launch with stock CAA

1. Install the PeerPod CRD and deploy the GCP CAA DaemonSet on the dedicated
   worker. Set the Compute project, zone, VPC resource path, subnet, TDX
   machine type and imported PodVM image in the CAA configuration. If the
   chart uses `imagePullPolicy: Never`, preload the OCI archive into the
   worker's containerd `k8s.io` namespace and check the exact image digest.
   Configure the relay's mTLS endpoints.
2. Give CAA its own Google Application Default Credentials for Compute and
   network operations. The PodVM starts without an attached Google service
   account. On the trusted host, initialize the
   [Authority](../issuer/README.md) and configure
   [KBS](../integration/gcp-trusted-services/README.md#configuration) for the
   same measurement, policy, workload and KMS key. Pass the scoped KMS
   credentials to KBS on stdin or a dedicated descriptor. After attestation
   and admission, CDH receives them through KBS and uses them for Cloud KMS.
3. Create one Pod with RuntimeClass `kata-remote`, a scheduling gate and the
   encrypted workload selected by digest. Capture its UID from the Kubernetes
   API. Prepare a fresh signed intent for the expected application spec and
   use the launch controller to open the gate. Bind the persisted Pod UID
   to the CAA PeerPod and the numeric Compute instance ID. Check that the
   instance has Intel TDX, the expected source image ID on its boot disk and
   an empty service-account list.
4. Drive the guest bootstrap, policy and admission exchanges through the
   controller. Check the application container ID against the designated
   worker's CRI readback before issuing the signed startup plan. Preserve
   the protected export and the original Authority/KBS receipts. Use the
   evidence assembler to produce the pack and preserve the independently
   selected trust configuration and challenge.

Run these commands from `integration/gke` after preparing the deployment
profile and the two operator configurations in the
[controller guide](../integration/gke/CONTROLLERS.md). Run `qualify` and
`launch` in their respective private service sessions.

```bash
python3 -B tools/controller/run.py qualify deployment.json qualification-operator.json
```

After verifying and reviewing the qualification evidence, sign Q. Create
the gated Pod and schedule it with the second operator configuration.
Read back the new PodVM and bind the normal Authority and KBS configuration
to that instance before running `launch`.

```bash
python3 -B tools/controller/run.py schedule deployment.json pod-operator.json
python3 -B tools/controller/run.py describe-pod deployment.json pod-operator.json
python3 -B tools/controller/run.py launch deployment.json pod-operator.json
```

### Verify the new execution

Use the evidence assembler with the original protocol records and the
relying party's independently selected trust and challenge files.

Run the [GCP verifier](../verifier/README.md#gcp-tdx) with the resulting
`pack.json`, relying-party trust and challenge files, and both pinned TDX
workers and their SHA-384 hashes. Expect exit status `0`, `verified_exec`
and `exec_committed`. Compare the verified attempt, container ID, VM identity
and encrypted manifest digest with the operator's observations. To repeat the
test, use a new Pod UID, launch intent and verifier challenge.
