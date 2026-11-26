#!/usr/bin/env python3
"""Render the pinned stock-CAA and Kata charts and a gated proof Pod."""

import argparse
from hashlib import file_digest, sha256
import json
from pathlib import Path
import re
import subprocess
import tarfile

import yaml


ROOT = Path(__file__).resolve().parents[1]
RUNTIME_NS = "execution-proof-runtime"
WORKLOAD_NS = "execution-proof"
WORKER_LABEL = "execution-proof-worker"
DNS = r"[a-z][a-z0-9-]{0,61}[a-z0-9]"
DIGEST = r"sha256:[a-f0-9]{64}"
CAA_REFERENCE = "localhost/execution-proof/caa:stock"
FIELDS = {
    "project", "zone", "network", "subnet", "podvm_image", "machine_type",
    "kubernetes_version", "workload_image",
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def read_json(path):
    return json.loads(path.read_text())


def read_profile(path):
    profile = read_json(path)
    require(isinstance(profile, dict) and profile.keys() == FIELDS,
            "deployment fields differ from deployment.example.json")
    for field in FIELDS - {"workload_image", "kubernetes_version"}:
        value = profile[field]
        require(isinstance(value, str) and re.fullmatch(DNS, value)
                and not value.startswith("replace-with-"), f"set {field}")
    version = profile["kubernetes_version"]
    require(isinstance(version, str) and re.fullmatch(r"v?1\.\d+\.\d+(?:-gke\.\d+)?", version),
            "set kubernetes_version")
    image = profile["workload_image"]
    require(isinstance(image, str) and not image.startswith("registry.example.invalid/")
            and re.fullmatch(r"[a-z0-9][a-z0-9._:/-]+@" + DIGEST, image),
            "set a digest-pinned encrypted workload_image")
    return profile


def verify_charts(assets):
    for line in (ROOT / "charts.sha256").read_text().splitlines():
        expected, name = line.split()
        with (assets / "charts" / name).open("rb") as chart:
            require(file_digest(chart, "sha256").hexdigest() == expected,
                    f"unexpected Helm chart digest: {name}")


def caa_image(archive_path):
    with tarfile.open(archive_path, "r") as archive:
        def document(name, digest=None):
            member = archive.getmember(name)
            require(member.isfile() and 0 < member.size <= 1 << 20,
                    "unexpected OCI metadata size or type")
            with archive.extractfile(member) as source:
                raw = source.read()
            if digest is not None:
                require("sha256:" + sha256(raw).hexdigest() == digest, "OCI metadata digest mismatch")
            return json.loads(raw)

        def blob(descriptor):
            digest = descriptor["digest"]
            require(re.fullmatch(DIGEST, digest), "invalid OCI descriptor digest")
            return document("blobs/" + digest.replace(":", "/", 1), digest)

        index = document("index.json")
        require(len(index["manifests"]) == 1, "expected one CAA image manifest")
        descriptor = index["manifests"][0]
        require(descriptor["mediaType"] == "application/vnd.oci.image.manifest.v1+json",
                "expected a single-platform OCI manifest")
        image = blob(descriptor)
        config = blob(image["config"])
        require(config["os"] == "linux" and config["architecture"] == "amd64",
                "CAA image must target Linux amd64")
        return {"reference": CAA_REFERENCE, "digest": descriptor["digest"]}


def helm(chart, name, values, version):
    if isinstance(values, Path):
        result = subprocess.run(
            ["helm", "template", name, str(chart), "--namespace", RUNTIME_NS,
             "--kube-version", version, "-f", str(values)],
            check=True, capture_output=True, text=True,
        )
    else:
        result = subprocess.run(
            ["helm", "template", name, str(chart), "--namespace", RUNTIME_NS,
             "--kube-version", version, "-f", "-"],
            input=yaml.safe_dump(values), check=True, capture_output=True, text=True,
        )
    return [document for document in yaml.safe_load_all(result.stdout) if document]


def caa_manifests(profile, assets, image, *, namespace_finalizers=False):
    name, tag = image["reference"].rsplit(":", 1)
    repository = f"projects/{profile['project']}"
    values = {
        "provider": "gcp",
        "limit": "1",
        "image": {"name": name, "tag": f"{tag}@{image['digest']}"},
        "secrets": {"mode": "reference", "existingTlsSecretName": "caa-relay-tls"},
        "tlsProfile": {"minVersion": "VersionTLS13"},
        "providerConfigs": {"gcp": {
            "GCP_PROJECT_ID": profile["project"], "GCP_ZONE": profile["zone"],
            "GCP_NETWORK": f"{repository}/global/networks/{profile['network']}",
            "GCP_SUBNETWORK": profile["subnet"],
            "GCP_CONFIDENTIAL_TYPE": "TDX", "GCP_MACHINE_TYPE": profile["machine_type"],
            "GCP_DISK_TYPE": "pd-balanced", "PODVM_IMAGE_NAME": profile["podvm_image"],
            "DISABLECVM": "false", "FORWARDER_PORT": "15150", "PROXY_TIMEOUT": "8m",
            "CACERT_FILE": "/etc/certificates/ca.crt",
            "CERT_FILE": "/etc/certificates/client.crt",
            "CERT_KEY": "/etc/certificates/client.key",
            "REMOTE_HYPERVISOR_ENDPOINT": "/run/peerpod/hypervisor.sock",
        }},
        "resourceCtrl": {"enabled": False},
        "webhook": {"enabled": False},
        "kata-deploy": {"enabled": False},
    }
    objects = helm(assets / "charts/peerpods-0.4.0.tgz", "proof-caa", values,
                   profile["kubernetes_version"])
    daemons = [obj for obj in objects if obj["kind"] == "DaemonSet"]
    require(len(daemons) == 1 and not any(obj["kind"] == "Secret" for obj in objects),
            "expected a single CAA DaemonSet with external Secret references")
    spec = daemons[0]["spec"]["template"]["spec"]
    containers = spec["containers"]
    require(len(containers) == 1 and containers[0]["image"] == f"{name}:{tag}@{image['digest']}",
            "unexpected CAA image or container layout")
    container = containers[0]
    # The stock entrypoint requires inline GCP_CREDENTIALS and replaces the ADC path.
    container["command"] = ["/usr/local/bin/cloud-api-adaptor"]
    container["args"] = ["gcp"]
    container["imagePullPolicy"] = "Never"
    spec.setdefault("nodeSelector", {})[WORKER_LABEL] = "true"
    mounts = container.setdefault("volumeMounts", [])
    require(not any(m["mountPath"] in {"/tmp", "/run/caa-adc"} for m in mounts),
            "CAA chart already owns a private mount")
    mounts.extend([
        {"name": "proof-caa-tmp", "mountPath": "/tmp"},
        {"name": "proof-caa-adc", "mountPath": "/run/caa-adc", "readOnly": True},
    ])
    env = container.setdefault("env", [])
    require(not any(var["name"] == "GOOGLE_APPLICATION_CREDENTIALS" for var in env),
            "CAA chart already selects an ADC path")
    env.append({"name": "GOOGLE_APPLICATION_CREDENTIALS", "value": "/run/caa-adc/GCP_CREDENTIALS"})
    spec.setdefault("volumes", []).extend([
        {"name": "proof-caa-tmp", "emptyDir": {"medium": "Memory", "sizeLimit": "16Mi"}},
        {"name": "proof-caa-adc", "secret": {"secretName": "caa-adc", "defaultMode": 0o400,
          "items": [{"key": "GCP_CREDENTIALS", "path": "GCP_CREDENTIALS"}]}},
    ])
    finalizers = {"apiGroups": [""], "resources": ["pods/finalizers"], "verbs": ["update"]}
    if not namespace_finalizers:
        finalizers["resourceNames"] = ["proof-1"]
    role = {"name": "proof-pod-owner", "namespace": WORKLOAD_NS}
    objects.extend([
        {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role", "metadata": role,
         "rules": [finalizers]},
        {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding", "metadata": role,
         "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": role["name"]},
         "subjects": [{"kind": "ServiceAccount", "name": spec["serviceAccountName"],
                       "namespace": RUNTIME_NS}]},
    ])
    return objects


def render(profile, output, assets, *, namespace_finalizers=False):
    verify_charts(assets)
    image = checked_caa_image(assets)
    kata = helm(assets / "charts/kata-deploy-4.0.0.tgz", "proof-kata",
                 ROOT / "templates/kata-values.yaml", profile["kubernetes_version"])
    require(sum(obj["kind"] == "RuntimeClass" and obj["metadata"]["name"] == "kata-remote"
                for obj in kata) == 1, "Kata rendered without the kata-remote RuntimeClass")
    caa = caa_manifests(profile, assets, image, namespace_finalizers=namespace_finalizers)
    pod = yaml.safe_load((ROOT / "templates/pod.yaml").read_text())
    pod["spec"]["containers"][0]["image"] = profile["workload_image"]
    pod["spec"]["nodeSelector"][WORKER_LABEL] = "true"
    namespaces = [
        {"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": WORKLOAD_NS}},
        {"apiVersion": "v1", "kind": "Namespace", "metadata": {
            "name": RUNTIME_NS, "labels": {"pod-security.kubernetes.io/enforce": "privileged"}}},
    ]
    output.mkdir(mode=0o700)
    for name, documents in (("namespaces", namespaces), ("kata", kata),
                            ("caa", caa), ("pod", [pod])):
        with (output / f"{name}.yaml").open("x") as rendered:
            yaml.safe_dump_all(documents, rendered, explicit_start=True, sort_keys=False)
    with (output / "caa-image.json").open("x") as receipt:
        json.dump(image, receipt, indent=2)
        receipt.write("\n")
    print(f"Rendered Kubernetes manifests in {output}")


def checked_caa_image(assets):
    receipt = read_json(assets / "caa-build-receipt.json")
    archive = assets / "caa-linux-amd64.oci.tar"
    with archive.open("rb") as stream:
        require(file_digest(stream, "sha256").hexdigest() == receipt["archive_sha256"],
                "CAA archive differs from the build receipt")
    image = caa_image(archive)
    require(image["digest"] == receipt["manifest_digest"], "CAA manifest differs from the build receipt")
    return image


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("profile", type=Path)
    parser.add_argument("output", type=Path, help="new output directory")
    parser.add_argument("--assets", type=Path, default=ROOT / "build")
    parser.add_argument("--namespace-finalizers", action="store_true",
                        help="allow CAA to update Pod finalizers throughout the dedicated workload namespace")
    args = parser.parse_args()
    try:
        render(read_profile(args.profile), args.output, args.assets, namespace_finalizers=args.namespace_finalizers)
    except subprocess.CalledProcessError as error:
        parser.exit(1, error.stderr or str(error))
    except (ValueError, OSError, KeyError, TypeError, tarfile.TarError, yaml.YAMLError) as error:
        parser.exit(1, f"{error}\n")
