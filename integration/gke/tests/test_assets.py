import hashlib
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

import render


class DeploymentAssetTests(unittest.TestCase):
    def test_rejects_modified_chart(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            charts = root / "charts"
            charts.mkdir()
            expected = hashlib.sha256(b"approved chart").hexdigest()
            (root / "charts.sha256").write_text(f"{expected}  fixture.tgz\n")
            chart = charts / "fixture.tgz"
            chart.write_bytes(b"approved chart")
            with patch.object(render, "ROOT", root):
                render.verify_charts(root)
                chart.write_bytes(b"replacement chart")
                with self.assertRaisesRegex(ValueError, "unexpected Helm chart digest"):
                    render.verify_charts(root)

    def test_gcp_runs_the_provider_with_file_adc(self):
        profile = json.loads((render.ROOT / "deployment.example.json").read_text())
        image = {"reference": "test.invalid/caa:stock", "digest": "sha256:" + "a" * 64}
        container = {"command": ["/usr/local/bin/entrypoint.sh"],
                     "image": image["reference"] + "@" + image["digest"]}
        spec = {"serviceAccountName": "cloud-api-adaptor", "containers": [container]}
        chart = [{"kind": "DaemonSet", "spec": {"template": {"spec": spec}}}]
        with patch.object(render, "helm", return_value=chart) as helm:
            objects = render.caa_manifests(profile, Path("."), image)
        role = next(obj for obj in objects if obj["kind"] == "Role")
        self.assertEqual(role["rules"][0]["resourceNames"], ["proof-1"])
        values = helm.call_args.args[2]
        self.assertEqual(values["secrets"], {"mode": "reference", "existingTlsSecretName": "caa-relay-tls"})
        self.assertEqual(container["command"] + container["args"], ["/usr/local/bin/cloud-api-adaptor", "gcp"])
        mount = next(m for m in container["volumeMounts"] if m["name"] == "proof-caa-adc")
        secret = next(v["secret"] for v in spec["volumes"] if v["name"] == mount["name"])
        self.assertTrue(mount["readOnly"])
        self.assertEqual(secret, {"secretName": "caa-adc", "defaultMode": 0o400,
                                  "items": [{"key": "GCP_CREDENTIALS", "path": "GCP_CREDENTIALS"}]})
        self.assertEqual(container["env"], [{"name": "GOOGLE_APPLICATION_CREDENTIALS",
                          "value": mount["mountPath"] + "/" + secret["items"][0]["path"]}])

    def test_caa_namespace_finalizers_are_opt_in_and_scoped(self):
        profile = json.loads((render.ROOT / "deployment.example.json").read_text())
        image = {"reference": "test.invalid/caa:stock", "digest": "sha256:" + "a" * 64}
        container = {"image": image["reference"] + "@" + image["digest"]}
        spec = {"serviceAccountName": "cloud-api-adaptor", "containers": [container]}
        with patch.object(render, "helm", return_value=[{"kind": "DaemonSet", "spec": {"template": {"spec": spec}}}]):
            objects = render.caa_manifests(profile, Path("."), image, namespace_finalizers=True)
        role = next(obj for obj in objects if obj["kind"] == "Role")
        self.assertEqual(role["metadata"]["namespace"], "execution-proof")
        self.assertEqual(role["rules"], [{"apiGroups": [""], "resources": ["pods/finalizers"], "verbs": ["update"]}])

    def test_uses_manifest_digest_and_checks_platform(self):
        for architecture in ("amd64", "arm64"):
            with self.subTest(architecture=architecture), tempfile.TemporaryDirectory() as raw:
                path = Path(raw) / "caa-linux-amd64.oci.tar"
                with tarfile.open(path, "w") as archive:
                    def write(name, value):
                        data = json.dumps(value).encode()
                        digest = hashlib.sha256(data).hexdigest()
                        item = tarfile.TarInfo(name or f"blobs/sha256/{digest}")
                        item.size = len(data)
                        archive.addfile(item, io.BytesIO(data))
                        return "sha256:" + digest

                    config = write(None, {"os": "linux", "architecture": architecture})
                    digest = write(None, {"config": {"digest": config}})
                    write("index.json", {"manifests": [{
                        "mediaType": "application/vnd.oci.image.manifest.v1+json",
                        "digest": digest,
                    }]})
                receipt = path.parent / "caa-build-receipt.json"
                pins = {"manifest_digest": digest, "archive_sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
                receipt.write_text(json.dumps(pins))
                if architecture == "amd64":
                    self.assertEqual(render.checked_caa_image(path.parent), {
                        "reference": render.CAA_REFERENCE, "digest": digest,
                    })
                    for field, error in [("manifest_digest", "CAA manifest"), ("archive_sha256", "CAA archive")]:
                        receipt.write_text(json.dumps({**pins, field: "0" * 64}))
                        with self.assertRaisesRegex(ValueError, error):
                            render.checked_caa_image(path.parent)
                else:
                    with self.assertRaisesRegex(ValueError, "Linux amd64"):
                        render.checked_caa_image(path.parent)


if __name__ == "__main__":
    unittest.main()
