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

    def test_uses_manifest_digest_and_checks_platform(self):
        for architecture in ("amd64", "arm64"):
            with self.subTest(architecture=architecture), tempfile.TemporaryDirectory() as raw:
                path = Path(raw) / "caa.tar"
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
                if architecture == "amd64":
                    self.assertEqual(render.caa_image(path), {
                        "reference": render.CAA_REFERENCE, "digest": digest,
                    })
                else:
                    with self.assertRaisesRegex(ValueError, "Linux amd64"):
                        render.caa_image(path)


if __name__ == "__main__":
    unittest.main()
