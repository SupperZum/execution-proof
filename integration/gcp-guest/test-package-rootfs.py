import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest


PACKAGE = Path(__file__).with_name("package-rootfs.py")
PURPOSE = "qlad.execution-proof.gcp-producer-core.v1"
LIBC = "/lib/x86_64-linux-gnu/libc.so.6"
LIBSECCOMP = "/lib/x86_64-linux-gnu/libseccomp.so.2"
LOADER = "/lib64/ld-linux-x86-64.so.2"
CONFIG = "onb17/boot/config.json"
CORE = "onb17/boot/producer-core.json"


def sha384(data):
    return hashlib.sha384(data).hexdigest()


class PackageRootfsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        temporary = tempfile.TemporaryDirectory()
        cls.addClassCleanup(temporary.cleanup)
        root = Path(temporary.name)
        source = root / "resolver.c"
        source.write_text(
            "#include <unistd.h>\n"
            "int seccomp_syscall_resolve_name_arch(unsigned arch, const char *name) {\n"
            "    (void)arch; (void)name;\n"
            "    return getpid();\n"
            "}\n",
            encoding="ascii",
        )
        cls.resolver = root / "resolver.so"
        subprocess.run(
            [
                "cc", "-shared", "-fPIC", "-Wl,-soname,libseccomp.so.2",
                "-Wl,-z,noexecstack", "-o", str(cls.resolver), str(source),
            ],
            capture_output=True,
            check=True,
        )
        cls.resolver_bytes = cls.resolver.read_bytes()

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.leaves = self.root / "leaves"
        self.config = self.root / "config.json"
        self.core = self.root / "producer-core.json"
        self.output = self.root / "guest.tar"
        self.config_bytes = b'{ "version": 1 }\n'
        self.config.write_bytes(self.config_bytes)
        self.base = {
            LIBC: ("shared_library", b"measured libc fixture"),
            LOADER: ("loader", b"measured loader fixture"),
            "/onb17/bin/kata-agent-gcp-proof": ("kata_agent_binary", b"measured Kata fixture"),
        }
        for path, (_, data) in self.base.items():
            leaf = self.leaves / path.lstrip("/")
            leaf.parent.mkdir(parents=True, exist_ok=True)
            leaf.write_bytes(data)
        (self.leaves / "undeclared").write_bytes(b"not in the measured closure")

    def run_package(self, *, pin=None, omit=()):
        manifest = {
            "version": 1,
            "purpose": PURPOSE,
            "config_sha384": sha384(self.config_bytes),
            "leaves": [
                {"kind": kind, "path": path, "sha384": sha384(data), "size_bytes": len(data)}
                for path, (kind, data) in sorted(self.base.items())
                if path not in omit
            ],
        }
        self.core.write_text(json.dumps(manifest), encoding="ascii")
        result = subprocess.run(
            [
                sys.executable, "-B", str(PACKAGE),
                "--leaves", str(self.leaves),
                "--config", str(self.config),
                "--core", str(self.core),
                "--libseccomp", str(self.resolver),
                "--libseccomp-sha384", pin or sha384(self.resolver_bytes),
                "--output", str(self.output),
            ],
            capture_output=True,
            text=True,
            timeout=20,
        )
        return result, manifest

    def test_archive_measures_exact_resolver_and_preserves_base(self):
        result, manifest = self.run_package()
        self.assertEqual(result.returncode, 0, result.stderr)
        resolver_name = LIBSECCOMP.lstrip("/")
        expected = {path.lstrip("/"): data for path, (_, data) in self.base.items()}
        expected[resolver_name] = self.resolver_bytes
        expected[CONFIG] = self.config_bytes
        resolver_leaf = {
            "kind": "shared_library",
            "path": LIBSECCOMP,
            "sha384": sha384(self.resolver_bytes),
            "size_bytes": len(self.resolver_bytes),
        }
        manifest["leaves"] = sorted(manifest["leaves"] + [resolver_leaf], key=lambda leaf: leaf["path"])
        with tarfile.open(self.output, "r:") as archive:
            files = [member for member in archive if not member.isdir()]
            self.assertEqual(sorted(member.name for member in files), sorted([*expected, CORE]))
            for member in files:
                with self.subTest(member=member.name):
                    self.assertTrue(member.isfile())
                    self.assertEqual((member.uid, member.gid, member.mtime), (0, 0, 0))
                    with archive.extractfile(member) as source:
                        data = source.read()
                    if member.name == CORE:
                        self.assertEqual(json.loads(data), manifest)
                    else:
                        self.assertEqual(data, expected[member.name])
            self.assertEqual(archive.getmember(resolver_name).mode, 0o555)

    def test_wrong_resolver_digest_does_not_create_archive(self):
        result, _ = self.run_package(pin=sha384(b"unselected resolver"))
        self.assertIn("libseccomp SHA-384 mismatch", result.stderr)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.output.exists())

    def test_libc_must_be_in_measured_inventory(self):
        result, _ = self.run_package(omit=(LIBC,))
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.output.exists())

    def test_changed_leaf_does_not_create_archive(self):
        (self.leaves / LIBC.lstrip("/")).write_bytes(b"changed libc fixture!")
        result, _ = self.run_package()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("staged leaf does not match the producer core", result.stderr)
        self.assertFalse(self.output.exists())

    def test_existing_archive_is_preserved(self):
        self.output.write_bytes(b"existing archive")
        result, _ = self.run_package()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.output.read_bytes(), b"existing archive")


if __name__ == "__main__":
    unittest.main()
