"""Run the current Rust loader in a disposable Linux VM with file-backed EROFS."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization


def sha(data):
    return hashlib.sha384(data).hexdigest()


def write_tree(args, out):
    root = out / "root"
    for folder in ("dev", "proc", "sys", "run", "onb17/boot"):
        (root / folder).mkdir(parents=True)
    config = json.loads((Path(__file__).resolve().parents[1] / "boot-config.example.json").read_text())
    config.pop("management_relay")
    config.update(authority="authority", tenant="tenant", grant_audience="launch", aggregate_audience="policy",
                  admission_receipt_audience="admission", resource_path=["default", "credentials", "gcp"],
                  workflow_id="workflow", host_transport="vsock")
    for key, seed in [("authority", 1), ("kbs_proof", 4), ("build", 201), ("reference", 202), ("qualification", 5)]:
        pub = Ed25519PrivateKey.from_private_bytes(bytes([seed]) * 32).public_key()
        config["roots"][key + "_public_key"] = list(pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw))
    leaves = []

    def leaf(path, kind, raw):
        dest = root / path.lstrip("/")
        dest.parent.mkdir(exist_ok=True, parents=True)
        dest.write_bytes(raw)
        dest.chmod(0o555 if kind.endswith("_binary") or kind in {"loader", "shared_library"} else 0o444)
        leaves.append(dict(path=path, kind=kind, sha384=sha(raw), size_bytes=len(raw)))
        return sha(raw)

    kata = args.handoff_tests.read_bytes()
    leaf(config["kata_agent_path"], "kata_agent_binary", kata)
    # Equal length isolates the digest comparison against /proc/self/exe.
    leaf(config["cdh_path"], "cdh_binary", bytes(len(kata)))
    leaf(config["bootstrap_path"], "bootstrap_binary", b"bootstrap fixture")
    for kind, raw in (("rpc", subprocess.check_output([args.build_inputs, "--rpc-policy"])),
                      ("launch", b"as-policy"), ("image", b"image-policy"),
                      ("writer", b"writer-policy"), ("device", b"device-policy")):
        config[kind + "_policy_sha384"] = leaf(config[kind + "_policy_path"], kind + "_policy", raw)
    leaf("/onb17/policy/workload.json", "data", subprocess.check_output([args.build_inputs, "--workload-policy"]))
    for family in ("authority", "kbs"):
        name = family + "_tls_roots"
        config["roots"][name + "_sha384"] = leaf(config[name + "_path"], "tls_roots", family.encode())
    for line in subprocess.check_output(["ldd", args.handoff_tests], text=True).splitlines():
        path = next((Path(t) for t in line.split() if t.startswith("/")), None)
        if path:
            leaf(str(path), "loader" if path.name.startswith("ld-linux") else "shared_library", path.read_bytes())
    wire = json.dumps(config, separators=(",", ":")).encode()
    (root / "onb17/boot/config.json").write_bytes(wire)
    core = dict(version=1, purpose="qlad.execution-proof.gcp-producer-core.v1",
                config_sha384=sha(wire), leaves=sorted(leaves, key=lambda x: x["path"]))
    (root / "onb17/boot/producer-core.json").write_text(json.dumps(core, separators=(",", ":")))
    subprocess.run([args.build_inputs, root / "onb17/boot/config.json", root / "onb17/boot/producer-core.json"], check=True)
    proc = subprocess.run([args.verifier_tests, "--ignored", "--exact", "gcp_graph::tests::capsule_root::prepare_native_capsules"],
                          env={**os.environ, "CAPSULE_FIXTURE_DIR": str(out)}, check=True, stdout=subprocess.PIPE, text=True)
    assert "1 passed" in proc.stdout
    path = root / config["device_policy_path"].lstrip("/")
    for case in ("valid", "leaf", "extra"):
        if case == "leaf":
            path.chmod(0o644)
            path.write_bytes(b"DEVICE-policy")
            path.chmod(0o444)
        if case == "extra":
            path.chmod(0o644)
            path.write_bytes(b"device-policy")
            path.chmod(0o444)
            (root / "extra").write_bytes(b"unlisted")
        subprocess.run([args.mkfs, "-T", "0", "--all-root", out / (case + ".erofs"), root],
                       check=True, stdout=subprocess.DEVNULL)


def archive(out):
    # Linux newc with root ownership and a console device, without host mknod.
    image = bytearray()

    def add(name, mode, raw=b"", major=0, minor=0):
        fields = (len(image) + 1, mode, 0, 0, 1, 0, len(raw), 0, 0, major, minor, len(name) + 1, 0)
        image.extend(b"070701" + "".join(f"{v:08x}" for v in fields).encode() + name.encode() + b"\0")
        image.extend(b"\0" * (-len(image) % 4))
        image.extend(raw)
        image.extend(b"\0" * (-len(image) % 4))

    for name in ("dev", "inputs", "images", "view"):
        add(name, stat.S_IFDIR | 0o755)
    add("dev/console", stat.S_IFCHR | 0o600, major=5, minor=1)
    add("init", stat.S_IFREG | 0o555, (out / "init").read_bytes())
    for case in ("valid", "leaf", "extra"):
        name = case + ".erofs"
        add(name, stat.S_IFREG | 0o400, (out / name).read_bytes())
    for case in ("valid", "spec", "resource", "workflow"):
        name = case + ".json"
        add("inputs/" + name, stat.S_IFREG | 0o400, (out / name).read_bytes())
    add("TRAILER!!!", 0)
    (out / "init.cpio").write_bytes(image)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for arg in ("kernel", "qemu", "bios", "qemu-data", "mkfs", "handoff-tests", "verifier-tests", "build-inputs", "output"):
        parser.add_argument("--" + arg, type=Path, required=True)
    args = parser.parse_args()
    out = args.output.resolve()
    os.umask(0o022)
    out.mkdir(mode=0o700, exist_ok=False)
    write_tree(args, out)
    subprocess.run(["cc", "-static", "-Os", "-Wall", "-Wextra", "-Werror", "-o", out / "init",
                    Path(__file__).with_name("init.c")], check=True)
    archive(out)
    with (out / "console.log").open("wb") as log:
        subprocess.run([args.qemu, "-L", args.qemu_data, "-bios", args.bios, "-machine", "q35", "-accel", "tcg",
                        "-cpu", "max", "-smp", "2", "-m", "1024M", "-nodefaults", "-no-user-config", "-nic", "none",
                        "-monitor", "none", "-display", "none", "-serial", "stdio", "-no-reboot",
                        "-sandbox", "on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny",
                        "-kernel", args.kernel, "-initrd", out / "init.cpio", "-append", "console=ttyS0 rdinit=/init panic=1"],
                       stdout=log, stderr=subprocess.STDOUT, timeout=150, check=True)
    log = (out / "console.log").read_text(errors="replace")
    if log.count("1 passed; 0 failed") != 3 or "CAPSULE_ROOT_TOTAL 3" not in log:
        raise RuntimeError(f"loader fixture failed; see {out / 'console.log'}")
    print("EROFS loader passed for the valid root, changed leaf and unlisted file")


if __name__ == "__main__":
    main()
