"""Validate the optional D5 observation against its protected record."""
import base64
import hashlib
import json
import re

FIELD = "guest_readback_b64"
MAX_BYTES = 8192
DOMAIN = b"qlad.execution-proof.gcp-d5-readback.v1\0"


def unique(pairs):
    obj = dict(pairs)
    if len(obj) != len(pairs):
        raise ValueError("duplicate guest readback field")
    return obj


def verify(export, record_raw):
    encoded = export[FIELD]
    if not isinstance(encoded, str) or len(encoded) > ((MAX_BYTES + 2) // 3) * 4:
        raise ValueError("guest readback exceeds transport bound")
    raw = base64.b64decode(encoded, validate=True)
    if not 0 < len(raw) <= MAX_BYTES or base64.b64encode(raw).decode() != encoded:
        raise ValueError("invalid guest readback encoding")
    record = json.loads(record_raw, object_pairs_hook=unique)
    value = json.loads(raw, object_pairs_hook=unique)
    version = value.get("version") if isinstance(value, dict) else None
    if type(version) is not int or version not in (1, 2, 3, 4, 5):
        raise ValueError("guest readback version")
    domain = f"qlad.execution-proof.gcp-d5-readback.v{version}\0".encode("ascii")
    if hashlib.sha256(domain + raw).hexdigest() != record["event_id"]:
        raise ValueError("guest readback event digest mismatch")
    fields = {"version", "nonce", "container_id", "generation", "process"}
    if version >= 2:
        fields.add("syscalls")
    if version >= 3:
        fields.add("role_view")
    if version >= 5:
        fields.add("producer_custody")
    if set(value) != fields:
        raise ValueError("guest readback shape")
    if version >= 2:
        verify_syscalls(value["syscalls"])
    if version >= 3:
        verify_role_view(value["role_view"], version)
    if version >= 5:
        verify_producer_custody(value["producer_custody"])
    nonce = value["nonce"]
    if not isinstance(nonce, list) or len(nonce) != 32 or any(type(x) is not int or not 0 <= x <= 255 for x in nonce):
        raise ValueError("guest readback nonce")
    process, task = value["process"], record["task"]
    if (value["container_id"], value["generation"], process["pid"], process["start_ticks"]) != (
        task["container_id"], task["generation"], task["pid"], task["process_start_time_ticks"]
    ):
        raise ValueError("guest readback task identity mismatch")
    if set(process) != {
        "pid", "start_ticks", "uids", "gids", "supplementary_groups", "inheritable", "permitted",
        "effective", "bounding", "ambient", "no_new_privs", "seccomp_mode", "seccomp_filters",
        "mount_types", "descriptors", "producer_paths",
    }:
        raise ValueError("guest readback process fields")
    for name in ("uids", "gids", "supplementary_groups"):
        ids = process[name]
        if (not isinstance(ids, list)
                or (name != "supplementary_groups" and len(ids) != 4)
                or any(type(n) is not int or not 0 <= n < 2**32 for n in ids)):
            raise ValueError("guest readback IDs")
    for name in ("inheritable", "permitted", "effective", "bounding", "ambient"):
        if type(process[name]) is not int or not 0 <= process[name] < 2**64:
            raise ValueError("guest readback capability masks")
    if (type(process["no_new_privs"]) is not bool or type(process["seccomp_mode"]) is not int
            or process["seccomp_mode"] not in (0, 1, 2)
            or type(process["seccomp_filters"]) is not int or not 0 <= process["seccomp_filters"] < 2**32):
        raise ValueError("guest readback security state")
    mounts = process["mount_types"]
    if not isinstance(mounts, list) or len(mounts) > 256 or any(
        type(name) is not str or re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", name) is None for name in mounts
    ):
        raise ValueError("guest readback mount types")
    descriptors = process["descriptors"]
    if not isinstance(descriptors, list) or len(descriptors) > 64 or any(
        not isinstance(row, list) or len(row) != 2 or type(row[0]) is not int or not 0 <= row[0] < 2**32
        or row[1] not in ("Pipe", "Socket", "AnonymousInode", "Path") for row in descriptors
    ):
        raise ValueError("guest readback descriptors")
    verify_paths(process["producer_paths"])
    return value


def verify_producer_custody(custody):
    kinds = {"sealed_origin": "file", "ramfs_backing": "file", "root": "directory",
             "cwd": "directory", "executable": "file"}
    if not isinstance(custody, dict) or set(custody) != set(kinds):
        raise ValueError("producer custody descriptor set")
    for role, kind in kinds.items():
        fd = custody[role]
        expected = {"kind", "access", "cloexec", "readonly_mount", "immutable_seals"}
        if (not isinstance(fd, dict) or set(fd) != expected or fd["kind"] != kind
                or fd["cloexec"] is not True or type(fd["readonly_mount"]) is not bool):
            raise ValueError("producer custody descriptor metadata")
        if role == "sealed_origin":
            if fd["access"] not in ("read_only", "read_write") or fd["immutable_seals"] is not True:
                raise ValueError("producer custody origin seals")
        elif (fd["access"] not in ("path_only", "read_only") or fd["readonly_mount"] is not True
                or fd["immutable_seals"] is not None):
            raise ValueError("producer custody mount or access")


def verify_path_metadata(metadata):
    if metadata is None:
        return
    if (not isinstance(metadata, dict) or set(metadata) != {"kind", "mode", "uid", "gid"}
            or metadata["kind"] not in ("socket", "char_device", "directory", "symlink", "other")
            or type(metadata["mode"]) is not int or not 0 <= metadata["mode"] <= 0o7777
            or any(type(metadata[k]) is not int or not 0 <= metadata[k] < 2**32 for k in ("uid", "gid"))):
        raise ValueError("guest readback path metadata")


def verify_paths(paths):
    expected_paths = ["sys/kernel/config/tsm/report", "dev/tdx_guest",
                      "run/onb17/kata-agent.sock", "run/onb17/kata-sandbox.sock"]
    if (not isinstance(paths, list) or len(paths) != len(expected_paths)
            or any(not isinstance(row, list) or len(row) != 2 for row in paths)
            or [row[0] for row in paths] != expected_paths):
        raise ValueError("guest readback producer paths")
    for _, metadata in paths:
        verify_path_metadata(metadata)


def verify_role_view(view, version):
    listeners = {"agent_unix_listener", "sandbox_unix_listener", "relay_ipv4_listener"}
    fields = {"scope", "paths", "socket_parent"} | listeners
    if version >= 4:
        fields |= {"relay_owner", "private_runtime"}
    if (not isinstance(view, dict) or set(view) != fields
            or view["scope"] != "kata_observer_namespace"
            or any(type(view[key]) is not bool for key in listeners)):
        raise ValueError("guest role view shape")
    verify_paths(view["paths"])
    verify_path_metadata(view["socket_parent"])
    if version < 4:
        return
    verify_path_metadata(view["private_runtime"])
    owner = view["relay_owner"]
    if owner is None:
        return
    ids = ("uid", "gid")
    masks = ("effective_capabilities", "permitted_capabilities")
    groups = "supplementary_groups"
    identity = "executable_inode_matches_measured_leaf"
    if (not isinstance(owner, dict) or set(owner) != set(ids + masks + (groups, identity))
            or not view["relay_ipv4_listener"] or owner[identity] is not True
            or any(type(owner[key]) is not int or not 0 <= owner[key] < 2**32 for key in ids)
            or any(type(owner[key]) is not int or not 0 <= owner[key] < 2**64 for key in masks)
            or not isinstance(owner[groups], list) or len(owner[groups]) > 32
            or any(type(v) is not int or not 0 <= v < 2**32 for v in owner[groups])):
        raise ValueError("guest relay owner shape")


def verify_syscalls(trace):
    if not isinstance(trace, dict) or set(trace) != {"completion", "stops", "outcomes"}:
        raise ValueError("guest syscall trace shape")
    reason, stops, outcomes = trace["completion"], trace["stops"], trace["outcomes"]
    if (reason not in ("observed_all", "task_exit", "observation_limit")
            or type(stops) is not int or not 0 <= stops <= 64
            or not isinstance(outcomes, list) or len(outcomes) > 4 or 2 * len(outcomes) > stops):
        raise ValueError("guest syscall trace bounds")
    seen = set()
    for outcome in outcomes:
        if not isinstance(outcome, dict) or set(outcome) != {"call", "result", "is_error"}:
            raise ValueError("guest syscall outcome shape")
        call, result, is_error = outcome["call"], outcome["result"], outcome["is_error"]
        if (call not in ("open", "openat", "ioctl", "connect") or call in seen
                or type(result) is not int or not -4095 <= result < 2**63
                or result in (-516, -514, -513, -512)
                or type(is_error) is not bool or is_error != (result < 0)):
            raise ValueError("guest syscall outcome")
        seen.add(call)
    complete = bool(seen & {"open", "openat"}) and {"ioctl", "connect"} <= seen
    if complete != (reason == "observed_all"):
        raise ValueError("guest syscall completion")


def evidence_export(source, output):
    """Produce the existing assembler's v2 input. Keep the original intact."""
    export = json.loads(source.read_bytes(), object_pairs_hook=unique)
    if FIELD not in export:
        return source
    raw_record = base64.b64decode(export["record_b64"], validate=True)
    verify(export, raw_record)
    del export[FIELD]
    with output.open("x") as stream:
        json.dump(export, stream, separators=(",", ":"))
    return output


def verified_observation(export_path, pack_path, verifier_report):
    """Use only after the independent execution verifier returns verified_exec."""
    export = json.loads(export_path.read_bytes(), object_pairs_hook=unique)
    raw_record = base64.b64decode(export["record_b64"], validate=True)
    observed = verify(export, raw_record)
    record = json.loads(raw_record, object_pairs_hook=unique)
    pack = json.loads(pack_path.read_bytes(), object_pairs_hook=unique)
    if (bytes(pack["execution"]["record"]) != raw_record
            or bytes(pack["execution"]["quote"]) != base64.b64decode(export["quote_b64"], validate=True)):
        raise ValueError("guest readback record or quote differs from verified pack")
    (pod,) = verifier_report["pods"]
    if (pod["verdict"]["status"] != "verified_exec" or pod["event_id"] != record["event_id"]
            or pod["container_id"] != record["task"]["container_id"]):
        raise ValueError("guest readback does not match verified execution")
    return {"pod_uid": pod["pod_uid"], "boot_id": pod["boot_id"], "attempt_id": pod["attempt_id"],
            "event_id": pod["event_id"], "guest_readback": observed}
