"""KBS trust-bundle checks for the GCP guest archive and payload builders."""

MAX_KBS_TLS_ROOTS_BYTES = 64 << 10


def validate_kbs_tls_roots(config, leaves):
    path = config.get("kbs_tls_roots_path") if isinstance(config, dict) else None
    roots = config.get("roots") if isinstance(config, dict) else None
    if not isinstance(path, str) or not isinstance(roots, dict):
        raise ValueError("missing KBS TLS roots configuration")
    for leaf in leaves:
        if leaf["path"] == path:
            if leaf["kind"] != "tls_roots" or leaf["sha384"] != roots.get("kbs_tls_roots_sha384"):
                raise ValueError("KBS TLS roots do not match the configured inventory")
            if leaf["size_bytes"] > MAX_KBS_TLS_ROOTS_BYTES:
                raise ValueError("KBS TLS roots exceed 64 KiB")
            return
    raise ValueError("KBS TLS roots missing from the producer inventory")
