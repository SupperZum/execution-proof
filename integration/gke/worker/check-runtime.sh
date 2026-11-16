#!/bin/sh
# Run on the designated GKE worker in the host mount namespace.
set -eu
export PATH=/usr/sbin:/usr/bin:/sbin:/bin:/home/kubernetes/bin
export LC_ALL=C
cd /

check() {
    if ! "$@"; then
        printf 'worker check failed: %s\n' "$*" >&2
        exit 1
    fi
}

toml_value() {
    section=$1
    key=$2
    shift 2
    awk -v section="$section" -v key="$key" '
        FNR == 1 { current = "" }
        /^[[:space:]]*\[/ {
            current = $0
            gsub(/["\047[:space:]]/, "", current)
            next
        }
        current == "[" section "]" && /^[[:space:]]*[^#][^=]*=/ {
            pos = index($0, "=")
            name = substr($0, 1, pos - 1)
            gsub(/["\047[:space:]]/, "", name)
            if (name == key) {
                value = substr($0, pos + 1)
                sub(/^[[:space:]]*["\047]?/, "", value)
                sub(/["\047]?[[:space:]]*$/, "", value)
            }
        }
        END { if (value == "") exit 1; print value }
    ' "$@"
}

pid=$(systemctl show containerd.service --property=MainPID --value)
case "$pid" in ''|0|*[!0-9]*) exit 1;; esac
config=$(tr '\000' '\n' < "/proc/$pid/cmdline" | awk '
    next_is_path { path = $0; next_is_path = 0; next }
    $0 == "--config" || $0 == "-c" { next_is_path = 1; next }
    /^--config=/ { path = substr($0, 10) }
    END { if (next_is_path) exit 1; print path }
')
config=${config:-/etc/containerd/config.toml}
dump=$("/proc/$pid/exe" --config "$config" config dump)

runtime=plugins.io.containerd.cri.v1.runtime.containerd.runtimes.kata-remote
images=plugins.io.containerd.cri.v1.images.runtime_platforms.kata-remote
proxy=proxy_plugins.nydus-for-kata-tee
runtime_type=$(printf '%s\n' "$dump" | toml_value "$runtime" runtime_type)
runtime_snapshotter=$(printf '%s\n' "$dump" | toml_value "$runtime" snapshotter)
image_snapshotter=$(printf '%s\n' "$dump" | toml_value "$images" snapshotter)
kata_config=$(printf '%s\n' "$dump" | toml_value "$runtime.options" ConfigPath)
kata_shim=$(printf '%s\n' "$dump" | toml_value "$runtime" runtime_path)
proxy_type=$(printf '%s\n' "$dump" | toml_value "$proxy" type)
proxy_address=$(printf '%s\n' "$dump" | toml_value "$proxy" address)
unset dump

check test "$runtime_type" = io.containerd.kata-remote.v2
check test "$runtime_snapshotter" = nydus-for-kata-tee
check test "$image_snapshotter" = nydus-for-kata-tee
check test "$proxy_type" = snapshot
check test "$proxy_address" = /run/nydus-for-kata-tee/containerd-nydus-grpc.sock
check test -S "$proxy_address"
check systemctl is-active --quiet nydus-for-kata-tee.service
plugins=$(ctr --address /run/containerd/containerd.sock plugins ls)
plugin=$(printf '%s\n' "$plugins" | awk '
    $1 == "io.containerd.snapshotter.v1" && $2 == "nydus-for-kata-tee" && $NF == "ok" { print; found = 1 }
    END { if (!found) exit 1 }
')
printf 'kernel=%s\nruntime_type=%s\nruntime_snapshotter=%s\nimage_snapshotter=%s\n' \
    "$(uname -r)" "$runtime_type" "$runtime_snapshotter" "$image_snapshotter"
printf 'snapshotter_socket=%s\nsnapshotter_plugin=%s\n' "$proxy_address" "$plugin"
sha256sum "$kata_shim" "$kata_config"
set -- "$kata_config"
for file in "$(dirname "$kata_config")"/config.d/*; do
    if [ -f "$file" ]; then
        sha256sum "$file"
        set -- "$@" "$file"
    fi
done
remote_socket=$(toml_value hypervisor.remote remote_hypervisor_socket "$@")
remote_timeout=$(toml_value hypervisor.remote remote_hypervisor_timeout "$@")
check test "$remote_socket" = /run/peerpod/hypervisor.sock
check test "$remote_timeout" = 600
printf 'remote_hypervisor_socket=%s\nremote_hypervisor_timeout=%s\n' "$remote_socket" "$remote_timeout"
