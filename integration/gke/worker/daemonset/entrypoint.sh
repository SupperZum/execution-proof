#!/bin/bash
set -euo pipefail
umask 077

[[ ${WORKER_SHA384:-} =~ ^[0-9a-f]{96}$ ]]
cd /opt/onb17
printf '%s  %s\n' "$WORKER_SHA384" worker.tar | sha384sum --check --status

stage=$(mktemp -d /worker/input.XXXXXXXX)
trap 'rm -rf -- "$stage"' EXIT
tar -xf worker.tar -C "$stage"
install -m 0500 install-worker.sh "$stage/install-worker.sh"

# PID 1 is the node's systemd. Enter its mount namespace and use the host's
# systemctl and containerd tools. Only the staging path needs a hostPath.
nsenter --target 1 --mount --root --wdns=/ -- /bin/bash \
    "/var/lib/onb17-worker-install/${stage##*/}/install-worker.sh" "$WORKER_SHA384" "${NODE_IP:-}"
