#!/bin/bash
set -euo pipefail
umask 077
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/home/kubernetes/bin
export LC_ALL=C

revision=$1
[[ $revision =~ ^[0-9a-f]{96}$ ]]
cd -- "$(dirname -- "$0")"
installer=/var/lib/onb17-worker-install
runtime=/run/execution-proof
state=/var/lib/onb17-single-guest

test "$(ps -p 1 -o comm=)" = systemd
grep -Eq '^ID=ubuntu$' /etc/os-release
test "$(uname -m)" = x86_64
test -S /run/containerd/containerd.sock
for tool in systemctl ctr crictl jq flock; do command -v "$tool" >/dev/null; done

exec 9>"$installer/lock"
flock --exclusive 9
if [[ -e $installer/revision ]]; then
    [[ $(cat "$installer/revision") == "$revision" ]] || {
        echo "worker payload changed, replace the dedicated node" >&2
        exit 1
    }
else
    printf '%s\n' "$revision" > "$installer/revision.new"
    mv -T "$installer/revision.new" "$installer/revision"
fi

install -d -m 0700 "$runtime" "$state"
# Leave the guard grant and any reservation intact when Kubernetes retries.
put() {
    local src=$1 dest=$2 mode=$3 tmp
    if cmp -s -- "$src" "$dest"; then
        return
    fi
    tmp=$(mktemp "${dest}.XXXXXXXX")
    install -m "$mode" -- "$src" "$tmp"
    mv -T -- "$tmp" "$dest"
}

for helper in single-guest check-runtime.sh worker-readback caa-heartbeat; do
    put "$helper" "$runtime/$helper" 0755
done
put onb17-single-guest.socket /etc/systemd/system/onb17-single-guest.socket 0644
put onb17-single-guest.service /etc/systemd/system/onb17-single-guest.service 0644
systemctl daemon-reload
systemctl enable --now onb17-single-guest.socket
test -S "$runtime/single-guest.sock"

# Kata starts after this init container and loads the fragment when it
# installs its config and restarts containerd.
install -d -m 0755 /etc/containerd/conf.d
put cri-images.toml /etc/containerd/conf.d/92-onb17-cri-images.toml 0644

if [[ -f registry-ca.crt ]] && ! cmp -s registry-ca.crt /usr/local/share/ca-certificates/onb17-registry.crt; then
    install -m 0644 registry-ca.crt /usr/local/share/ca-certificates/onb17-registry.crt
    update-ca-certificates
fi

reference=$(jq -er .reference caa-image.json)
digest=$(jq -er .digest caa-image.json)
[[ $reference == localhost/execution-proof/caa:stock && $digest =~ ^sha256:[0-9a-f]{64}$ ]]
canonical="${reference%:*}@$digest"
check_image() {
    ctr --namespace k8s.io images ls | awk -v ref="$1" -v d="$digest" \
        '$1 == ref && $3 == d { found = 1 } END { exit !found }'
}
if ! check_image "$canonical"; then
    bash import-caa.sh caa-linux-amd64.oci.tar caa-build-receipt.json caa-image.json
    ctr --namespace k8s.io images tag "$reference@$digest" "$canonical"
fi
ctr --namespace k8s.io images label "$canonical" io.cri-containerd.image=managed
check_image "$canonical"
crictl --image-endpoint unix:///run/containerd/containerd.sock inspecti "$canonical" >/dev/null

if [[ -f worker-access.json ]]; then
    ip=$(python3 -c 'from ipaddress import IPv4Address; import sys; print(IPv4Address(sys.argv[1]))' "$2")
    access=/var/lib/onb17-worker-access
    if ! id onb17-worker >/dev/null 2>&1; then
        useradd --system --no-create-home --home-dir "$access" --shell /bin/sh onb17-worker
    fi
    getent passwd onb17-worker | grep -Eq ":$access:/bin/sh$"
    install -d -m 0755 "$access" /run/sshd
    test -s /etc/ssh/ssh_host_ed25519_key
    put worker-access.py "$access/worker-access.py" 0500
    put worker-access.json "$access/access.json" 0600
    put onb17-worker-access.service /etc/systemd/system/onb17-worker-access.service 0644
    jq -er .key worker-access.json > authorized_keys
    put authorized_keys "$access/authorized_keys" 0644
    cat > sshd_config <<CONFIG
AddressFamily inet
ListenAddress $ip
Port 2222
HostKey /etc/ssh/ssh_host_ed25519_key
PidFile /run/onb17-worker-sshd.pid
AuthorizedKeysFile $access/authorized_keys
AllowUsers onb17-worker
AuthenticationMethods publickey
UsePAM yes
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin no
DisableForwarding yes
PermitTTY no
PermitUserRC no
ForceCommand /usr/bin/sudo -n -- $access/worker-access.py
CONFIG
    put sshd_config "$access/sshd_config" 0600
    cat > sudoers <<SUDO
Defaults:onb17-worker env_keep += "SSH_ORIGINAL_COMMAND"
onb17-worker ALL=(root) NOPASSWD: $access/worker-access.py ""
SUDO
    visudo -c -f sudoers >/dev/null
    put sudoers /etc/sudoers.d/onb17-worker 0440
    /usr/sbin/sshd -t -f "$access/sshd_config"
    systemctl daemon-reload
    systemctl enable --now onb17-worker-access.service
fi

echo "worker payload installed: $revision"
