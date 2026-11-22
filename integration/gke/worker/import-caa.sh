#!/usr/bin/env bash
set -euo pipefail

archive=${1:?expected OCI archive}
receipt=${2:?expected CAA build receipt}
image=${3:?expected rendered caa-image.json}
digest=$(jq -er '.manifest_digest | select(test("^sha256:[a-f0-9]{64}$"))' "$receipt")
expected_sha=$(jq -er '.archive_sha256 | select(test("^[a-f0-9]{64}$"))' "$receipt")
reference=$(jq -er '.reference' "$image")
[[ $(jq -er '.digest' "$image") == "$digest" ]]
actual_sha=$(sha256sum < "$archive")
[[ ${actual_sha%% *} == "$expected_sha" ]]

ctr --namespace k8s.io images import --digests "$archive"
target="$reference@$digest"
readback() {
    ctr --namespace k8s.io images ls | awk -v ref="$1" -v digest="$digest" \
        '$1 == ref && $3 == digest { found = 1 } END { exit !found }'
}
if ! readback "$target"; then
    source="$reference"
    if ! readback "$source"; then
        source="$digest"
        readback "$source"
    fi
    ctr --namespace k8s.io images tag "$source" "$target"
fi
readback "$target"
