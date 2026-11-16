#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
destination=${1:-"$root/build/charts"}
if [ -d "$destination" ] && (cd "$destination" && sha256sum --check --status "$root/charts.sha256"); then
    exit 0
fi

mkdir -p "$destination"
staging=$(mktemp -d "$destination/.pull.XXXXXX")
trap 'rm -rf -- "$staging"' EXIT
trap 'exit 1' HUP INT TERM
helm pull oci://ghcr.io/kata-containers/kata-deploy-charts/kata-deploy --version 4.0.0 --destination "$staging"
helm pull oci://ghcr.io/confidential-containers/cloud-api-adaptor/charts/peerpods --version 0.4.0 --destination "$staging"
(cd "$staging" && sha256sum --check "$root/charts.sha256")
mv -- "$staging/kata-deploy-4.0.0.tgz" "$staging/peerpods-0.4.0.tgz" "$destination/"
