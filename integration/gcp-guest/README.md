# Build the GCP PodVM disk

Build on x86-64 GNU/Linux. The commands below use Ubuntu 24.04, Python 3.11 or
later, the Rust toolchains selected by the checkouts, and Go 1.26.7 or later.
The output is a local sparse-disk import archive. The deployment must prepare
the signed boot manifest and references for that image before booting it.

## 1. Check out the four repositories

Set `EPP_URL`, `GC_URL`, `KATA_URL`, and `TRUSTEE_URL` to the clone sources
and the corresponding `*_REF` variables to the supplied commit IDs. Use the
directories below because the component Cargo manifests use sibling path dependencies.
The refs must include the GCP preparation and launch changes. Git bundles also
work as clone sources if the build refs are distributed privately.

```sh
mkdir podvm-workspace
cd podvm-workspace
git clone "$EPP_URL" execution-proof-prototype
git clone "$GC_URL" guest-components-prepared-dev
git clone "$KATA_URL" kata-launch-dev
git clone "$TRUSTEE_URL" trustee-launch-dev
git -C execution-proof-prototype checkout --detach "$EPP_REF"
git -C guest-components-prepared-dev checkout --detach "$GC_REF"
git -C kata-launch-dev checkout --detach "$KATA_REF"
git -C trustee-launch-dev checkout --detach "$TRUSTEE_REF"
root=$PWD
mkdir -p build/bin inputs/public
```

Guest Components and Kata supply the guest binaries. EPP supplies the bootstrap,
management relay and disk builder. Use the matching Trustee checkout when
[building the trusted service](../gcp-trusted-services/README.md) for deployment.

## 2. Prepare the build tools and Linux source

Install the system build dependencies on the build host:

```sh
sudo apt install build-essential binutils bc bison flex libelf-dev libssl-dev \
  libclang-dev cmake pkg-config protobuf-compiler python3 curl ca-certificates \
  autoconf automake libtool gdisk dosfstools mtools tar gzip libseccomp2
export PATH="/usr/sbin:$PATH"
```

Fetch the Linux source matching [the shipped TDX profile](gcp-tdx.defconfig)
and build the EROFS utilities with static linking for the guest helper.

```sh
linux_commit=028ef9c96e96197026887c0f092424679298aae8
curl -fL "https://codeload.github.com/torvalds/linux/tar.gz/$linux_commit" \
  -o build/linux.tar.gz
printf '%s  %s\n' \
  50b7771fe50fb04cbc5342244eac7b2ff2dade4567d6658568a57bd57708855db5b80e958083ab7bb441d584cbc7d47c \
  build/linux.tar.gz | sha384sum --check && tar -xf build/linux.tar.gz -C build

curl -fL https://codeload.github.com/erofs/erofs-utils/tar.gz/refs/tags/v1.8.10 \
  -o build/erofs-utils.tar.gz
printf '%s  %s\n' \
  05eb4edebe11decce6ecb34e98d2f80c8cd283c2f2967d8ba7efd58418570514 \
  build/erofs-utils.tar.gz | sha256sum --check && tar -xf build/erofs-utils.tar.gz -C build
(
  cd build/erofs-utils-1.8.10
  ./autogen.sh
  ./configure --prefix="$root/build/erofs" --disable-shared \
    --disable-lz4 --disable-lzma --without-zlib --without-libzstd \
    --without-xxhash --without-uuid
  make -j4 LDFLAGS=-all-static
  make install LDFLAGS=-all-static
)
```

Keep the selected loader, glibc, GCC runtime and `libseccomp.so.2` from the same
compatible x86-64 GNU userspace as the guest binaries. The example file list
uses the Ubuntu multiarch paths. Check the `DT_NEEDED` entries with `readelf -Wd`
and include any additional shared libraries in the file list. The guest
`mkfs.erofs` helper must be a static executable.

## 3. Build the guest components

From `podvm-workspace`, build the two Rust guest roles, the Go relay, the
static bootstrap, and the boot input validator.

```sh
(
  cd guest-components-prepared-dev
  OPENSSL_STATIC=1 CARGO_TARGET_DIR="$root/build/cdh-target" \
    cargo build --release --locked --target x86_64-unknown-linux-gnu \
      -p confidential-data-hub --no-default-features \
      --features gcp-production --bin gcp-proof-preparation
)
cp build/cdh-target/x86_64-unknown-linux-gnu/release/gcp-proof-preparation build/bin/
(
  cd kata-launch-dev/src/agent
  CARGO_TARGET_DIR="$root/build/kata-target" \
    cargo build --release --locked --target x86_64-unknown-linux-gnu \
      --no-default-features --features gcp-proof-startup --bin kata-agent-gcp-proof
)
cp build/kata-target/x86_64-unknown-linux-gnu/release/kata-agent-gcp-proof build/bin/
(
  cd execution-proof-prototype/integration/management-relay
  CGO_ENABLED=0 go build -trimpath -o "$root/build/bin/management-relay" ./cmd/management-relay
)
python3 execution-proof-prototype/integration/gcp-guest/build-init.py \
  --crypto-archive /usr/lib/x86_64-linux-gnu/libcrypto.a \
  --crypto-includes /usr/include --output build/bootstrap
cp build/bootstrap/init build/bin/
(
  cd execution-proof-prototype
  CARGO_TARGET_DIR="$root/build/epp-target" cargo build --locked \
    -p execution-proof-handoff --features gcp-startup --example gcp-build-inputs
)
```

## 4. Select the public boot inputs

Copy the [file list](files.example.json) and the
[boot configuration template](boot-config.example.json).

```sh
cp execution-proof-prototype/integration/gcp-guest/files.example.json inputs/files.json
cp execution-proof-prototype/integration/gcp-guest/boot-config.example.json inputs/config.json
```

Each `source` is a host filename. Relative filenames resolve against the file
list's directory. Each `path` is the absolute filename inside the guest. Keep
the resolver out of the list so the packager can add its pinned bytes.

Generate the fixed RPC and workload policy bytes from the same checkout.
The guest checks their exact hashes.

```sh
validator=build/epp-target/debug/examples/gcp-build-inputs
"$validator" --rpc-policy > inputs/public/rpc.json
"$validator" --workload-policy > inputs/public/workload.json
```

Fill the template with your deployment's Authority and KBS identities,
endpoints, public roots and policy hashes. The five Ed25519 public-key fields
are arrays of 32 byte values. Put the public policies, registry and KMS
selection, DNS configuration and relay certificates under `inputs/public`
using the filenames in the file list. Use a DNS resolver reachable from
the guest network in `resolv.conf`. Compute the `*_sha384` fields over the
exact selected file bytes. For `client_leaf_der_sha384` hash the relay client's
DER certificate. Keep signing keys, TLS private keys and service-account
credentials outside the image inputs. [Boot config schema](../../contract/src/gcp_artifact.rs)
· [Trusted service configuration](../gcp-trusted-services/README.md#configuration)
· [Relay configuration](../management-relay/README.md)

Use the immutable configuration section of
`guest-components-prepared-dev/confidential-data-hub/gcp-production.md` for
`preparation.json`. Match the KBS policy, credential scope, registry identity and
KMS key version to the same deployment. Match the public relay certificate,
client CA and client leaf hash in the boot configuration to `relay.json`.

The Ubuntu resolver from `libseccomp2` version
`2.5.5-1ubuntu3.1` has the digest shown below. For a different compatible build,
select its package and expected SHA-384 explicitly.

## 5. Assemble the disk

```sh
seccomp=/lib/x86_64-linux-gnu/libseccomp.so.2
seccomp_sha384=a6b846f13764ea28763427a5a8d3c7d6a8c79b7a1e601e31d44d512c9702861fc7f3641a88c796772b7d649e79f4ab57
python3 execution-proof-prototype/integration/gcp-guest/build-podvm.py \
  --files inputs/files.json --config inputs/config.json \
  --validator "$validator" \
  --libseccomp "$seccomp" --libseccomp-sha384 "$seccomp_sha384" \
  --erofs-tools build/erofs/bin --kernel-source "build/linux-$linux_commit" \
  --jobs 4 --output build/podvm
```

The builder stages the selected files and validates the boot config and producer
core. It then calls [package-rootfs.py](package-rootfs.py), which adds the
resolver and produces `tcb.tar`. The next steps build and read back EROFS,
embed the checked initramfs in the EFI kernel, and verify the GPT disk and the
sparse archive. Each run takes a new output directory. Kernel output is under
`kernel/`, with diagnostics in `kernel/build.log`.

Use `build/podvm/disk/disk.tar.gz` as the disk archive.
`disk/import-manifest.json` records its digest. Use `payload/producer-core.json`
and `kernel/build-receipt.json` with the original boot configuration when
preparing the signed boot artifacts for that disk.
