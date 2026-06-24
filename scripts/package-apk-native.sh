#!/usr/bin/env bash
set -euo pipefail

# Build a real native Alpine APK with abuild and install it with apk add.
#
# Unlike scripts/package-apk-smoke.sh (which validates the package FORMAT on any
# POSIX host), this script requires a genuine Alpine environment with abuild and
# apk, produces a real signed .apk via `abuild -r`, installs it with `apk add`,
# and runs the installed binaries as a post-install smoke. It closes the
# packaging environment gap that a typical development host cannot: native APK build +
# install execution.

export PATH="$HOME/.cargo/bin:/root/.cargo/bin:$PATH"

usage() {
  cat <<'USAGE'
Usage: scripts/package-apk-native.sh [OPTIONS]

Build, install (apk add), and smoke-test a real native Alpine APK.

Requires an Alpine environment with: abuild, apk, cargo, a musl Rust target.

Options:
  --target <triple>    musl Rust target. Defaults to x86_64-unknown-linux-musl.
  --output-dir <path>  Work/output directory. Defaults to /tmp/zuicity-apk-native.
  --version <version>  Version string. Defaults to Cargo workspace version.
  --skip-build         Reuse an existing release build for the target.
  -h, --help           Print this help.
USAGE
}

repo_root() {
  local script_dir
  script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  cd "$script_dir/.." && pwd
}

cargo_workspace_version() {
  python3 - <<'PY'
from pathlib import Path
for line in Path('Cargo.toml').read_text().splitlines():
    if line.strip().startswith('version = '):
        print(line.split('=', 1)[1].strip().strip('"'))
        raise SystemExit(0)
raise SystemExit('workspace version not found')
PY
}

require_tool() {
  command -v "$1" >/dev/null 2>&1 || { echo "missing required tool: $1" >&2; exit 2; }
}

normalize_apk_version() {
  # abuild rejects any pkgver that is not strictly numeric and dot-separated,
  # so reduce the raw version to its leading digits(.digits)* core.
  local raw numeric
  raw="$1"
  numeric="$(printf '%s' "$raw" \
    | sed -E 's/[^0-9]+/./g; s/^\.+//; s/\.+$//; s/\.+/./g' \
    | grep -oE '^[0-9]+(\.[0-9]+)*' || true)"
  [ -n "$numeric" ] || numeric="0.0.0"
  printf '%s\n' "$numeric"
}

apk_arch_for_target() {
  case "$1" in
    x86_64-unknown-linux-musl) printf 'x86_64\n' ;;
    aarch64-unknown-linux-musl) printf 'aarch64\n' ;;
    *) echo "unsupported native APK target: $1" >&2; exit 2 ;;
  esac
}

target="x86_64-unknown-linux-musl"
output_dir="/tmp/zuicity-apk-native"
version=""
skip_build=0
while [ "$#" -gt 0 ]; do
  case "$1" in
    --target) target="$2"; shift 2 ;;
    --output-dir) output_dir="$2"; shift 2 ;;
    --version) version="$2"; shift 2 ;;
    --skip-build) skip_build=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done

require_tool abuild
require_tool apk
require_tool cargo
require_tool python3
require_tool sed

root="$(repo_root)"
cd "$root"
case "$output_dir" in /*) ;; *) output_dir="$root/$output_dir" ;; esac

version="${version:-$(cargo_workspace_version)}"
apk_version="$(normalize_apk_version "$version")"
apk_arch="$(apk_arch_for_target "$target")"

build_dir="$output_dir/build"
aports="$output_dir/aports/zuicity"
mkdir -p "$build_dir" "$aports"

# 1. Build static musl release binaries.
if [ "$skip_build" -eq 0 ]; then
  rustup target add "$target" >/dev/null 2>&1 || true
  RUSTFLAGS="-C target-feature=+crt-static" cargo build --release --target "$target" \
    -p zuicity-cli --bins
fi
bin_dir="target/$target/release"
for bin in zuicity-client zuicity-server; do
  [ -x "$bin_dir/$bin" ] || { echo "missing release binary: $bin_dir/$bin" >&2; exit 1; }
  install -m 0755 "$bin_dir/$bin" "$build_dir/$bin"
done

# 2. Generate an abuild packager key if absent.
export PACKAGER_PRIVKEY="${PACKAGER_PRIVKEY:-$output_dir/keys/zuicity.rsa}"
mkdir -p "$(dirname "$PACKAGER_PRIVKEY")"
if [ ! -f "$PACKAGER_PRIVKEY" ]; then
  abuild-keygen -a -n -i >/dev/null 2>&1 || abuild-keygen -a -n >/dev/null 2>&1 || true
  # abuild-keygen writes to ~/.abuild; locate the generated key.
  genkey="$(ls -1 "$HOME"/.abuild/*.rsa 2>/dev/null | head -1 || true)"
  if [ -n "$genkey" ]; then
    PACKAGER_PRIVKEY="$genkey"
  fi
fi

# 3. Stage source tarball + APKBUILD.
src_tar="$output_dir/zuicity-$apk_version.tar.gz"
( cd "$build_dir" && tar -czf "$src_tar" zuicity-client zuicity-server )

cat >"$aports/APKBUILD" <<APKBUILD
# Maintainer: Zuicity Rust maintainers <noreply@github.com>
pkgname=zuicity
pkgver=$apk_version
pkgrel=1
pkgdesc="Rust port of Zuicity"
url="https://github.com/teracoot/zuicity"
arch="$apk_arch"
license="AGPL-3.0-only"
depends="ca-certificates"
options="!check !strip"
source="zuicity-\$pkgver.tar.gz"
builddir="\$srcdir"

package() {
  install -Dm0755 "\$srcdir/zuicity-client" "\$pkgdir/usr/bin/zuicity-client"
  install -Dm0755 "\$srcdir/zuicity-server" "\$pkgdir/usr/bin/zuicity-server"
}
APKBUILD

cp "$src_tar" "$aports/"

# 4. Build the real .apk with abuild.
export REPODEST="$output_dir/packages"
mkdir -p "$REPODEST"
(
  cd "$aports"
  abuild checksum
  abuild -r
)

apk_file="$(find "$REPODEST" -name 'zuicity-*.apk' | head -1)"
[ -n "$apk_file" ] || { echo "abuild produced no .apk" >&2; exit 1; }
echo "built_apk=$apk_file"

# 5. Real install with apk add (requires root). When run unprivileged (e.g. the
#    abuild build user), stop after building and let the caller install as root.
if [ "$(id -u)" -ne 0 ]; then
  echo "not root: skipping apk add install; built package at $apk_file"
  manifest="$output_dir/apk-native-manifest.txt"
  cat >"$manifest" <<MANIFEST
version=$version
apk_version=$apk_version
target=$target
apk_arch=$apk_arch
apk_file=$apk_file
installed=deferred-to-root-caller
MANIFEST
  printf 'native_apk=%s\n' "$apk_file"
  printf 'manifest=%s\n' "$manifest"
  exit 0
fi

apk add --allow-untrusted "$apk_file"

# 6. Post-install run smoke against the installed binaries.
client_version="$output_dir/installed-client-version.txt"
server_version="$output_dir/installed-server-version.txt"
/usr/bin/zuicity-client -v >"$client_version" 2>&1
/usr/bin/zuicity-server -v >"$server_version" 2>&1
apk info -e zuicity >/dev/null || { echo "apk does not report zuicity installed" >&2; exit 1; }

manifest="$output_dir/apk-native-manifest.txt"
cat >"$manifest" <<MANIFEST
version=$version
apk_version=$apk_version
target=$target
apk_arch=$apk_arch
apk_file=$apk_file
client_version=$client_version
server_version=$server_version
installed=$(apk info -e zuicity)
MANIFEST

printf 'native_apk=%s\n' "$apk_file"
printf 'manifest=%s\n' "$manifest"
printf 'installed_client=%s\n' "$(head -1 "$client_version")"
printf 'installed_server=%s\n' "$(head -1 "$server_version")"
