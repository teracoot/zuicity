#!/usr/bin/env bash
set -euo pipefail

export PATH="$HOME/.cargo/bin:/root/.cargo/bin:$PATH"

usage() {
  cat <<'USAGE'
Usage: scripts/package-release.sh [OPTIONS]

Stage a local Zuicity Rust release archive with upstream-style assets and digests.

Options:
  --target <triple>      Rust target triple. Defaults to rustc host triple.
  --output-dir <path>    Output directory. Defaults to /tmp/zuicity-package.
  --version <version>    Version string used for build metadata and manifest output. Defaults to Cargo workspace version.
  --friendly-name <name> Override the release asset platform name for variants sharing a target triple.
  --skip-build           Reuse existing release binaries instead of running cargo build.
  --skip-smoke           Do not run staged binaries. Required for non-host cross-target packages.

Environment:
   CARGO_BUILD_TOOL       Build command to use, usually cargo or cross. Defaults to cargo.
   CARGO_BUILD_FLAGS      Extra flags passed after the cargo/cross build subcommand.
   -h, --help             Print this help.
USAGE
}

repo_root() {
  local script_dir
  script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  cd "$script_dir/.." && pwd
}

host_triple() {
  rustc -vV | awk '/^host: / { print $2 }'
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
  command -v "$1" >/dev/null 2>&1 || {
    echo "missing required tool: $1" >&2
    exit 2
  }
}

validate_friendly_name() {
  [[ "$1" =~ ^[A-Za-z0-9._-]+$ ]] || {
    echo "invalid friendly name: $1" >&2
    exit 2
  }
}

target=""
output_dir="/tmp/zuicity-package"
version=""
friendly_name_override=""
skip_build=0
skip_smoke=0
while [ "$#" -gt 0 ]; do
  case "$1" in
    --target)
      [ "$#" -ge 2 ] || { echo "--target requires a value" >&2; exit 2; }
      target="$2"
      shift 2
      ;;
    --output-dir)
      [ "$#" -ge 2 ] || { echo "--output-dir requires a value" >&2; exit 2; }
      output_dir="$2"
      shift 2
      ;;
    --version)
      [ "$#" -ge 2 ] || { echo "--version requires a value" >&2; exit 2; }
      version="$2"
      shift 2
      ;;
    --friendly-name)
      [ "$#" -ge 2 ] || { echo "--friendly-name requires a value" >&2; exit 2; }
      friendly_name_override="$2"
      shift 2
      ;;
    --skip-build)
      skip_build=1
      shift
      ;;
    --skip-smoke)
      skip_smoke=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

root="$(repo_root)"
cd "$root"
case "$output_dir" in
  /*) ;;
  *) output_dir="$root/$output_dir" ;;
esac
build_tool="${CARGO_BUILD_TOOL:-cargo}"
build_flags=()
# zigbuild produces portable Linux binaries linked against an old glibc floor
# (default 2.17) via cargo-zigbuild. The cargo subcommand is `cargo zigbuild`,
# the required tool is `cargo`, and the target triple carries a `.<glibc>` suffix
# only while building; output paths use the bare triple.
zigbuild_glibc="${ZIGBUILD_GLIBC:-2.17}"
if [ "$build_tool" = "zigbuild" ]; then
  build_command=(cargo zigbuild)
  require_tool cargo
  require_tool cargo-zigbuild
else
  build_command=("$build_tool" build)
  require_tool "$build_tool"
fi
if [ -n "${CARGO_BUILD_FLAGS:-}" ]; then
  read -r -a build_flags <<< "$CARGO_BUILD_FLAGS"
  build_command+=("${build_flags[@]}")
fi
require_tool rustc
require_tool jq
require_tool zip
require_tool md5sum
require_tool sha1sum
require_tool sha256sum
require_tool sha512sum
require_tool install

target="${target:-$(host_triple)}"
version="${version:-$(cargo_workspace_version)}"
if [ -n "$friendly_name_override" ]; then
  friendly_name="$friendly_name_override"
else
  friendly_name="$(jq -r --arg target "$target" '.[$target].friendlyName // empty' install/friendly-filenames.json)"
  if [ -z "$friendly_name" ]; then
    friendly_name="${target//_/-}"
  fi
fi
validate_friendly_name "$friendly_name"

if [ "$skip_build" -eq 0 ]; then
  if [ "$build_tool" = "zigbuild" ]; then
    AWS_LC_SYS_NO_JITTER_ENTROPY=1 ZUICITY_VERSION="$version" VERSION="$version" \
      "${build_command[@]}" --release -p zuicity-cli --bins \
      --target "$target.$zigbuild_glibc"
  elif [ "$build_tool" = "cargo" ] && [ "$target" = "$(host_triple)" ]; then
    ZUICITY_VERSION="$version" VERSION="$version" "${build_command[@]}" --release -p zuicity-cli --bins
  else
    ZUICITY_VERSION="$version" VERSION="$version" "${build_command[@]}" --release -p zuicity-cli --bins --target "$target"
  fi
fi

bin_dir="target/release"
if [ "$target" != "$(host_triple)" ] || [ "$build_tool" = "zigbuild" ]; then
  bin_dir="target/$target/release"
fi
client_bin="$bin_dir/zuicity-client"
server_bin="$bin_dir/zuicity-server"
case "$target" in
  *windows*)
    client_bin="$client_bin.exe"
    server_bin="$server_bin.exe"
    ;;
esac
[ -x "$client_bin" ] || { echo "missing executable $client_bin" >&2; exit 1; }
[ -x "$server_bin" ] || { echo "missing executable $server_bin" >&2; exit 1; }

rm -rf "$output_dir"
mkdir -p "$output_dir/build"
install -m 0755 "$client_bin" "$output_dir/build/$(basename "$client_bin")"
install -m 0755 "$server_bin" "$output_dir/build/$(basename "$server_bin")"
install -m 0644 install/example-client.json "$output_dir/build/example-client.json"
install -m 0644 install/example-server.json "$output_dir/build/example-server.json"
if [[ "$target" == *linux* ]]; then
  install -m 0644 install/zuicity-client.service "$output_dir/build/zuicity-client.service"
  install -m 0644 install/zuicity-server.service "$output_dir/build/zuicity-server.service"
fi

if [ "$skip_smoke" -eq 0 ]; then
  "$output_dir/build/$(basename "$client_bin")" -v >/dev/null
  "$output_dir/build/$(basename "$server_bin")" -v >/dev/null
fi

archive="$output_dir/zuicity-$friendly_name.zip"
(
  cd "$output_dir/build"
  zip -9qr "$archive" .
)
{
  md5sum "$archive"
  sha1sum "$archive"
  sha256sum "$archive"
  sha512sum "$archive"
} >"$archive.dgst"
sha256sum "$archive" >"$archive.sha256"
manifest="$output_dir/manifest.txt"
release_manifest="$output_dir/zuicity-$friendly_name.manifest.txt"
cat >"$manifest" <<MANIFEST
version=$version
target=$target
friendly_name=$friendly_name
build_tool=$build_tool
smoke_skipped=$skip_smoke
archive=$archive
archive_dgst=$archive.dgst
archive_sha256=$archive.sha256
MANIFEST
cp "$manifest" "$release_manifest"

printf 'release_dir=%s\n' "$output_dir"
printf 'archive=%s\n' "$archive"
printf 'digest=%s\n' "$archive.dgst"
printf 'sha256=%s\n' "$archive.sha256"
