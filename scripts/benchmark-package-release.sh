#!/usr/bin/env bash
set -euo pipefail

export PATH="$HOME/.cargo/bin:/root/.cargo/bin:$PATH"

usage() {
  cat <<'USAGE'
Usage: scripts/benchmark-package-release.sh [OPTIONS]

Measure release packaging automation time and artifact sizes.

Options:
  --target <triple>      Rust target triple. Defaults to rustc host triple.
  --output-dir <path>    Package output directory. Defaults to /tmp/zuicity-package-benchmark.
  --log-dir <path>       Benchmark log directory. Defaults to target/zuicity-logs/packaging-benchmark.
  --version <version>    Version string passed to package-release.sh.
  --skip-build           Reuse existing release binaries and measure packaging/staging only.
  --skip-smoke           Pass through to package-release.sh for non-host packages.
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

require_tool() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "missing required tool: $1" >&2
    exit 2
  }
}

target=""
output_dir="/tmp/zuicity-package-benchmark"
log_dir=""
version="packaging-benchmark"
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
    --log-dir)
      [ "$#" -ge 2 ] || { echo "--log-dir requires a value" >&2; exit 2; }
      log_dir="$2"
      shift 2
      ;;
    --version)
      [ "$#" -ge 2 ] || { echo "--version requires a value" >&2; exit 2; }
      version="$2"
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
require_tool rustc
require_tool stat
require_tool date

target="${target:-$(host_triple)}"
log_dir="${log_dir:-$root/target/zuicity-logs/packaging-benchmark}"
mkdir -p "$log_dir"
release_log="$log_dir/package-release-command.log"
summary="$log_dir/package-release-benchmark.txt"

args=(--target "$target" --output-dir "$output_dir" --version "$version")
if [ "$skip_build" -eq 1 ]; then
  args+=(--skip-build)
fi
if [ "$skip_smoke" -eq 1 ]; then
  args+=(--skip-smoke)
fi

start_ms=$(date +%s%3N)
set +e
scripts/package-release.sh "${args[@]}" >"$release_log" 2>&1
rc=$?
set -e
if [ "$rc" -ne 0 ]; then
  printf 'package_release_rc=%s
release_log=%s
' "$rc" "$release_log" >"$summary"
  exit "$rc"
fi
end_ms=$(date +%s%3N)
elapsed_ms=$((end_ms - start_ms))

archive="$(find "$output_dir" -maxdepth 1 -type f -name '*.zip' | sort | head -n 1)"
[ -n "$archive" ] || { echo "missing release archive in $output_dir" >&2; exit 1; }
manifest="$output_dir/manifest.txt"
dgst="$archive.dgst"
sha256="$archive.sha256"

{
  printf 'target=%s
' "$target"
  printf 'version=%s
' "$version"
  printf 'skip_build=%s
' "$skip_build"
  printf 'skip_smoke=%s
' "$skip_smoke"
  printf 'elapsed_millis=%s
' "$elapsed_ms"
  printf 'output_dir=%s
' "$output_dir"
  printf 'archive=%s
' "$archive"
  printf 'archive_bytes=%s
' "$(stat -c %s "$archive")"
  printf 'digest_bytes=%s
' "$(stat -c %s "$dgst")"
  printf 'sha256_bytes=%s
' "$(stat -c %s "$sha256")"
  printf 'manifest_bytes=%s
' "$(stat -c %s "$manifest")"
  printf 'release_log=%s
' "$release_log"
} >"$summary"
cat "$summary"
