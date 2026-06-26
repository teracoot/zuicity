#!/usr/bin/env bash
# Build portable Linux x86_64 binaries that run on old glibc (>= 2.17), so the
# release works on Debian/CentOS/RHEL and other long-lived distributions.
#
# Requires: rustup target x86_64-unknown-linux-gnu, zig (>=0.13), cargo-zigbuild.
# Install zig + cargo-zigbuild once:
#   pip3 install ziglang==0.13.0   # or download the zig tarball onto PATH
#   cargo install --locked cargo-zigbuild
#
# Output: target/x86_64-unknown-linux-gnu/release/{zuicity-server,zuicity-client}
set -euo pipefail

TARGET="x86_64-unknown-linux-gnu.2.17"
OUT_TARGET="x86_64-unknown-linux-gnu"

if ! command -v zig >/dev/null 2>&1; then
  if python3 -m ziglang version >/dev/null 2>&1; then
    echo "warning: no 'zig' on PATH; using 'python3 -m ziglang' shim" >&2
  else
    echo "error: zig not found (install ziglang via pip or the zig tarball)" >&2
    exit 1
  fi
fi

cd "$(dirname "$0")/.."

AWS_LC_SYS_NO_JITTER_ENTROPY=1 \
  cargo zigbuild --release --target "$TARGET" --bin zuicity-server --bin zuicity-client

bin_dir="target/${OUT_TARGET}/release"
echo "=== built portable binaries ==="
ls -lh "$bin_dir/zuicity-server" "$bin_dir/zuicity-client"

echo "=== max glibc symbol required (must be <= 2.17) ==="
for b in zuicity-server zuicity-client; do
  max="$(objdump -T "$bin_dir/$b" 2>/dev/null | grep -oE 'GLIBC_[0-9]+\.[0-9]+' | sort -uV | tail -1)"
  echo "  $b -> $max"
done
