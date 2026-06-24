#!/usr/bin/env bash
# Three-way juicity benchmark orchestrator.
#
# Runs the 4-metric benchmark for each implementation across rotated repetitions
# over a real two-namespace veth path, aggregates medians, and renders a chart.
#
# Requires root (creates network namespaces). Requires: python3, openssl, ip.
#
# Usage:
#   sudo run-comparison.sh \
#     --rust-dir   <dir with zuicity-client/zuicity-server> \
#     --go-dir     <dir> \
#     --other-dir  <dir> \
#     [--reps 5] [--iters 60] [--out-dir <dir>]
set -u
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"

REPS=5
ITERS=60
RUST_DIR=""
GO_DIR=""
OTHER_DIR=""
OUT_DIR=""

while [ $# -gt 0 ]; do
  case "$1" in
    --rust-dir) RUST_DIR="$2"; shift 2 ;;
    --go-dir) GO_DIR="$2"; shift 2 ;;
    --other-dir) OTHER_DIR="$2"; shift 2 ;;
    --reps) REPS="$2"; shift 2 ;;
    --iters) ITERS="$2"; shift 2 ;;
    --out-dir) OUT_DIR="$2"; shift 2 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

if [ "$(id -u)" -ne 0 ]; then
  echo "must run as root (creates net namespaces)" >&2
  exit 1
fi
for tag in rust go juicityrs; do
  d="$(bin_for "$tag")"
  [ -n "$d" ] || { echo "missing --rust-dir/--go-dir/--other-dir" >&2; exit 2; }
  [ -x "$d/$(client_name_for "$tag")" ] && [ -x "$d/$(server_name_for "$tag")" ] || {
    echo "binaries not found/executable in: $d" >&2; exit 2; }
done

STAMP="$(date +%Y%m%d-%H%M%S)"
OUT_DIR="${OUT_DIR:-$REPO/benchmark-results/$STAMP}"
mkdir -p "$OUT_DIR"
RESULTS="$OUT_DIR/results.jsonl"
: > "$RESULTS"
echo "output: $OUT_DIR"

bin_for() {
  case "$1" in
    rust) echo "$RUST_DIR" ;;
    go) echo "$GO_DIR" ;;
    juicityrs) echo "$OTHER_DIR" ;;
  esac
}

client_name_for() {
  case "$1" in
    rust) echo "zuicity-client" ;;
    *) echo "juicity-client" ;;
  esac
}

server_name_for() {
  case "$1" in
    rust) echo "zuicity-server" ;;
    *) echo "juicity-server" ;;
  esac
}

# Rotate implementation order across reps to cancel ordering bias.
orders=("rust go juicityrs" "go juicityrs rust" "juicityrs rust go" \
        "rust juicityrs go" "go rust juicityrs")

for rep in $(seq 1 "$REPS"); do
  idx=$(( (rep - 1) % ${#orders[@]} ))
  for tag in ${orders[$idx]}; do
    dir="$(bin_for "$tag")"
    log="$OUT_DIR/${rep}-${tag}.log"
    echo "RUN rep=$rep tag=$tag"
    timeout 8m bash "$HERE/bench-one.sh" "$tag" \
      "$dir/$(client_name_for "$tag")" "$dir/$(server_name_for "$tag")" "$ITERS" >"$log" 2>&1
    grep -h '"tag"' "$log" >> "$RESULTS" 2>/dev/null || true
  done
done

echo "collected $(wc -l < "$RESULTS") result lines"

if [ -s "$RESULTS" ]; then
  python3 "$REPO/scripts/render-benchmark-chart.py" "$RESULTS" \
    --out-dir "$OUT_DIR" \
    --title "zuicity QUIC proxy: performance comparison"
  echo "chart: $OUT_DIR/benchmark-chart.svg (and .png if a converter is present)"
fi
echo "DONE $OUT_DIR"
