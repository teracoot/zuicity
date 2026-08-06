#!/usr/bin/env bash
# Run one isolated TCP benchmark row. Environment selection is owned by
# tcp-gso-suite.py; this script only builds the topology and records the row.
set -euo pipefail

export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

TAG=""
CLIENT=""
SERVER=""
OUT_DIR=""
CPUS=""
SERVER_CPUS=""
CLIENT_CPUS=""
DRIVER_CPUS=""
ECHO_CPUS=""
RTT_SAMPLES=60
THROUGHPUT_SAMPLES=100
THROUGHPUT_BYTES=4194304
WARMUP_TRANSFERS=5
TIMEOUT_SECONDS=120
TRACE_GSO=skip

usage() {
  cat >&2 <<'EOF'
usage: bench-one-tcp.sh --tag TAG --client PATH --server PATH --out-dir DIR
       [--cpus LIST] [--server-cpus LIST] [--client-cpus LIST]
       [--driver-cpus LIST] [--echo-cpus LIST]
       [--rtt-samples N] [--throughput-samples N]
       [--throughput-bytes N] [--warmup-transfers N] [--timeout-seconds N]
       [--trace-gso present|absent|skip]
EOF
}

while (( $# > 0 )); do
  case "$1" in
    --tag) TAG=${2:?}; shift 2 ;;
    --client) CLIENT=${2:?}; shift 2 ;;
    --server) SERVER=${2:?}; shift 2 ;;
    --out-dir) OUT_DIR=${2:?}; shift 2 ;;
    --cpus) CPUS=${2:?}; shift 2 ;;
    --server-cpus) SERVER_CPUS=${2:?}; shift 2 ;;
    --client-cpus) CLIENT_CPUS=${2:?}; shift 2 ;;
    --driver-cpus) DRIVER_CPUS=${2:?}; shift 2 ;;
    --echo-cpus) ECHO_CPUS=${2:?}; shift 2 ;;
    --rtt-samples) RTT_SAMPLES=${2:?}; shift 2 ;;
    --throughput-samples) THROUGHPUT_SAMPLES=${2:?}; shift 2 ;;
    --throughput-bytes) THROUGHPUT_BYTES=${2:?}; shift 2 ;;
    --warmup-transfers) WARMUP_TRANSFERS=${2:?}; shift 2 ;;
    --timeout-seconds) TIMEOUT_SECONDS=${2:?}; shift 2 ;;
    --trace-gso) TRACE_GSO=${2:?}; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown argument: $1" >&2; usage; exit 2 ;;
  esac
done

[[ -n "$TAG" && -n "$CLIENT" && -n "$SERVER" && -n "$OUT_DIR" ]] || {
  usage
  exit 2
}
[[ "$TAG" != *[!A-Za-z0-9._-]* ]] || {
  echo "tag contains unsupported characters: $TAG" >&2
  exit 2
}
case "$TRACE_GSO" in
  present|absent|skip) ;;
  *) echo "--trace-gso must be present, absent, or skip" >&2; exit 2 ;;
esac
ZUICITY_CONGESTION_CONTROL=${BENCH_ZUICITY_CONGESTION_CONTROL:-bbr}
case "$ZUICITY_CONGESTION_CONTROL" in
  bbr|cubic|new_reno) ;;
  *) echo "BENCH_ZUICITY_CONGESTION_CONTROL must be bbr, cubic, or new_reno" >&2; exit 2 ;;
esac
if [[ $(id -u) -ne 0 ]]; then
  echo "bench-one-tcp.sh must run as root" >&2
  exit 1
fi
for value in "$RTT_SAMPLES" "$THROUGHPUT_SAMPLES" "$THROUGHPUT_BYTES"; do
  [[ "$value" =~ ^[1-9][0-9]*$ ]] || { echo "sample values must be positive integers" >&2; exit 2; }
done
[[ "$WARMUP_TRANSFERS" =~ ^[0-9]+$ ]] || {
  echo "warmup transfers must be a non-negative integer" >&2
  exit 2
}
[[ -x "$CLIENT" && -x "$SERVER" ]] || {
  echo "client or server binary is not executable" >&2
  exit 2
}
for preload in "${BENCH_CLIENT_PRELOAD:-}" "${BENCH_SERVER_PRELOAD:-}"; do
  [[ -z "$preload" || -r "$preload" ]] || {
    echo "preload control is not readable: $preload" >&2
    exit 2
  }
done
TCP_DRIVER=${BENCH_TCP_DRIVER:-$HERE/tcp-driver.py}
[[ -f "$TCP_DRIVER" && -f "$HERE/echo-server.py" ]] || {
  echo "benchmark helper is missing" >&2
  exit 2
}
if [[ "$TRACE_GSO" != skip ]]; then
  command -v strace >/dev/null || { echo "strace is required for GSO probes" >&2; exit 2; }
fi

SERVER_CPUS=${SERVER_CPUS:-$CPUS}
CLIENT_CPUS=${CLIENT_CPUS:-$CPUS}
DRIVER_CPUS=${DRIVER_CPUS:-$CPUS}
ECHO_CPUS=${ECHO_CPUS:-$CPUS}
SERVER_AFFINITY=()
CLIENT_AFFINITY=()
DRIVER_AFFINITY=()
ECHO_AFFINITY=()
if [[ -n "$CPUS$SERVER_CPUS$CLIENT_CPUS$DRIVER_CPUS$ECHO_CPUS" ]]; then
  command -v taskset >/dev/null || { echo "taskset is required with --cpus" >&2; exit 2; }
fi
if [[ -n "$SERVER_CPUS" ]]; then
  taskset -c "$SERVER_CPUS" true
  SERVER_AFFINITY=(taskset -c "$SERVER_CPUS")
fi
if [[ -n "$CLIENT_CPUS" ]]; then
  taskset -c "$CLIENT_CPUS" true
  CLIENT_AFFINITY=(taskset -c "$CLIENT_CPUS")
fi
if [[ -n "$DRIVER_CPUS" ]]; then
  taskset -c "$DRIVER_CPUS" true
  DRIVER_AFFINITY=(taskset -c "$DRIVER_CPUS")
fi
if [[ -n "$ECHO_CPUS" ]]; then
  taskset -c "$ECHO_CPUS" true
  ECHO_AFFINITY=(taskset -c "$ECHO_CPUS")
fi
if [[ -n "$CPUS" ]]; then
  taskset -c "$CPUS" true
fi

CAPTURE_DIR="$OUT_DIR/captures/$TAG"
[[ ! -e "$CAPTURE_DIR" ]] || {
  echo "refusing to overwrite capture: $CAPTURE_DIR" >&2
  exit 2
}
mkdir -p "$CAPTURE_DIR"
WORK="$(mktemp -d /tmp/zuicity-tcp-row.XXXXXX)"
SUFFIX="${BASHPID}-${RANDOM}"
NS_SERVER="zuicity-bench-s-$SUFFIX"
NS_CLIENT="zuicity-bench-c-$SUFFIX"
VETH_SERVER="zbs${BASHPID}"
VETH_CLIENT="zbc${BASHPID}"
IP_SERVER=10.210.0.1
IP_CLIENT=10.210.0.2
SERVER_PORT=9443
TARGET_PORT=7000
UDP_TARGET_PORT=7001
FORWARD_PORT=1080
LOG_LEVEL=${BENCH_LOG_LEVEL:-warn}
SERVER_PID=""
CLIENT_PID=""

cleanup() {
  local status=$?
  trap - EXIT INT TERM
  for namespace in "$NS_SERVER" "$NS_CLIENT"; do
    ip netns pids "$namespace" 2>/dev/null | xargs -r kill 2>/dev/null || true
  done
  sleep 0.1
  for namespace in "$NS_SERVER" "$NS_CLIENT"; do
    ip netns pids "$namespace" 2>/dev/null | xargs -r kill -9 2>/dev/null || true
    ip netns del "$namespace" 2>/dev/null || true
  done
  ip link del "$VETH_SERVER" 2>/dev/null || true
  for file in echo.log server.log client.log driver.stderr result.json resources.json merged.json server.json client.json; do
    if [[ -f "$WORK/$file" ]]; then
      install -m 0644 "$WORK/$file" "$CAPTURE_DIR/$file"
    fi
  done
  shopt -s nullglob
  for trace in "$WORK"/*.strace*; do
    install -m 0644 "$trace" "$CAPTURE_DIR/$(basename "$trace")"
  done
  rm -rf "$WORK"
  exit "$status"
}
trap cleanup EXIT INT TERM

status_value() {
  local field=$1 pid=$2
  awk -v field="$field" '$1 == field ":" { print $2; found=1 } END { if (!found) print 0 }' \
    "/proc/$pid/status" 2>/dev/null || printf '0\n'
}

cpu_ticks() {
  awk '{ print $14 + $15 }' "/proc/$1/stat" 2>/dev/null || printf '0\n'
}

ip netns add "$NS_SERVER"
ip netns add "$NS_CLIENT"
ip link add "$VETH_SERVER" type veth peer name "$VETH_CLIENT"
ip link set "$VETH_SERVER" netns "$NS_SERVER"
ip link set "$VETH_CLIENT" netns "$NS_CLIENT"
ip -n "$NS_SERVER" addr add "$IP_SERVER/24" dev "$VETH_SERVER"
ip -n "$NS_CLIENT" addr add "$IP_CLIENT/24" dev "$VETH_CLIENT"
ip -n "$NS_SERVER" link set "$VETH_SERVER" up
ip -n "$NS_CLIENT" link set "$VETH_CLIENT" up
ip -n "$NS_SERVER" link set lo up
ip -n "$NS_CLIENT" link set lo up

openssl req -x509 -newkey rsa:2048 \
  -keyout "$WORK/key.pem" -out "$WORK/cert.pem" -days 1 -nodes \
  -subj /CN=zuicity.local \
  -addext "subjectAltName=DNS:zuicity.local,IP:$IP_SERVER" >/dev/null 2>&1
cat >"$WORK/server.json" <<JSON
{"listen":"$IP_SERVER:$SERVER_PORT","users":{"00000000-0000-0000-0000-000000000099":"bench-password"},"certificate":"$WORK/cert.pem","private_key":"$WORK/key.pem","congestion_control":"$ZUICITY_CONGESTION_CONTROL","log_level":"$LOG_LEVEL"}
JSON
cat >"$WORK/client.json" <<JSON
{"server":"$IP_SERVER:$SERVER_PORT","uuid":"00000000-0000-0000-0000-000000000099","password":"bench-password","sni":"zuicity.local","allow_insecure":true,"congestion_control":"$ZUICITY_CONGESTION_CONTROL","log_level":"$LOG_LEVEL","forward":{"$IP_CLIENT:$FORWARD_PORT/tcp":"$IP_SERVER:$TARGET_PORT"}}
JSON

ip netns exec "$NS_SERVER" "${ECHO_AFFINITY[@]}" \
  python3 "$HERE/echo-server.py" "$IP_SERVER" "$TARGET_PORT" "$UDP_TARGET_PORT" \
  >"$WORK/echo.log" 2>&1 &
ECHO_PID=$!
sleep 0.4

SERVER_COMMAND=("$SERVER" run -c "$WORK/server.json")
CLIENT_COMMAND=("$CLIENT" run -c "$WORK/client.json")
if [[ -n "${BENCH_SERVER_PRELOAD:-}" ]]; then
  SERVER_COMMAND=(env LD_PRELOAD="$BENCH_SERVER_PRELOAD" "${SERVER_COMMAND[@]}")
fi
if [[ -n "${BENCH_CLIENT_PRELOAD:-}" ]]; then
  CLIENT_COMMAND=(env LD_PRELOAD="$BENCH_CLIENT_PRELOAD" "${CLIENT_COMMAND[@]}")
fi
if [[ "$TRACE_GSO" != skip ]]; then
  SERVER_COMMAND=(strace -ff -qq -s 1 -e trace=setsockopt,sendmsg,sendmmsg \
    -o "$WORK/server.strace" "${SERVER_COMMAND[@]}")
  CLIENT_COMMAND=(strace -ff -qq -s 1 -e trace=setsockopt,sendmsg,sendmmsg \
    -o "$WORK/client.strace" "${CLIENT_COMMAND[@]}")
fi

ip netns exec "$NS_SERVER" "${SERVER_AFFINITY[@]}" "${SERVER_COMMAND[@]}" \
  >"$WORK/server.log" 2>&1 &
SERVER_PID=$!
sleep 0.8
kill -0 "$ECHO_PID"
kill -0 "$SERVER_PID"

ip netns exec "$NS_CLIENT" "${CLIENT_AFFINITY[@]}" "${CLIENT_COMMAND[@]}" \
  >"$WORK/client.log" 2>&1 &
CLIENT_PID=$!
sleep 1.2
kill -0 "$CLIENT_PID"

SERVER_BASELINE=$(status_value VmRSS "$SERVER_PID")
CLIENT_BASELINE=$(status_value VmRSS "$CLIENT_PID")
SERVER_PEAK=$SERVER_BASELINE
CLIENT_PEAK=$CLIENT_BASELINE
SERVER_TICKS_BEFORE=$(cpu_ticks "$SERVER_PID")
CLIENT_TICKS_BEFORE=$(cpu_ticks "$CLIENT_PID")

ip netns exec "$NS_CLIENT" "${DRIVER_AFFINITY[@]}" \
  python3 "$TCP_DRIVER" \
    --client-ip "$IP_CLIENT" \
    --forward-port "$FORWARD_PORT" \
    --tag "$TAG" \
    --rtt-samples "$RTT_SAMPLES" \
    --throughput-samples "$THROUGHPUT_SAMPLES" \
    --throughput-bytes "$THROUGHPUT_BYTES" \
    --warmup-transfers "$WARMUP_TRANSFERS" \
    --timeout-seconds "$TIMEOUT_SECONDS" \
  >"$WORK/result.json" 2>"$WORK/driver.stderr" &
DRIVER_PID=$!
while kill -0 "$DRIVER_PID" 2>/dev/null; do
  SERVER_CURRENT=$(status_value VmRSS "$SERVER_PID")
  CLIENT_CURRENT=$(status_value VmRSS "$CLIENT_PID")
  (( SERVER_CURRENT > SERVER_PEAK )) && SERVER_PEAK=$SERVER_CURRENT
  (( CLIENT_CURRENT > CLIENT_PEAK )) && CLIENT_PEAK=$CLIENT_CURRENT
  sleep 0.02
done
set +e
wait "$DRIVER_PID"
DRIVER_STATUS=$?
set -e

SERVER_TICKS_AFTER=$(cpu_ticks "$SERVER_PID")
CLIENT_TICKS_AFTER=$(cpu_ticks "$CLIENT_PID")
SERVER_POST=$(status_value VmRSS "$SERVER_PID")
CLIENT_POST=$(status_value VmRSS "$CLIENT_PID")
SERVER_HWM=$(status_value VmHWM "$SERVER_PID")
CLIENT_HWM=$(status_value VmHWM "$CLIENT_PID")
CLK_TCK=$(getconf CLK_TCK)

UDP_SEGMENT_ATTEMPTS=0
UDP_SEGMENT_SUCCESSES=0
UDP_SEGMENT_CAPABILITY_PROBES=0
TRACE_PASSED=true
if [[ "$TRACE_GSO" != skip ]]; then
  shopt -s nullglob
  TRACE_FILES=("$WORK"/*.strace*)
  if (( ${#TRACE_FILES[@]} > 0 )); then
    TRACE_COUNTS=$(python3 "$HERE/tcp_gso_suite.py" trace-counts "${TRACE_FILES[@]}")
    read -r UDP_SEGMENT_ATTEMPTS UDP_SEGMENT_SUCCESSES UDP_SEGMENT_CAPABILITY_PROBES <<<"$TRACE_COUNTS"
  fi
  if [[ "$TRACE_GSO" == present && "$UDP_SEGMENT_SUCCESSES" -eq 0 ]]; then
    TRACE_PASSED=false
  elif [[ "$TRACE_GSO" == absent && "$UDP_SEGMENT_ATTEMPTS" -ne 0 ]]; then
    TRACE_PASSED=false
  fi
  if [[ "$UDP_SEGMENT_CAPABILITY_PROBES" -ne 0 ]]; then
    TRACE_PASSED=false
  fi
fi

python3 - \
  "$WORK/result.json" "$WORK/resources.json" "$DRIVER_STATUS" "$CLK_TCK" \
  "$SERVER_BASELINE" "$SERVER_PEAK" "$SERVER_HWM" "$SERVER_POST" \
  "$SERVER_TICKS_BEFORE" "$SERVER_TICKS_AFTER" \
  "$CLIENT_BASELINE" "$CLIENT_PEAK" "$CLIENT_HWM" "$CLIENT_POST" \
  "$CLIENT_TICKS_BEFORE" "$CLIENT_TICKS_AFTER" \
  "$TRACE_GSO" "$UDP_SEGMENT_ATTEMPTS" "$UDP_SEGMENT_SUCCESSES" \
  "$UDP_SEGMENT_CAPABILITY_PROBES" \
  "$TRACE_PASSED" "$CPUS" "$SERVER_CPUS" "$CLIENT_CPUS" "$DRIVER_CPUS" \
  "$ECHO_CPUS" <<'PY'
import json
import pathlib
import sys

(
    result_path,
    resources_path,
    driver_status,
    ticks_per_second,
    server_baseline,
    server_peak,
    server_hwm,
    server_post,
    server_ticks_before,
    server_ticks_after,
    client_baseline,
    client_peak,
    client_hwm,
    client_post,
    client_ticks_before,
    client_ticks_after,
    trace_expected,
    udp_segment_attempts,
    udp_segment_successes,
    udp_segment_capability_probes,
    trace_passed,
    cpus,
    server_cpus,
    client_cpus,
    driver_cpus,
    echo_cpus,
) = sys.argv[1:]

ticks_per_second = int(ticks_per_second)


def process_resources(baseline, peak, hwm, post, ticks_before, ticks_after):
    return {
        "baseline_rss_kib": int(baseline),
        "sampled_peak_rss_kib": int(peak),
        "process_peak_hwm_kib": int(hwm),
        "post_rss_kib": int(post),
        "cpu_seconds": round(
            max(0, int(ticks_after) - int(ticks_before)) / ticks_per_second,
            6,
        ),
    }


resources = {
    "cpu_affinity": cpus or None,
    "role_cpu_affinity": {
        "server": server_cpus or None,
        "client": client_cpus or None,
        "driver": driver_cpus or None,
        "echo": echo_cpus or None,
    },
    "clock_ticks_per_second": ticks_per_second,
    "server": process_resources(
        server_baseline,
        server_peak,
        server_hwm,
        server_post,
        server_ticks_before,
        server_ticks_after,
    ),
    "client": process_resources(
        client_baseline,
        client_peak,
        client_hwm,
        client_post,
        client_ticks_before,
        client_ticks_after,
    ),
}
resources["combined_process_peak_hwm_kib"] = (
    resources["server"]["process_peak_hwm_kib"]
    + resources["client"]["process_peak_hwm_kib"]
)
resources["combined_proxy_cpu_seconds"] = round(
    resources["server"]["cpu_seconds"] + resources["client"]["cpu_seconds"],
    6,
)
pathlib.Path(resources_path).write_text(
    json.dumps(resources, sort_keys=True) + "\n", encoding="utf-8"
)

try:
    result = json.loads(pathlib.Path(result_path).read_text(encoding="utf-8"))
except (OSError, json.JSONDecodeError) as error:
    result = {
        "schema_version": 1,
        "tag": pathlib.Path(result_path).parent.name,
        "errors": [f"invalid_driver_result:{type(error).__name__}"],
    }
result["driver_exit_status"] = int(driver_status)
result["resources"] = resources
result["gso_trace"] = {
    "expected": trace_expected,
    "udp_segment_attempts": int(udp_segment_attempts),
    "udp_segment_successes": int(udp_segment_successes),
    "udp_segment_capability_probes": int(udp_segment_capability_probes),
    "passed": trace_passed == "true",
}
pathlib.Path(result_path).write_text(
    json.dumps(result, sort_keys=True) + "\n", encoding="utf-8"
)
pathlib.Path(pathlib.Path(result_path).parent / "merged.json").write_text(
    json.dumps(result, sort_keys=True) + "\n", encoding="utf-8"
)
PY

cat "$WORK/merged.json"
if (( DRIVER_STATUS != 0 )) || [[ "$TRACE_PASSED" != true ]]; then
  exit 1
fi
