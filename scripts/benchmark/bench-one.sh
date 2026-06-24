#!/usr/bin/env bash
# Run the 4-metric benchmark for ONE implementation over a real two-namespace
# veth path. Emits a single JSON line (the driver's output) on stdout.
#
# Usage: bench-one.sh <tag> <client-bin> <server-bin> [iters]
set -u
export PATH="/usr/sbin:/sbin:$PATH"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

TAG="${1:?tag}"; CLIENT="${2:?client bin}"; SERVER="${3:?server bin}"; ITERS="${4:-60}"

W="$(mktemp -d)"
NS_SRV="jbench-srv-$$"; NS_CLI="jbench-cli-$$"
VETH_SRV="jb-srv-$$"; VETH_CLI="jb-cli-$$"
IP_SRV=10.210.0.1; IP_CLI=10.210.0.2; SRV_PORT=9443
ECHO_PORT=7000; UDP_ECHO_PORT=7001; FWD_PORT=1080; UDP_FWD_PORT=1081
UUID="00000000-0000-0000-0000-000000000099"; PASSWORD="bench-password"

cleanup() {
  ip netns pids "$NS_SRV" 2>/dev/null | xargs -r kill 2>/dev/null
  ip netns pids "$NS_CLI" 2>/dev/null | xargs -r kill 2>/dev/null
  ip netns del "$NS_SRV" 2>/dev/null
  ip netns del "$NS_CLI" 2>/dev/null
  ip link del "$VETH_SRV" 2>/dev/null
  rm -rf "$W"
}
trap cleanup EXIT

ip netns add "$NS_SRV"; ip netns add "$NS_CLI"
ip link add "$VETH_SRV" type veth peer name "$VETH_CLI"
ip link set "$VETH_SRV" netns "$NS_SRV"; ip link set "$VETH_CLI" netns "$NS_CLI"
ip -n "$NS_SRV" addr add "$IP_SRV/24" dev "$VETH_SRV"
ip -n "$NS_CLI" addr add "$IP_CLI/24" dev "$VETH_CLI"
ip -n "$NS_SRV" link set "$VETH_SRV" up; ip -n "$NS_CLI" link set "$VETH_CLI" up
ip -n "$NS_SRV" link set lo up; ip -n "$NS_CLI" link set lo up

openssl req -x509 -newkey rsa:2048 -keyout "$W/key.pem" -out "$W/cert.pem" -days 2 -nodes \
  -subj "/CN=zuicity.local" -addext "subjectAltName=DNS:zuicity.local,IP:$IP_SRV" >/dev/null 2>&1

cat >"$W/server.json" <<JSON
{"listen":"$IP_SRV:$SRV_PORT","users":{"$UUID":"$PASSWORD"},"certificate":"$W/cert.pem","private_key":"$W/key.pem","congestion_control":"bbr","log_level":"warn"}
JSON
cat >"$W/client.json" <<JSON
{"server":"$IP_SRV:$SRV_PORT","uuid":"$UUID","password":"$PASSWORD","sni":"zuicity.local","allow_insecure":true,"congestion_control":"bbr","log_level":"warn","forward":{"$IP_CLI:$FWD_PORT/tcp":"$IP_SRV:$ECHO_PORT","$IP_CLI:$UDP_FWD_PORT/udp":"$IP_SRV:$UDP_ECHO_PORT"}}
JSON

ip netns exec "$NS_SRV" python3 "$HERE/echo-server.py" "$IP_SRV" "$ECHO_PORT" "$UDP_ECHO_PORT" >"$W/echo.log" 2>&1 &
sleep 1
ip netns exec "$NS_SRV" "$SERVER" run -c "$W/server.json" >"$W/server-$TAG.log" 2>&1 &
sleep 2
if ! ip netns pids "$NS_SRV" | grep -q .; then
  echo "{\"tag\":\"$TAG\",\"error\":\"server_died\"}"
  exit 1
fi
ip netns exec "$NS_CLI" "$CLIENT" run -c "$W/client.json" >"$W/client-$TAG.log" 2>&1 &
sleep 3
ip netns exec "$NS_CLI" python3 "$HERE/driver.py" "$IP_CLI" "$FWD_PORT" "$UDP_FWD_PORT" "$TAG" "$ITERS"
