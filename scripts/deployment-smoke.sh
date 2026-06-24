#!/usr/bin/env bash
set -euo pipefail

export PATH="$HOME/.cargo/bin:/root/.cargo/bin:$PATH"

usage() {
  cat <<'USAGE'
Usage: scripts/deployment-smoke.sh [OPTIONS]

Stage release assets into an isolated local deployment root and run a bounded
client/server deployment smoke with real TCP and UDP forward traffic.

Options:
  --target <triple>      Host Linux Rust target triple. Defaults to rustc host triple.
  --output-dir <path>    Output directory. Defaults to /tmp/zuicity-deployment-smoke.
  --version <version>    Version string used for release staging. Defaults to Cargo workspace version.
  --duration <seconds>   Bounded traffic duration. Defaults to 5.
  --skip-build           Reuse existing release binaries when staging release assets.
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

require_file() {
  [ -f "$1" ] || { echo "missing expected file: $1" >&2; exit 1; }
}

require_executable() {
  [ -x "$1" ] || { echo "missing expected executable: $1" >&2; exit 1; }
}

print_failure_context() {
  local rc="$1"
  trap - ERR
  set +e
  local dir="${output_dir:-}"
  echo "deployment-smoke failed with exit code $rc" >&2
  if [ -n "$dir" ]; then
    echo "output_dir=$dir" >&2
    for name in \
      package-release.log \
      openssl-cert.log \
      server.log \
      client.log \
      deployment-driver.log \
      deployment-smoke-manifest.txt \
      installed-client-version.txt \
      installed-server-version.txt; do
      local file="$dir/$name"
      if [ -f "$file" ]; then
        echo "===== $file =====" >&2
        sed -n '1,220p' "$file" >&2
      fi
    done
    if command -v find >/dev/null 2>&1; then
      echo "===== $dir file tree =====" >&2
      find "$dir" -maxdepth 4 -type f -printf '%M %s %p\n' 2>/dev/null | sort | sed -n '1,180p' >&2
    fi
  fi
  exit "$rc"
}

target=""
output_dir="/tmp/zuicity-deployment-smoke"
version=""
duration="5"
skip_build=0
trap 'print_failure_context "$?"' ERR
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
    --duration)
      [ "$#" -ge 2 ] || { echo "--duration requires a value" >&2; exit 2; }
      duration="$2"
      shift 2
      ;;
    --skip-build)
      skip_build=1
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
require_tool bash
require_tool install
require_tool openssl
require_tool python3
require_tool rustc
require_tool sed

target="${target:-$(host_triple)}"
host="$(host_triple)"
if [ "$target" != "$host" ]; then
  echo "Deployment smoke executes packaged binaries and must use the host target ($host), got $target" >&2
  exit 2
fi
case "$duration" in
  ''|*[!0-9]*) echo "--duration must be a positive integer number of seconds" >&2; exit 2 ;;
esac
if [ "$duration" -le 0 ]; then
  echo "--duration must be positive" >&2
  exit 2
fi

version="${version:-$(cargo_workspace_version)}"
release_dir="$output_dir/release"
deploy_root="$output_dir/deploy-root"
etc_dir="$deploy_root/etc/zuicity"
bin_dir="$deploy_root/usr/bin"
service_dir="$deploy_root/usr/lib/systemd/system"
manifest="$output_dir/deployment-smoke-manifest.txt"

rm -rf "$output_dir"
mkdir -p "$output_dir" "$etc_dir" "$bin_dir" "$service_dir"

release_args=(scripts/package-release.sh --target "$target" --output-dir "$release_dir" --version "$version")
if [ "$skip_build" -eq 1 ]; then
  release_args+=(--skip-build)
fi
"${release_args[@]}" >"$output_dir/package-release.log" 2>&1

release_build="$release_dir/build"
require_executable "$release_build/zuicity-client"
require_executable "$release_build/zuicity-server"
require_file "$release_build/example-client.json"
require_file "$release_build/example-server.json"
require_file "$release_build/zuicity-client.service"
require_file "$release_build/zuicity-server.service"

install -m 0755 "$release_build/zuicity-client" "$bin_dir/zuicity-client"
install -m 0755 "$release_build/zuicity-server" "$bin_dir/zuicity-server"
install -m 0644 "$release_build/example-client.json" "$etc_dir/example-client.json"
install -m 0644 "$release_build/example-server.json" "$etc_dir/example-server.json"
install -m 0644 "$release_build/zuicity-client.service" "$service_dir/zuicity-client.service"
install -m 0644 "$release_build/zuicity-server.service" "$service_dir/zuicity-server.service"

openssl req \
  -x509 \
  -newkey rsa:2048 \
  -keyout "$etc_dir/private.key" \
  -out "$etc_dir/fullchain.pem" \
  -days 1 \
  -nodes \
  -subj /CN=localhost \
  -addext subjectAltName=DNS:localhost,IP:127.0.0.1 \
  >"$output_dir/openssl-cert.log" 2>&1
chmod 0600 "$etc_dir/private.key"
chmod 0644 "$etc_dir/fullchain.pem"

"$bin_dir/zuicity-client" -v >"$output_dir/installed-client-version.txt" 2>&1
"$bin_dir/zuicity-server" -v >"$output_dir/installed-server-version.txt" 2>&1

python3 - "$bin_dir/zuicity-client" "$bin_dir/zuicity-server" "$deploy_root" "$output_dir" "$duration" "$version" <<'PY'
from __future__ import annotations

import json
import os
import signal
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

CLIENT = Path(sys.argv[1])
SERVER = Path(sys.argv[2])
DEPLOY_ROOT = Path(sys.argv[3])
OUT = Path(sys.argv[4])
DURATION = int(sys.argv[5])
VERSION = sys.argv[6]
UUID = "00000000-0000-0000-0000-000000000001"
PASSWORD = "deployment smoke password"

server_proc: subprocess.Popen[str] | None = None
client_proc: subprocess.Popen[str] | None = None
stop_event = threading.Event()
summary: dict[str, object] = {}


def reserve_tcp_port() -> int:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return int(port)


def reserve_udp_port() -> int:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return int(port)


def start_tcp_echo() -> tuple[int, threading.Thread, dict[str, int]]:
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen()
    listener.settimeout(0.2)
    port = int(listener.getsockname()[1])
    stats = {"accepted": 0, "bytes": 0}

    def run() -> None:
        with listener:
            while not stop_event.is_set():
                try:
                    conn, _ = listener.accept()
                except socket.timeout:
                    continue
                with conn:
                    conn.settimeout(2.0)
                    stats["accepted"] += 1
                    while True:
                        try:
                            data = conn.recv(65536)
                        except socket.timeout:
                            break
                        if not data:
                            break
                        stats["bytes"] += len(data)
                        conn.sendall(data)

    thread = threading.Thread(target=run, name="tcp-echo", daemon=True)
    thread.start()
    return port, thread, stats


def start_udp_echo() -> tuple[int, threading.Thread, dict[str, int]]:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))
    sock.settimeout(0.2)
    port = int(sock.getsockname()[1])
    stats = {"datagrams": 0, "bytes": 0}

    def run() -> None:
        with sock:
            while not stop_event.is_set():
                try:
                    data, peer = sock.recvfrom(65535)
                except socket.timeout:
                    continue
                stats["datagrams"] += 1
                stats["bytes"] += len(data)
                sock.sendto(data, peer)

    thread = threading.Thread(target=run, name="udp-echo", daemon=True)
    thread.start()
    return port, thread, stats


def process_text(proc: subprocess.Popen[str], log_path: Path) -> str:
    if log_path.exists():
        return log_path.read_text(errors="replace")
    return f"missing log for pid={proc.pid}"


def wait_for_log(proc: subprocess.Popen[str], log_path: Path, needle: str, timeout: float) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            raise RuntimeError(f"process exited before {needle!r}: {process_text(proc, log_path)}")
        if log_path.exists() and needle in log_path.read_text(errors="replace"):
            return
        time.sleep(0.05)
    raise TimeoutError(f"timed out waiting for {needle!r}: {process_text(proc, log_path)}")


def tcp_round_trip(addr: tuple[str, int], payload: bytes, timeout: float = 2.0) -> bytes:
    with socket.create_connection(addr, timeout=timeout) as stream:
        stream.settimeout(timeout)
        stream.sendall(payload)
        stream.shutdown(socket.SHUT_WR)
        chunks: list[bytes] = []
        while True:
            chunk = stream.recv(65536)
            if not chunk:
                break
            chunks.append(chunk)
        return b"".join(chunks)


def udp_round_trip(addr: tuple[str, int], payload: bytes, timeout: float = 2.0) -> bytes:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        sock.sendto(payload, addr)
        data, peer = sock.recvfrom(65535)
        if peer != addr:
            raise RuntimeError(f"unexpected UDP peer {peer}, expected {addr}")
        return data


def retry(operation, deadline: float):
    last_error: BaseException | None = None
    while time.monotonic() < deadline:
        try:
            return operation()
        except BaseException as exc:  # noqa: BLE001 - diagnostic wrapper for smoke script
            last_error = exc
            time.sleep(0.1)
    raise TimeoutError(f"operation did not become ready: {last_error}")


def terminate_process(proc: subprocess.Popen[str] | None, name: str) -> int | None:
    if proc is None:
        return None
    if proc.poll() is None:
        proc.send_signal(signal.SIGTERM)
        try:
            return proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            return proc.wait(timeout=5)
    return proc.returncode


def main() -> int:
    global server_proc, client_proc
    tcp_echo_port, tcp_thread, tcp_stats = start_tcp_echo()
    udp_echo_port, udp_thread, udp_stats = start_udp_echo()
    server_port = reserve_udp_port()
    tcp_forward_port = reserve_tcp_port()
    udp_forward_port = reserve_udp_port()
    etc = DEPLOY_ROOT / "etc" / "zuicity"
    server_config = etc / "server.json"
    client_config = etc / "client.json"
    server_log = OUT / "server.log"
    client_log = OUT / "client.log"
    driver_log = OUT / "deployment-driver.log"

    server_json = {
        "listen": f"127.0.0.1:{server_port}",
        "users": {UUID: PASSWORD},
        "certificate": str(etc / "fullchain.pem"),
        "private_key": str(etc / "private.key"),
        "congestion_control": "bbr",
        "log_level": "debug",
    }
    client_json = {
        "server": f"127.0.0.1:{server_port}",
        "uuid": UUID,
        "password": PASSWORD,
        "sni": "localhost",
        "allow_insecure": True,
        "log_level": "debug",
        "forward": {
            f"127.0.0.1:{tcp_forward_port}/tcp": f"127.0.0.1:{tcp_echo_port}",
            f"127.0.0.1:{udp_forward_port}/udp": f"127.0.0.1:{udp_echo_port}",
        },
    }
    server_config.write_text(json.dumps(server_json, indent=2) + "\n")
    client_config.write_text(json.dumps(client_json, indent=2) + "\n")

    with server_log.open("w") as server_output:
        server_proc = subprocess.Popen(
            [str(SERVER), "run", "-c", str(server_config), "--disable-timestamp"],
            stdout=server_output,
            stderr=subprocess.STDOUT,
            text=True,
        )
    wait_for_log(server_proc, server_log, "Listen at", 8.0)

    with client_log.open("w") as client_output:
        client_proc = subprocess.Popen(
            [str(CLIENT), "run", "-c", str(client_config), "--disable-timestamp"],
            stdout=client_output,
            stderr=subprocess.STDOUT,
            text=True,
        )

    tcp_addr = ("127.0.0.1", tcp_forward_port)
    udp_addr = ("127.0.0.1", udp_forward_port)
    first_tcp = retry(
        lambda: tcp_round_trip(tcp_addr, b"deployment smoke tcp ready"),
        time.monotonic() + 8.0,
    )
    if first_tcp != b"deployment smoke tcp ready":
        raise RuntimeError(f"TCP readiness echo mismatch: {first_tcp!r}")
    first_udp = retry(
        lambda: udp_round_trip(udp_addr, b"deployment smoke udp ready"),
        time.monotonic() + 8.0,
    )
    if first_udp != b"deployment smoke udp ready":
        raise RuntimeError(f"UDP readiness echo mismatch: {first_udp!r}")

    tcp_rounds = 1
    udp_rounds = 1
    deadline = time.monotonic() + DURATION
    iteration = 0
    while time.monotonic() < deadline:
        if server_proc.poll() is not None:
            raise RuntimeError(f"zuicity-server exited early: {process_text(server_proc, server_log)}")
        if client_proc.poll() is not None:
            raise RuntimeError(f"zuicity-client exited early: {process_text(client_proc, client_log)}")
        tcp_payload = f"deployment tcp {iteration}".encode()
        udp_payload = f"deployment udp {iteration}".encode()
        if tcp_round_trip(tcp_addr, tcp_payload) != tcp_payload:
            raise RuntimeError("TCP deployment payload mismatch")
        tcp_rounds += 1
        if udp_round_trip(udp_addr, udp_payload) != udp_payload:
            raise RuntimeError("UDP deployment payload mismatch")
        udp_rounds += 1
        iteration += 1
        time.sleep(0.2)

    client_exit = terminate_process(client_proc, "client")
    server_exit = terminate_process(server_proc, "server")
    stop_event.set()
    tcp_thread.join(timeout=1.0)
    udp_thread.join(timeout=1.0)

    if client_exit != 0:
        raise RuntimeError(f"zuicity-client did not exit cleanly after SIGTERM: {client_exit}")
    if server_exit != 0:
        raise RuntimeError(f"zuicity-server did not exit cleanly after SIGTERM: {server_exit}")

    server_log_text = server_log.read_text(errors="replace")
    client_log_text = client_log.read_text(errors="replace")
    for needle, source, path in [
        ("Listen at", server_log_text, server_log),
        ("Exiting", server_log_text, server_log),
        ("Exiting", client_log_text, client_log),
    ]:
        if needle not in source:
            raise RuntimeError(f"missing {needle!r} in {path}")

    summary.update(
        {
            "version": VERSION,
            "duration_seconds": DURATION,
            "tcp_round_trips": tcp_rounds,
            "udp_round_trips": udp_rounds,
            "tcp_echo_connections": tcp_stats["accepted"],
            "tcp_echo_bytes": tcp_stats["bytes"],
            "udp_echo_datagrams": udp_stats["datagrams"],
            "udp_echo_bytes": udp_stats["bytes"],
            "server_addr": f"127.0.0.1:{server_port}",
            "tcp_forward_addr": f"127.0.0.1:{tcp_forward_port}",
            "udp_forward_addr": f"127.0.0.1:{udp_forward_port}",
            "tcp_echo_addr": f"127.0.0.1:{tcp_echo_port}",
            "udp_echo_addr": f"127.0.0.1:{udp_echo_port}",
            "client_exit": client_exit,
            "server_exit": server_exit,
            "client_config": str(client_config),
            "server_config": str(server_config),
            "client_log": str(client_log),
            "server_log": str(server_log),
            "client_service": str(DEPLOY_ROOT / "usr" / "lib" / "systemd" / "system" / "zuicity-client.service"),
            "server_service": str(DEPLOY_ROOT / "usr" / "lib" / "systemd" / "system" / "zuicity-server.service"),
        }
    )
    driver_log.write_text("\n".join(f"{key}={value}" for key, value in summary.items()) + "\n")
    return 0


try:
    code = main()
except BaseException as exc:  # noqa: BLE001 - smoke script diagnostics
    terminate_process(client_proc, "client")
    terminate_process(server_proc, "server")
    stop_event.set()
    (OUT / "deployment-driver.log").write_text(f"error={exc!r}\n")
    raise
sys.exit(code)
PY

cat >"$manifest" <<MANIFEST
version=$version
target=$target
duration_seconds=$duration
release_dir=$release_dir
deploy_root=$deploy_root
client_bin=$bin_dir/zuicity-client
server_bin=$bin_dir/zuicity-server
client_config=$etc_dir/client.json
server_config=$etc_dir/server.json
client_service=$service_dir/zuicity-client.service
server_service=$service_dir/zuicity-server.service
client_version=$output_dir/installed-client-version.txt
server_version=$output_dir/installed-server-version.txt
package_release_log=$output_dir/package-release.log
openssl_log=$output_dir/openssl-cert.log
server_log=$output_dir/server.log
client_log=$output_dir/client.log
deployment_driver_log=$output_dir/deployment-driver.log
MANIFEST
cat "$output_dir/deployment-driver.log" >>"$manifest"

printf 'manifest=%s\n' "$manifest"
printf 'deploy_root=%s\n' "$deploy_root"
printf 'server_log=%s\n' "$output_dir/server.log"
printf 'client_log=%s\n' "$output_dir/client.log"
printf 'driver_log=%s\n' "$output_dir/deployment-driver.log"
