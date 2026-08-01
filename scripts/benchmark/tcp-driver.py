#!/usr/bin/env python3
"""Measure TCP latency and send-plus-echo throughput through a proxy forward."""

import argparse
import datetime as dt
import json
import socket
import statistics
import sys
import time


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--client-ip", required=True)
    parser.add_argument("--forward-port", required=True, type=int)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--rtt-samples", type=int, default=60)
    parser.add_argument("--throughput-samples", type=int, default=100)
    parser.add_argument("--throughput-bytes", type=int, default=4 * 1024 * 1024)
    parser.add_argument("--warmup-transfers", type=int, default=5)
    parser.add_argument("--timeout-seconds", type=float, default=120.0)
    args = parser.parse_args()
    for name in (
        "rtt_samples",
        "throughput_samples",
        "throughput_bytes",
        "warmup_transfers",
    ):
        if getattr(args, name) < (0 if name == "warmup_transfers" else 1):
            parser.error(f"--{name.replace('_', '-')} has an invalid value")
    if args.timeout_seconds <= 0:
        parser.error("--timeout-seconds must be positive")
    return args


def percentile(values: list[float], percent: float) -> float:
    ordered = sorted(values)
    index = max(
        0,
        min(len(ordered) - 1, round((percent / 100.0) * (len(ordered) - 1))),
    )
    return ordered[index]


def latency_stats(values: list[float]) -> dict[str, object]:
    return {
        "n": len(values),
        "mean_ms": round(statistics.mean(values), 6),
        "median_ms": round(statistics.median(values), 6),
        "p95_ms": round(percentile(values, 95), 6),
        "min_ms": round(min(values), 6),
        "max_ms": round(max(values), 6),
        "values_ms": [round(value, 9) for value in values],
    }


def throughput_stats(values: list[float]) -> dict[str, object]:
    return {
        "n": len(values),
        "mean_mbps": round(statistics.mean(values), 6),
        "median_mbps": round(statistics.median(values), 6),
        "p05_mbps": round(percentile(values, 5), 6),
        "min_mbps": round(min(values), 6),
        "max_mbps": round(max(values), 6),
        "values_mbps": [round(value, 9) for value in values],
    }


def open_socket(host: str, port: int, timeout: float) -> socket.socket:
    sock = socket.create_connection((host, port), timeout=timeout)
    sock.settimeout(timeout)
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    return sock


def receive_exact(sock: socket.socket, expected: int) -> int:
    received = 0
    while received < expected:
        chunk = sock.recv(min(262144, expected - received))
        if not chunk:
            break
        received += len(chunk)
    return received


def transfer(
    host: str,
    port: int,
    payload: bytes,
    timeout: float,
    include_connect: bool = False,
) -> tuple[int, float]:
    started = time.perf_counter_ns() if include_connect else None
    with open_socket(host, port, timeout) as sock:
        if started is None:
            started = time.perf_counter_ns()
        sock.sendall(payload)
        received = receive_exact(sock, len(payload))
        elapsed = (time.perf_counter_ns() - started) / 1_000_000_000
    return received, elapsed


def wait_until_ready(host: str, port: int) -> bool:
    for _ in range(60):
        try:
            with open_socket(host, port, 2.0) as sock:
                sock.sendall(b"ready")
                if receive_exact(sock, 5) == 5:
                    return True
        except OSError:
            time.sleep(0.25)
    return False


def main() -> int:
    args = parse_args()
    errors: list[str] = []
    if not wait_until_ready(args.client_ip, args.forward_port):
        print(json.dumps({"schema_version": 1, "tag": args.tag, "errors": ["ready_timeout"]}))
        return 1

    bulk = b"x" * args.throughput_bytes
    for index in range(args.warmup_transfers):
        try:
            received, _ = transfer(
                args.client_ip,
                args.forward_port,
                bulk,
                args.timeout_seconds,
            )
            if received != len(bulk):
                errors.append(f"warmup_{index}_short:{received}")
                break
        except OSError as error:
            errors.append(f"warmup_{index}:{type(error).__name__}")
            break

    payload = b"x" * 64
    connect_rtt: list[float] = []
    if not errors:
        for index in range(args.rtt_samples):
            try:
                received, elapsed = transfer(
                    args.client_ip,
                    args.forward_port,
                    payload,
                    10.0,
                    include_connect=True,
                )
                if received != len(payload):
                    errors.append(f"tcp_connect_rtt_{index}_short:{received}")
                    break
                connect_rtt.append(elapsed * 1000)
            except OSError as error:
                errors.append(f"tcp_connect_rtt_{index}:{type(error).__name__}")
                break

    persistent_rtt: list[float] = []
    if not errors:
        try:
            with open_socket(args.client_ip, args.forward_port, 10.0) as sock:
                for index in range(args.rtt_samples):
                    started = time.perf_counter_ns()
                    sock.sendall(payload)
                    received = receive_exact(sock, len(payload))
                    elapsed = (time.perf_counter_ns() - started) / 1_000_000_000
                    if received != len(payload):
                        errors.append(f"tcp_persistent_rtt_{index}_short:{received}")
                        break
                    persistent_rtt.append(elapsed * 1000)
        except OSError as error:
            errors.append(f"tcp_persistent_rtt:{type(error).__name__}")

    throughput: list[float] = []
    if not errors:
        for index in range(args.throughput_samples):
            try:
                received, elapsed = transfer(
                    args.client_ip,
                    args.forward_port,
                    bulk,
                    args.timeout_seconds,
                )
                if received != len(bulk):
                    errors.append(f"tcp_throughput_{index}_short:{received}")
                    break
                throughput.append((len(bulk) * 8 / 1_000_000) / elapsed)
            except OSError as error:
                errors.append(f"tcp_throughput_{index}:{type(error).__name__}")
                break

    result: dict[str, object] = {
        "schema_version": 1,
        "tag": args.tag,
        "recorded_at_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "workload": {
            "rtt_samples": args.rtt_samples,
            "throughput_samples": args.throughput_samples,
            "throughput_bytes": args.throughput_bytes,
            "warmup_transfers": args.warmup_transfers,
            "throughput_operation": "send_payload_plus_receive_full_echo",
            "throughput_connection": "fresh_tcp_connection_per_sample",
            "tcp_nodelay": True,
        },
        "errors": errors,
    }
    if connect_rtt:
        result["tcp_connect_rtt"] = latency_stats(connect_rtt)
    if persistent_rtt:
        result["tcp_persistent_rtt"] = latency_stats(persistent_rtt)
    if throughput:
        result["tcp_throughput"] = throughput_stats(throughput)
    print(json.dumps(result, sort_keys=True))
    return 0 if not errors else 1


if __name__ == "__main__":
    sys.exit(main())
