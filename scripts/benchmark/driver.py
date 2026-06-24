#!/usr/bin/env python3
"""Measurement engine: runs four metrics through the client's forward port and
emits a single JSON line. Metrics: TCP connect+RTT, TCP persistent RTT, TCP
throughput (4 MiB), UDP RTT.

Usage: driver.py <client_ip> <tcp_fwd_port> <udp_fwd_port> <tag> <iters>
"""
import json
import os
import socket
import statistics
import sys
import time

cli_ip = sys.argv[1]
tcp_fwd = int(sys.argv[2])
udp_fwd = int(sys.argv[3])
tag = sys.argv[4] if len(sys.argv) > 4 else "impl"
iters = int(sys.argv[5]) if len(sys.argv) > 5 else 60


def pct(xs, p):
    xs = sorted(xs)
    k = max(0, min(len(xs) - 1, int(round((p / 100.0) * (len(xs) - 1)))))
    return xs[k]


def stat_ms(xs):
    if not xs:
        return None
    return {
        "n": len(xs),
        "mean_ms": round(statistics.mean(xs), 3),
        "median_ms": round(statistics.median(xs), 3),
        "p95_ms": round(pct(xs, 95), 3),
        "min_ms": round(min(xs), 3),
        "max_ms": round(max(xs), 3),
    }


def stat_mbps(xs):
    if not xs:
        return None
    return {
        "n": len(xs),
        "mean": round(statistics.mean(xs), 2),
        "median": round(statistics.median(xs), 2),
        "max": round(max(xs), 2),
        "min": round(min(xs), 2),
    }


def recv_exact(sock, expected, chunk=4096):
    got = b""
    while len(got) < expected:
        c = sock.recv(chunk)
        if not c:
            break
        got += c
    return got


def warmup():
    for _ in range(60):
        try:
            with socket.create_connection((cli_ip, tcp_fwd), timeout=10) as s:
                s.settimeout(10)
                s.sendall(b"warmup")
                got = s.recv(64)
                if got == b"warmup":
                    return True
        except Exception:
            time.sleep(0.5)
    return False


if not warmup():
    print(json.dumps({"tag": tag, "error": "warmup_failed"}))
    sys.exit(1)

payload = b"x" * 64
errors = []

tcp_rtt = []
for _ in range(iters):
    try:
        t0 = time.perf_counter()
        with socket.create_connection((cli_ip, tcp_fwd), timeout=10) as s:
            s.settimeout(10)
            s.sendall(payload)
            got = recv_exact(s, len(payload))
        t1 = time.perf_counter()
        if got == payload:
            tcp_rtt.append((t1 - t0) * 1000.0)
    except Exception as exc:
        errors.append(f"tcp_connect_rtt:{type(exc).__name__}")
        break

tcp_persist = []
try:
    with socket.create_connection((cli_ip, tcp_fwd), timeout=10) as s:
        s.settimeout(10)
        for _ in range(iters):
            try:
                t0 = time.perf_counter()
                s.sendall(payload)
                got = recv_exact(s, len(payload))
                t1 = time.perf_counter()
                if got == payload:
                    tcp_persist.append((t1 - t0) * 1000.0)
            except Exception as exc:
                errors.append(f"tcp_persistent_rtt:{type(exc).__name__}")
                break
except Exception as exc:
    errors.append(f"tcp_persistent_open:{type(exc).__name__}")

thr = []
big = os.urandom(4 * 1024 * 1024)
for _ in range(max(5, iters // 6)):
    try:
        with socket.create_connection((cli_ip, tcp_fwd), timeout=30) as s:
            s.settimeout(30)
            t0 = time.perf_counter()
            s.sendall(big)
            got = 0
            while got < len(big):
                c = s.recv(262144)
                if not c:
                    break
                got += len(c)
            t1 = time.perf_counter()
        if got == len(big):
            thr.append((len(big) * 8 / 1e6) / (t1 - t0))
        else:
            errors.append(f"tcp_throughput_short:{got}")
            break
    except Exception as exc:
        errors.append(f"tcp_throughput:{type(exc).__name__}")
        break

udp_rtt = []
for _ in range(iters):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(5)
    try:
        t0 = time.perf_counter()
        s.sendto(payload, (cli_ip, udp_fwd))
        got, _ = s.recvfrom(4096)
        t1 = time.perf_counter()
        if got == payload:
            udp_rtt.append((t1 - t0) * 1000.0)
    except Exception as exc:
        errors.append(f"udp_rtt:{type(exc).__name__}")
        break
    finally:
        s.close()

print(json.dumps({
    "tag": tag,
    "tcp_connect_rtt": stat_ms(tcp_rtt),
    "tcp_persistent_rtt": stat_ms(tcp_persist),
    "tcp_throughput_mbps": stat_mbps(thr),
    "udp_rtt": stat_ms(udp_rtt),
    "errors": errors,
}))
