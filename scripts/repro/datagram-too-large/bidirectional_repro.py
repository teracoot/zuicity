#!/usr/bin/env python3
from __future__ import annotations

import argparse
import socket
import threading
import time
from dataclasses import dataclass


@dataclass(slots=True)
class Counters:
    tcp_churn_connections: int = 0
    tcp_churn_bytes_sent: int = 0
    tcp_churn_bytes_received: int = 0
    tcp_upload_connections: int = 0
    tcp_upload_bytes_sent: int = 0
    tcp_upload_bytes_received: int = 0
    tcp_download_connections: int = 0
    tcp_download_bytes_received: int = 0
    udp_echo_packets: int = 0
    udp_echo_bytes_sent: int = 0
    udp_echo_replies: int = 0
    udp_source_requests: int = 0
    udp_source_replies: int = 0
    udp_source_max_reply: int = 0
    errors: int = 0


def recv_available(sock: socket.socket, counters: Counters, field: str) -> None:
    while True:
        try:
            data = sock.recv(65_535)
        except socket.timeout:
            return
        except OSError:
            counters.errors += 1
            return
        if not data:
            return
        setattr(counters, field, getattr(counters, field) + len(data))


def tcp_churn(host: str, port: int, deadline: float, counters: Counters) -> None:
    payloads = [
        b"mining.subscribe\n",
        b"mining.authorize\n",
        b"mining.submit\n",
        b"x" * 512,
        b"y" * 4096,
    ]
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((host, port), timeout=3.0) as sock:
                sock.settimeout(0.01)
                counters.tcp_churn_connections += 1
                for payload in payloads:
                    sock.sendall(payload)
                    counters.tcp_churn_bytes_sent += len(payload)
                    recv_available(sock, counters, "tcp_churn_bytes_received")
        except OSError:
            counters.errors += 1
            time.sleep(0.05)


def tcp_upload(host: str, port: int, deadline: float, counters: Counters) -> None:
    sizes = [4096, 8192, 12_288, 16_384]
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((host, port), timeout=3.0) as sock:
                sock.settimeout(0.002)
                counters.tcp_upload_connections += 1
                connection_deadline = min(deadline, time.monotonic() + 12.0)
                index = 0
                while time.monotonic() < connection_deadline:
                    size = sizes[index % len(sizes)]
                    payload = bytes([size % 251]) * size
                    sock.sendall(payload)
                    counters.tcp_upload_bytes_sent += size
                    recv_available(sock, counters, "tcp_upload_bytes_received")
                    index += 1
        except OSError:
            counters.errors += 1
            time.sleep(0.05)


def tcp_download(host: str, port: int, deadline: float, counters: Counters) -> None:
    chunks = [4096, 8192, 16_384, 32_768]
    index = 0
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((host, port), timeout=3.0) as sock:
                counters.tcp_download_connections += 1
                chunk = chunks[index % len(chunks)]
                index += 1
                sock.sendall(f"chunk={chunk} seconds=10\n".encode("ascii"))
                sock.settimeout(0.05)
                while time.monotonic() < deadline:
                    data = sock.recv(65_535)
                    if not data:
                        break
                    counters.tcp_download_bytes_received += len(data)
        except OSError:
            counters.errors += 1
            time.sleep(0.05)


def udp_echo(host: str, port: int, deadline: float, counters: Counters, worker: int) -> None:
    sizes = [1200, 1280, 1350, 1400, 1450, 1472]
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(0.001)
        index = worker
        while time.monotonic() < deadline:
            size = sizes[index % len(sizes)]
            payload = bytes([size % 251]) * size
            try:
                counters.udp_echo_bytes_sent += sock.sendto(payload, (host, port))
                counters.udp_echo_packets += 1
                while True:
                    try:
                        sock.recvfrom(65_535)
                        counters.udp_echo_replies += 1
                    except socket.timeout:
                        break
            except OSError:
                counters.errors += 1
            index += 1
            time.sleep(0.005)


def udp_source(host: str, port: int, deadline: float, counters: Counters, worker: int) -> None:
    sizes = [1200, 1280, 1400, 1472, 4096, 8192, 16_000]
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(0.005)
        index = worker
        while time.monotonic() < deadline:
            size = sizes[index % len(sizes)]
            command = f"size={size} count=3 interval=0.002\n".encode("ascii")
            try:
                sock.sendto(command, (host, port))
                counters.udp_source_requests += 1
                stop = time.monotonic() + 0.05
                while time.monotonic() < stop:
                    try:
                        data, _addr = sock.recvfrom(65_535)
                    except socket.timeout:
                        continue
                    counters.udp_source_replies += 1
                    counters.udp_source_max_reply = max(counters.udp_source_max_reply, len(data))
            except OSError:
                counters.errors += 1
            index += 1
            time.sleep(0.02)


def report(counters: Counters, started: float) -> None:
    elapsed = max(time.monotonic() - started, 0.001)
    print(
        " ".join(
            [
                f"seconds={elapsed:.1f}",
                f"tcp_churn_connections={counters.tcp_churn_connections}",
                f"tcp_upload_sent={counters.tcp_upload_bytes_sent}",
                f"tcp_download_received={counters.tcp_download_bytes_received}",
                f"udp_echo_packets={counters.udp_echo_packets}",
                f"udp_source_requests={counters.udp_source_requests}",
                f"udp_source_max_reply={counters.udp_source_max_reply}",
                f"errors={counters.errors}",
            ]
        ),
        flush=True,
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="skoracle.zivle.com")
    parser.add_argument("--seconds", type=float, default=360.0)
    parser.add_argument("--udp-echo-port", type=int, default=55211)
    parser.add_argument("--tcp-echo-port", type=int, default=55212)
    parser.add_argument("--udp-source-port", type=int, default=55213)
    parser.add_argument("--tcp-source-port", type=int, default=55214)
    args = parser.parse_args()

    counters = Counters()
    started = time.monotonic()
    deadline = started + args.seconds
    workers: list[threading.Thread] = [
        threading.Thread(target=tcp_churn, args=(args.host, args.tcp_echo_port, deadline, counters), daemon=True),
        threading.Thread(target=tcp_upload, args=(args.host, args.tcp_echo_port, deadline, counters), daemon=True),
        threading.Thread(target=tcp_download, args=(args.host, args.tcp_source_port, deadline, counters), daemon=True),
        threading.Thread(target=udp_source, args=(args.host, args.udp_source_port, deadline, counters, 0), daemon=True),
        threading.Thread(target=udp_source, args=(args.host, args.udp_source_port, deadline, counters, 1), daemon=True),
    ]
    workers.extend(
        threading.Thread(target=udp_echo, args=(args.host, args.udp_echo_port, deadline, counters, worker), daemon=True)
        for worker in range(4)
    )
    for worker in workers:
        worker.start()
    while time.monotonic() < deadline:
        time.sleep(30.0)
        report(counters, started)
    for worker in workers:
        worker.join(timeout=1.0)
    report(counters, started)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
