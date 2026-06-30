#!/usr/bin/env python3
from __future__ import annotations

import argparse
import socket
import threading
import time
from dataclasses import dataclass


@dataclass(slots=True)
class Counters:
    connections: int = 0
    bytes_sent: int = 0
    errors: int = 0


def parse_request(conn: socket.socket, default_chunk: int, default_seconds: float) -> tuple[int, float]:
    conn.settimeout(0.2)
    try:
        request = conn.recv(128).decode("ascii", errors="ignore")
    except socket.timeout:
        return default_chunk, default_seconds
    chunk = default_chunk
    seconds = default_seconds
    for part in request.replace("\n", " ").split():
        key, sep, value = part.partition("=")
        if sep != "=":
            continue
        try:
            if key == "chunk":
                chunk = max(1, min(int(value), 65_536))
            elif key == "seconds":
                seconds = max(0.1, min(float(value), default_seconds))
        except ValueError:
            continue
    return chunk, seconds


def handle(conn: socket.socket, counters: Counters, default_chunk: int, default_seconds: float) -> None:
    with conn:
        try:
            chunk, seconds = parse_request(conn, default_chunk, default_seconds)
            payload = bytes([chunk % 251]) * chunk
            deadline = time.monotonic() + seconds
            while time.monotonic() < deadline:
                conn.sendall(payload)
                counters.bytes_sent += len(payload)
        except OSError:
            counters.errors += 1


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--seconds", type=float, default=3600.0)
    parser.add_argument("--chunk", type=int, default=16_384)
    parser.add_argument("--client-seconds", type=float, default=30.0)
    args = parser.parse_args()

    counters = Counters()
    deadline = time.monotonic() + args.seconds
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", args.port))
    sock.listen(64)
    sock.settimeout(1.0)
    threads: list[threading.Thread] = []
    with sock:
        while time.monotonic() < deadline:
            try:
                conn, _addr = sock.accept()
            except socket.timeout:
                continue
            counters.connections += 1
            thread = threading.Thread(
                target=handle,
                args=(conn, counters, args.chunk, args.client_seconds),
                daemon=True,
            )
            thread.start()
            threads.append(thread)
    for thread in threads:
        thread.join(timeout=0.1)
    print(f"connections={counters.connections}")
    print(f"bytes_sent={counters.bytes_sent}")
    print(f"errors={counters.errors}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
