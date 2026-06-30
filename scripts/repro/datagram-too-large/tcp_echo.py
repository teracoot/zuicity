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
    bytes_received: int = 0
    max_chunk: int = 0


def handle(conn: socket.socket, counters: Counters) -> None:
    with conn:
        while True:
            data = conn.recv(65_535)
            if not data:
                return
            counters.bytes_received += len(data)
            counters.max_chunk = max(counters.max_chunk, len(data))
            conn.sendall(data)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--seconds", type=float, default=900.0)
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
            thread = threading.Thread(target=handle, args=(conn, counters), daemon=True)
            thread.start()
            threads.append(thread)
    for thread in threads:
        thread.join(timeout=0.1)
    print(f"connections={counters.connections}")
    print(f"bytes_received={counters.bytes_received}")
    print(f"max_chunk={counters.max_chunk}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
