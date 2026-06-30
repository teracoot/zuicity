#!/usr/bin/env python3
from __future__ import annotations

import argparse
import socket
import time


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", required=True)
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--chunk", type=int, default=65_536)
    parser.add_argument("--chunks", type=int, default=256)
    parser.add_argument("--read-timeout", type=float, default=0.02)
    args = parser.parse_args()

    payload = bytes([args.chunk % 251]) * args.chunk
    sent = 0
    received = 0
    start = time.monotonic()
    with socket.create_connection((args.host, args.port), timeout=5.0) as sock:
        sock.settimeout(args.read_timeout)
        for _index in range(args.chunks):
            sock.sendall(payload)
            sent += len(payload)
            while True:
                try:
                    data = sock.recv(65_535)
                except socket.timeout:
                    break
                if not data:
                    break
                received += len(data)
        sock.shutdown(socket.SHUT_WR)
        while True:
            try:
                data = sock.recv(65_535)
            except socket.timeout:
                break
            if not data:
                break
            received += len(data)
    elapsed = max(time.monotonic() - start, 0.001)
    print(f"bytes_sent={sent}")
    print(f"bytes_received={received}")
    print(f"seconds={elapsed:.3f}")
    print(f"send_mbps={(sent * 8 / elapsed / 1_000_000):.3f}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
