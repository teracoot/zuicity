#!/usr/bin/env python3
from __future__ import annotations

import argparse
import socket
import time
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class Config:
    port: int
    seconds: float


def serve(config: Config) -> tuple[int, int, int]:
    deadline = time.monotonic() + config.seconds
    packets = 0
    bytes_received = 0
    max_len = 0
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", config.port))
    sock.settimeout(1.0)
    with sock:
        while time.monotonic() < deadline:
            try:
                data, addr = sock.recvfrom(65_535)
            except socket.timeout:
                continue
            packets += 1
            bytes_received += len(data)
            max_len = max(max_len, len(data))
            sock.sendto(data, addr)
    return packets, bytes_received, max_len


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--seconds", type=float, default=300.0)
    args = parser.parse_args()
    packets, bytes_received, max_len = serve(Config(port=args.port, seconds=args.seconds))
    print(f"packets={packets}")
    print(f"bytes_received={bytes_received}")
    print(f"max_len={max_len}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
