#!/usr/bin/env python3
from __future__ import annotations

import argparse
import socket
import time


def parse_sizes(raw: str) -> list[int]:
    return [int(part) for part in raw.split(",") if part]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", required=True)
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--sizes", default="1200,1280,1400,4096,9000")
    parser.add_argument("--count", type=int, default=12)
    parser.add_argument("--interval", type=float, default=0.05)
    args = parser.parse_args()
    sizes = parse_sizes(args.sizes)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(0.25)
    packets = 0
    bytes_sent = 0
    replies = 0
    with sock:
        for size in sizes:
            payload = bytes([size % 251]) * size
            for _index in range(args.count):
                bytes_sent += sock.sendto(payload, (args.host, args.port))
                packets += 1
                try:
                    sock.recvfrom(65_535)
                    replies += 1
                except socket.timeout:
                    pass
                time.sleep(args.interval)
    print(f"packets={packets}")
    print(f"bytes_sent={bytes_sent}")
    print(f"replies={replies}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
