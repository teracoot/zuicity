#!/usr/bin/env python3
from __future__ import annotations

import argparse
import socket
import time
from dataclasses import dataclass


@dataclass(slots=True)
class Counters:
    requests: int = 0
    replies: int = 0
    bytes_sent: int = 0
    errors: int = 0
    max_reply: int = 0


def parse_command(data: bytes) -> tuple[int, int, float]:
    text = data.decode("ascii", errors="ignore")
    size = 1200
    count = 1
    interval = 0.0
    for part in text.replace("\n", " ").split():
        key, sep, value = part.partition("=")
        if sep != "=":
            continue
        try:
            if key == "size":
                size = max(1, min(int(value), 65_507))
            elif key == "count":
                count = max(1, min(int(value), 200))
            elif key == "interval":
                interval = max(0.0, min(float(value), 1.0))
        except ValueError:
            continue
    return size, count, interval


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--seconds", type=float, default=3600.0)
    args = parser.parse_args()

    counters = Counters()
    deadline = time.monotonic() + args.seconds
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", args.port))
    sock.settimeout(1.0)
    with sock:
        while time.monotonic() < deadline:
            try:
                data, addr = sock.recvfrom(2048)
            except socket.timeout:
                continue
            counters.requests += 1
            size, count, interval = parse_command(data)
            payload = bytes([size % 251]) * size
            counters.max_reply = max(counters.max_reply, size)
            for _index in range(count):
                try:
                    counters.bytes_sent += sock.sendto(payload, addr)
                    counters.replies += 1
                except OSError:
                    counters.errors += 1
                if interval:
                    time.sleep(interval)
    print(f"requests={counters.requests}")
    print(f"replies={counters.replies}")
    print(f"bytes_sent={counters.bytes_sent}")
    print(f"max_reply={counters.max_reply}")
    print(f"errors={counters.errors}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
