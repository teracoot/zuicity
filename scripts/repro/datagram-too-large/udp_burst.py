#!/usr/bin/env python3
from __future__ import annotations

import argparse
import socket
import time


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", required=True)
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--size", type=int, required=True)
    parser.add_argument("--count", type=int, default=100)
    parser.add_argument("--interval", type=float, default=0.0)
    parser.add_argument("--recv", action="store_true")
    args = parser.parse_args()

    payload = bytes([args.size % 251]) * args.size
    sent = 0
    replies = 0
    max_reply = 0
    started = time.monotonic()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(0.01)
        for _index in range(args.count):
            sent += sock.sendto(payload, (args.host, args.port))
            if args.recv:
                while True:
                    try:
                        data, _addr = sock.recvfrom(65_535)
                    except socket.timeout:
                        break
                    replies += 1
                    max_reply = max(max_reply, len(data))
            if args.interval:
                time.sleep(args.interval)
    elapsed = max(time.monotonic() - started, 0.001)
    print(f"size={args.size}")
    print(f"packets={args.count}")
    print(f"bytes_sent={sent}")
    print(f"replies={replies}")
    print(f"max_reply={max_reply}")
    print(f"seconds={elapsed:.3f}")
    print(f"send_mbps={(sent * 8 / elapsed / 1_000_000):.3f}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
