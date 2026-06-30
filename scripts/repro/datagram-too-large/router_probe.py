#!/usr/bin/env python3
from __future__ import annotations

import argparse
import shlex
import subprocess


LOG_GREP = "skoracle|55211|55212|55213|55214|DATAGRAM|frame too large|Application error|handleConn|handlePkt|retry|outbound=test|dialer=aws15"


def build_remote_command(since: str, until: str, lines: int) -> str:
    journal = [
        "journalctl",
        "-u",
        "dae",
        "--since",
        since,
        "--until",
        until,
        "--no-pager",
        "-o",
        "short-iso",
    ]
    grep = ["grep", "-E", LOG_GREP]
    tail = ["tail", f"-{lines}"]
    return (
        " ".join(shlex.quote(part) for part in journal)
        + " | "
        + " ".join(shlex.quote(part) for part in grep)
        + " | "
        + " ".join(shlex.quote(part) for part in tail)
        + " || true"
    )


def build_ssh_command(args: argparse.Namespace) -> list[str]:
    destination = f"{args.router_user}@{args.router_host}"
    command = ["ssh", "-p", str(args.router_port)]
    if args.identity_file is not None:
        command.extend(["-i", args.identity_file])
    for option in args.ssh_option:
        command.extend(["-o", option])
    command.append(destination)
    command.append(build_remote_command(args.since, args.until, args.lines))
    return command


def main() -> int:
    parser = argparse.ArgumentParser(description="Read-only dae journal probe for skOracle repro windows.")
    parser.add_argument("--since", required=True)
    parser.add_argument("--until", required=True)
    parser.add_argument("--router-host", default="192.168.100.1")
    parser.add_argument("--router-user", default="root")
    parser.add_argument("--router-port", type=int, default=22)
    parser.add_argument("--identity-file")
    parser.add_argument("--ssh-option", action="append", default=[])
    parser.add_argument("--lines", type=int, default=260)
    args = parser.parse_args()

    completed = subprocess.run(build_ssh_command(args), check=False, text=True)
    return completed.returncode


if __name__ == "__main__":
    raise SystemExit(main())
