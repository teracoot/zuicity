#!/usr/bin/env bash
# Canonical release-comparison entry point. See README.md for manifest setup.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec python3 "$HERE/tcp_gso_suite.py" run "$@"
