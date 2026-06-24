# Zuicity Benchmarks

This crate contains the first production benchmark harness slice for the Zuicity port. It is intentionally isolated from production crates so benchmark dependencies do not leak into runtime builds.

## First Slice

The `first_slice` Criterion harness covers:

- config JSON parsing and validation
- loopback server runtime startup and shutdown
- Rust/Rust authenticated QUIC handshake
- Rust/Rust TCP relay echo hot path
- Rust/Rust UDP-over-stream echo hot path
- bounded concurrent Rust/Rust TCP clients
- bounded concurrent mixed-listener SOCKS5 UDP associations
- bounded server lifecycle TCP/UDP churn through the combined proxy loop
- mixed-listener HTTP CONNECT and SOCKS5 CONNECT TCP echo paths
- client forward-mode TCP and UDP echo paths
- live dae connector TCP and UDP echo paths
- server egress TCP direct, `send_through`, `fwmark`, SOCKS5 `dialer_link`, and HTTP CONNECT `dialer_link` paths
- server egress UDP direct, `send_through`, `fwmark`, and SOCKS5 `dialer_link` paths
- Linux current-process RSS memory snapshot smoke evidence
- release packaging automation elapsed-time and artifact-size snapshots

## Comparative TCP/UDP Latency Smoke

The public helpers `run_upstream_vs_rust_tcp_latency_comparison` and `run_upstream_vs_rust_udp_latency_comparison` build or reuse upstream `juicity-client` and `juicity-server`, then measure real TCP and UDP forward-mode echo round-trips through both the upstream Go stack and the embeddable Rust stack. They return completed iteration counts, echoed byte totals, and min/mean/max latency aggregates for both stacks.

This comparative proof intentionally lives in an integration smoke test instead of a Criterion bench because upstream process builds and lifecycle management are too slow and fragile for Criterion sampling.

## Artifact Runbook

Run from the repository root:

```bash
rm -rf /tmp/zuicity-benchmarks
mkdir -p /tmp/zuicity-benchmarks/logs

CARGO_TARGET_DIR=/tmp/zuicity-benchmarks/target \
  cargo check -p zuicity-benchmarks --benches \
  > /tmp/zuicity-benchmarks/logs/check-benches.txt 2>&1

CARGO_TARGET_DIR=/tmp/zuicity-benchmarks/target \
  cargo test -p zuicity-benchmarks --test first_slice_smoke -- --nocapture \
  > /tmp/zuicity-benchmarks/logs/test-first-slice-smoke.txt 2>&1

CARGO_TARGET_DIR=/tmp/zuicity-benchmarks/target \
  cargo test -p zuicity-benchmarks --test first_slice_smoke current_process_memory_snapshot_reports_nonzero_rss -- --nocapture \
  > /tmp/zuicity-benchmarks/logs/test-memory-snapshot.txt 2>&1

CARGO_TARGET_DIR=/tmp/zuicity-benchmarks/target \
  cargo test -p zuicity-benchmarks --test comparative_smoke upstream_vs_rust_tcp_latency_comparison_smoke -- --nocapture \
  > /tmp/zuicity-benchmarks/logs/test-comparative-smoke.txt 2>&1

CARGO_TARGET_DIR=/tmp/zuicity-benchmarks/target \
  cargo test -p zuicity-benchmarks --test comparative_smoke upstream_vs_rust_udp_latency_comparison_smoke -- --nocapture \
  > /tmp/zuicity-benchmarks/logs/test-comparative-udp-smoke.txt 2>&1

CARGO_TARGET_DIR=/tmp/zuicity-benchmarks/target \
  cargo bench -p zuicity-benchmarks --bench first_slice -- --save-baseline first-slice \
  > /tmp/zuicity-benchmarks/logs/bench-first-slice.txt 2>&1

CARGO_TARGET_DIR=/tmp/zuicity-benchmarks/target \
  cargo bench -p zuicity-benchmarks --bench first_slice -- concurrent_tcp_clients_rust_rust --save-baseline concurrent-tcp \
  > /tmp/zuicity-benchmarks/logs/bench-concurrent-tcp.txt 2>&1

CARGO_TARGET_DIR=/tmp/zuicity-benchmarks/target \
  cargo bench -p zuicity-benchmarks --bench first_slice -- concurrent_socks5_udp_associations_rust_rust --save-baseline concurrent-socks5-udp \
  > /tmp/zuicity-benchmarks/logs/bench-concurrent-socks5-udp.txt 2>&1

CARGO_TARGET_DIR=/tmp/zuicity-benchmarks/target \
  cargo bench -p zuicity-benchmarks --bench first_slice -- server_lifecycle_tcp_udp_churn_rust_rust --quiet \
  > /tmp/zuicity-benchmarks/logs/bench-server-lifecycle-churn.txt 2>&1

CARGO_TARGET_DIR=/tmp/zuicity-benchmarks/target \
  cargo bench -p zuicity-benchmarks --bench first_slice -- dae_connector --quiet \
  > /tmp/zuicity-benchmarks/logs/bench-dae-connector.txt 2>&1

CARGO_TARGET_DIR=/tmp/zuicity-benchmarks/target \
  cargo bench -p zuicity-benchmarks --bench first_slice -- server_egress_tcp --quiet \
  > /tmp/zuicity-benchmarks/logs/bench-server-egress-tcp.txt 2>&1

CARGO_TARGET_DIR=/tmp/zuicity-benchmarks/target \
  cargo bench -p zuicity-benchmarks --bench first_slice -- server_egress_udp --quiet \
  > /tmp/zuicity-benchmarks/logs/bench-server-egress-udp.txt 2>&1

CARGO_TARGET_DIR=/tmp/zuicity-benchmarks/target \
  cargo bench -p zuicity-benchmarks --bench first_slice -- mixed_ --quiet \
  > /tmp/zuicity-benchmarks/logs/bench-mixed-tcp.txt 2>&1

CARGO_TARGET_DIR=/tmp/zuicity-benchmarks/target \
  cargo bench -p zuicity-benchmarks --bench first_slice -- client_forward --quiet \
  > /tmp/zuicity-benchmarks/logs/bench-client-forward.txt 2>&1

scripts/benchmark-package-release.sh \
  --target x86_64-unknown-linux-gnu \
  --output-dir /tmp/zuicity-package-benchmark \
  --log-dir /tmp/zuicity-benchmarks/logs/packaging-release \
  --version benchmark-package-release \
  --skip-build \
  > /tmp/zuicity-benchmarks/logs/bench-package-release.txt 2>&1

scripts/package-apk-smoke.sh \
  --target x86_64-unknown-linux-gnu \
  --output-dir /tmp/zuicity-apk-smoke \
  --version benchmark-apk-smoke \
  --skip-build \
  > /tmp/zuicity-benchmarks/logs/package-apk-smoke.txt 2>&1
```

Expected artifacts:

- `/tmp/zuicity-benchmarks/logs/check-benches.txt`
- `/tmp/zuicity-benchmarks/logs/test-first-slice-smoke.txt`
- `/tmp/zuicity-benchmarks/logs/test-memory-snapshot.txt`
- `/tmp/zuicity-benchmarks/logs/test-comparative-smoke.txt`
- `/tmp/zuicity-benchmarks/logs/test-comparative-udp-smoke.txt`
- `/tmp/zuicity-benchmarks/logs/bench-first-slice.txt`
- `/tmp/zuicity-benchmarks/logs/bench-concurrent-tcp.txt`
- `/tmp/zuicity-benchmarks/logs/bench-concurrent-socks5-udp.txt`
- `/tmp/zuicity-benchmarks/logs/bench-server-lifecycle-churn.txt`
- `/tmp/zuicity-benchmarks/logs/bench-dae-connector.txt`
- `/tmp/zuicity-benchmarks/logs/bench-server-egress-tcp.txt`
- `/tmp/zuicity-benchmarks/logs/bench-server-egress-udp.txt`
- `/tmp/zuicity-benchmarks/logs/bench-mixed-tcp.txt`
- `/tmp/zuicity-benchmarks/logs/bench-client-forward.txt`
- `/tmp/zuicity-benchmarks/logs/bench-package-release.txt`
- `/tmp/zuicity-benchmarks/logs/package-apk-smoke.txt`
- `/tmp/zuicity-benchmarks/logs/packaging-release/package-release-benchmark.txt`
- `/tmp/zuicity-benchmarks/logs/packaging-release/package-release-command.log`
- `/tmp/zuicity-benchmarks/target/criterion/`
