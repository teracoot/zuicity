# Zuicity Benchmark Guidelines

This document defines the benchmark protocol for comparing three Juicity runtime
entries across local veth and WAN Oracle paths. It exists because earlier ad hoc
runs mixed sample counts, host labels, and memory collection methods, which made
the resulting spreadsheets hard to compare.

## Privacy Rules

- Reports, filenames, charts, and spreadsheets must use anonymized host labels
  only: `oracle-a`, `oracle-b`, and `oracle-target`.
- Do not write personal host nicknames, public IP addresses, SSH usernames,
  private key paths, tokens, UUIDs, passwords, SNI names, or certificate paths
  into benchmark output.
- Raw connection profiles may be used locally to run a benchmark, but their
  contents must never be copied into this repository or benchmark artifacts.
- If an old raw artifact contains personal labels, rewrite the public report with
  anonymized labels before publishing or sharing.

## Required Entries

Every benchmark round must include exactly these three entries unless the report
explicitly marks an entry as blocked:

| Public label | Meaning | Binary/config rule |
| --- | --- | --- |
| `go-dae` | Go/dae baseline for Juicity traffic | Use the Go baseline client/server or dae route that owns the comparison target. Record the exact commit or release. |
| `zuicity-prev` | Previous accepted Zuicity build | Use the last accepted release artifact, not a rebuild from current sources. |
| `zuicity-current` | Current Zuicity build under review | Use the binary built from the exact worktree/commit being evaluated. |

Do not compare a debug build against release binaries. Do not mix zigbuild and
native cargo artifacts unless the report says so and gives hashes for both.

## Required Topologies

### Local veth

Run each entry in two Linux network namespaces connected by a veth pair. Traffic
must cross the kernel IP stack and QUIC stack; localhost-only proxy smoke tests
do not count as a benchmark.

Required metrics per entry:

- TCP fresh connect + 64-byte RTT: `n`, mean, median, p95, min, max in ms.
- TCP persistent 64-byte RTT on one kept-open connection: same fields.
- TCP throughput: 4 MiB echo transfer, mean/median/min/max in Mbps.
- UDP 64-byte RTT: same latency fields.
- Client and server RSS: baseline, peak, and post-run idle KiB or MiB.
- Driver errors and timeout counts.

Default local settings:

- `reps=5` rotated across entries to reduce ordering bias.
- `iters=60` for RTT metrics.
- At least 5 throughput transfers per implementation run.
- One clean output directory per benchmark run.

### WAN Oracle Paths

Run the same three entries over both real Internet client paths:

- `oracle-a -> oracle-target`
- `oracle-b -> oracle-target`

The WAN harness should start temporary benchmark clients, servers, and echo
targets on non-production ports. It must not replace release assets, restart
unrelated services, alter firewall defaults, or disturb live UDP ports. If an
existing service must be stopped, the report must treat that as a separate
operator-approved maintenance action and record the restore command and final
health check.

Required WAN metrics per path and entry:

- TCP fresh connect RTT, TCP persistent RTT, TCP throughput, and UDP RTT.
- Server RSS on `oracle-target`; client RSS on `oracle-a`/`oracle-b` when
  available.
- Packet loss/timeouts/errors.
- Base network RTT sample between client host and target host before each run.

## Consistency Rules

- Build or fetch all entries before timing starts. Record SHA256 for every
  client and server binary.
- Run entries in rotated order, not grouped by implementation.
- Keep server configs equivalent: same UUID/password class, same congestion
  control, same TLS/SNI policy, same target echo service, same payload sizes.
- Warm up every entry before recording metrics.
- Record kernel, distro, CPU model, CPU governor, NIC/offload state when
  available, and whether `ZUICITY_ENABLE_GSO` or `ZUICITY_WORKER_THREADS` is set.
- Store raw JSONL. Spreadsheets and charts are derived artifacts, not evidence.
- Publish medians for local veth and averages only when the harness explicitly
  defines averages. Do not mix medians and means in one table without labels.
- A run with any driver error is not a clean win, even if some metrics look good.

## Output Layout

Use this structure for each benchmark session:

```text
benchmark-results/<timestamp>/
  veth/
    results.jsonl
    memory.jsonl
    benchmark-chart.md
    benchmark-chart.svg
    summary.md
    binaries.sha256
  wan/
    oracle-a/results.jsonl
    oracle-a/memory.jsonl
    oracle-b/results.jsonl
    oracle-b/memory.jsonl
    summary.md
  SHA256SUMS
```

The public summary must include the exact command lines, sample counts, all
warnings/blockers, and a clear go/no-go conclusion.

## Local Command Pattern

Prepare directories with the expected binary names:

```bash
mkdir -p /tmp/jbench/go-dae /tmp/jbench/zuicity-prev /tmp/jbench/zuicity-current
# go-dae:        juicity-client, juicity-server
# zuicity-prev:  zuicity-client, zuicity-server from the previous accepted release
# zuicity-current: zuicity-client, zuicity-server from the current build
```

Run each entry through `scripts/benchmark/bench-one.sh` in rotated order, capture
all JSON lines, and append RSS samples to `memory.jsonl` when RSS sampling is
enabled. `scripts/benchmark/run-comparison.sh` is suitable for the historical
`rust/go/juicityrs` naming scheme; for the labels in this guideline, use a
wrapper that preserves `go-dae`, `zuicity-prev`, and `zuicity-current` in raw
JSONL.

## WAN Command Pattern

Use a SOCKS5 benchmark client equivalent to the historical WAN harness:

```bash
python3 bench_client.py \
  --label oracle-a \
  --implementation zuicity-current \
  --proxy-host 127.0.0.1 \
  --proxy-port 21080 \
  --target-host 127.0.0.1 \
  --tcp-port 28080 \
  --udp-port 28081 \
  --runs 5 \
  --connect-samples 20 \
  --persistent-samples 100 \
  --udp-samples 50 \
  --throughput-bytes 33554432
```

The command above is a shape, not a license to expose host details. Substitute
hosts and ports from private connection profiles at runtime only, and save output
under anonymized `oracle-a`/`oracle-b` paths.
