# zuicity three-way performance benchmark

Reproducible comparison of three juicity implementations over a real
cross-host path:

| Implementation | What it is |
|---|---|
| `zuicity` (this repo) | The Rust port being developed here |
| `juicity` (Go) | Upstream Go juicity (`github.com/juicity/juicity`) |
| `juicity-rs` (other) | The separate Rust reimplementation (`github.com/juicity/juicity-rs`) |

The benchmark runs each implementation's client and server in two separate
Linux network namespaces joined by a `veth` pair, so traffic crosses a real
IP stack and real QUIC — not loopback. It measures four metrics (median of N
repetitions, implementation order rotated to cancel ordering bias):

- TCP connect+RTT (fresh connection + 64-byte echo), ms, lower is better
- TCP persistent RTT (64-byte echo on a kept-open connection), ms, lower is better
- TCP throughput (4 MiB echo transfer), Mbps, higher is better
- UDP RTT (64-byte datagram echo), ms, lower is better

## Requirements

- Linux with `CAP_NET_ADMIN` (run as root; it creates network namespaces)
- `python3`, `openssl`, `iproute2` (`ip`)
- A Rust toolchain (to build this port) and a Go toolchain (to build upstream)
- `unzip`, `curl` (to fetch the other juicity-rs release)

Works on any modern Linux host.

## 1. Build / fetch the three implementations

```bash
# (a) This Rust port
cargo build --release --bin zuicity-client --bin zuicity-server
mkdir -p /tmp/jbench/rust
cp target/release/zuicity-client target/release/zuicity-server /tmp/jbench/rust/

# (b) Upstream Go juicity
git clone https://github.com/juicity/juicity /tmp/juicity-go-src
mkdir -p /tmp/jbench/go
( cd /tmp/juicity-go-src
  go build -o /tmp/jbench/go/juicity-server ./cmd/server
  go build -o /tmp/jbench/go/juicity-client ./cmd/client )

# (c) The other juicity-rs (latest release, x86_64 musl)
mkdir -p /tmp/jbench/other && cd /tmp/jbench/other
curl -fSL \
  https://github.com/juicity/juicity-rs/releases/latest/download/juicity-x86_64-unknown-linux-musl.zip \
  -o juicity-rs.zip
unzip -o juicity-rs.zip
chmod +x juicity-client juicity-server
```

> Tip: the rust dir must contain binaries named exactly `zuicity-client` and
> `zuicity-server`, while the Go and other-rs dirs must contain `juicity-client`
> and `juicity-server`. To pin a specific juicity-rs release instead of `latest`,
> replace `latest/download` with `download/<tag>` (e.g. `download/v0.1.0.beta.3`).

## 2. Run the comparison

```bash
sudo scripts/benchmark/run-comparison.sh \
  --rust-dir  /tmp/jbench/rust \
  --go-dir    /tmp/jbench/go \
  --other-dir /tmp/jbench/other \
  --reps 5 --iters 60
```

Output lands in `benchmark-results/<timestamp>/`:

- `results.jsonl` - one JSON object per implementation run (raw metrics)
- `benchmark-chart.svg` - the comparison chart (renders in any browser / GitHub)
- `benchmark-chart.png` - PNG version (if `rsvg-convert`/`inkscape`/`convert` is present)
- `benchmark-chart.md` - a Markdown summary table

## 3. Re-render the chart from existing data

If you already have a `results.jsonl`, regenerate the chart without re-running
the benchmark:

```bash
python3 scripts/render-benchmark-chart.py <path>/results.jsonl \
  --out-dir <path> \
  --title "zuicity QUIC proxy: performance comparison"
```

The chart renderer is pure Python (standard library only) and always writes an
SVG + Markdown; a PNG is produced if an SVG converter is installed.

## 4. Excel spreadsheet (performance + memory)

`docs/benchmarks/benchmark-comparison.xlsx` is a formatted spreadsheet that
combines the four performance metrics with memory usage (peak and idle resident
set size for client and server) for all three implementations.

To regenerate it you need `results.jsonl` (performance) and `memory.jsonl`
(memory), plus the `openpyxl` library (`apt-get install python3-openpyxl` or
`pip install openpyxl`):

```bash
python3 scripts/render-benchmark-xlsx.py \
  --results docs/benchmarks/results.jsonl \
  --memory  docs/benchmarks/memory.jsonl \
  --out     docs/benchmarks/benchmark-comparison.xlsx
```

`memory.jsonl` is produced by running each implementation under sustained TCP
load while sampling its client and server RSS. Each line is one JSON object:
`{tag, client_peak_rss_kb, server_peak_rss_kb, client_idle_rss_kb,
server_idle_rss_kb}`.

## Notes on interpretation

- This is a single-host `veth` benchmark. Absolute numbers differ on physical
  NICs and over the Internet; it is meant for relative comparison under
  identical kernel/host conditions.
- UDP RTT is dominated by the per-peer UDP-over-stream setup that all juicity
  implementations pay (the driver uses a fresh local source port per datagram),
  so equal UDP RTT between two implementations is expected.
- All three implementations share the same `run -c <config.json>` CLI and the
  same config schema, which is what makes the single harness able to drive them.
