# Performance Analysis

This document records the performance characterization and optimization of the
Rust port relative to upstream Go, after cross-host runtime correctness was
proven. Parity and reliability are hard gates: every optimization below was kept
only if the two-network-namespace cross-host suite (IPv4 basic, 6-scenario
comprehensive, IPv6) stayed green and the full workspace tests stayed green.

## Headline Result

After the optimization work, on the two-namespace veth benchmark the Rust port
is faster than upstream Go on all four measured metrics (5-run medians):

| Metric | Rust | Go | Rust vs Go |
|---|---:|---:|---|
| TCP fresh connect + 64B RTT | 0.845 ms | 0.966 ms | ~13% faster |
| TCP persistent 64B RTT | 0.374 ms | 0.528 ms | ~29% faster |
| TCP throughput (4 MiB echo) | 817.7 Mbps | 400.1 Mbps | ~2.0x higher |
| UDP 64B RTT | 10.206 ms | 10.207 ms | parity |

The UDP RTT is at parity by construction, not by limitation: the benchmark
opens a fresh local UDP source port per datagram, so each measured round trip
pays a per-peer UDP-over-stream open (one QUIC stream + 1 RTT). Both Rust and Go
pay this identical, wire-protocol-determined cost; steady-state datagram RTT on a
reused association is far lower. Beating Go here would require diverging the
juicity UDP wire protocol, which is out of scope.

This is a local veth benchmark, not an Internet WAN benchmark. It measures
relative implementation behavior under identical kernel, namespace, and host
conditions; it does not replace profiling on real networks.

## Scope and Method

The comparison uses two Linux network namespaces connected by a veth pair. The
server namespace owns `10.210.0.1`, the client namespace owns `10.210.0.2`, and
the Juicity client forwards local TCP and UDP traffic over QUIC to TCP/UDP echo
services in the server namespace.

Measured paths:

- Fresh TCP connection plus 64-byte echo round trip through the Juicity forward.
- Persistent TCP 64-byte echo round trip through an already-open connection.
- TCP throughput for 4 MiB echo transfers.
- UDP 64-byte echo round trip through the UDP forward.

Run discipline:

- Five measured repetitions per implementation, implementation order rotated
  across repetitions.
- Each repetition uses 60 TCP connect-RTT samples, 60 persistent-RTT samples, 10
  throughput transfers, and 60 UDP-RTT samples.
- Headline values are the median of each repetition's median.

Harness and evidence (captured during the benchmark run):

- Runner: `run-perf-threeway-safe.sh`
- Harness wrapper: `perf-bench-safe.sh`
- Driver: `perf-driver-safe.py`
- Aggregator: `aggregate-perf-results.py`
- Final benchmark run: `perf-threeway-safe-20260621-032315/` (results.jsonl, aggregate.md)
- Cross-host re-verification: `final-verify-20260621-031850/`

## Compared Implementations

| Implementation | Binaries | Identity |
|---|---|---|
| Current Rust port | `./target/release/zuicity-client`, `./target/release/zuicity-server` | repo `zuicity` working tree; release build refreshed before each measurement; rustc 1.96.0 |
| Upstream Go Juicity | `/tmp/juicity-2ns/go-bin/juicity-client`, `/tmp/juicity-2ns/go-bin/juicity-server` | upstream repo HEAD `412dbe4`, built with go1.22.2 |
| Official `juicity/juicity-rs` release | `/root/projects/juicity/juicity-rs-other/juicity-client`, `/root/projects/juicity/juicity-rs-other/juicity-server` | `v0.1.0`, tag `v0.1.0.beta.2`, commit `7104f5f` |

The official `juicity/juicity-rs` release is runnable in the harness but unstable
under this workload (repeated throughput and UDP timeouts), so it is reported as
compatibility evidence, not a stable performance baseline.

## Optimization Sequence

Each change was evidence-driven, applied one at a time, and benchmarked. The
throughput figure shows the cumulative effect on the 4 MiB TCP throughput median.

### 1. Shared, reused QUIC connection in the client forwarders

Baseline behavior dialed a brand-new QUIC connection (full TLS 1.3 + auth
handshake) per accepted TCP connection and per new UDP local peer. Upstream Go
builds its juicity dialer once and reuses it for every forwarded connection
(`cmd/client/run.go:105`). The Rust forwarders now share a single lazily
established, auto-reconnecting authenticated QUIC connection
(`SharedQuicDialer` in `crates/zuicity-client/src/lib.rs`), opening a new stream
per relay instead of a new handshake. Health is checked via the quinn
connection `close_reason`, so the cache transparently reconnects after idle
close, server restart, or migration failure.

Effect: TCP fresh connect+RTT dropped from ~10.3 ms to ~0.9 ms (now faster than
Go); UDP setup similarly collapsed.

### 2. Concurrent per-stream server relay (goroutine-per-stream parity)

Reusing one connection exposed a server-side limit: the per-connection loop
relayed each accepted stream inline, so a long-lived UDP-over-stream blocked
acceptance of the next stream for the whole NAT idle window. Upstream Go
authenticates a connection once then spawns one goroutine per accepted stream
(`server/server.go`). The Rust serve
(`run_authenticated_proxy_connection_until`) now accepts streams in a loop and
spawns each relay concurrently into a `JoinSet`, matching Go. This was confirmed
with a negative control: an inline relay variant failed a multi-UDP-stream test
at the 5 s timeout; the concurrent variant passed in 0.12 s.

Effect: removed a second-datagram UDP timeout that connection reuse had exposed;
UDP RTT returned to parity with Go.

### 3. Relay copy buffer and TCP_NODELAY

The TCP relay used `tokio::io::copy` (8 KiB buffer) and left Nagle enabled. A
64 KiB relay copy buffer plus `set_nodelay(true)` on the local and target TCP
sockets were applied (larger buffers tested but 64 KiB was the knee). Latency
improved alongside throughput.

Effect: throughput 221 -> ~306 Mbps; latency unchanged or better.

### 4. Adaptive UDP GSO with per-path fallback

The remaining throughput gap was UDP segmentation offload. Upstream Go uses
Linux UDP GSO (`UDP_SEGMENT`) for QUIC egress. The Rust port had disabled GSO
because a kernel GSO probe can pass at startup while the actual egress drive
(veth, tun/VPN, virtio, many cloud NICs) rejects the `UDP_SEGMENT` control
message with `EINVAL` on the first handshake send, stranding the QUIC Initial
packet and timing out the connection (quinn-rs/quinn#2575, #2202).

The adaptive design (in `crates/zuicity-transport/src/lib.rs`) recovers GSO
throughput without that failure mode:

- GSO is attempted only for post-handshake, short-header, batched transmits.
  Long-header packets (QUIC Initial/Handshake, first byte high bit set) always
  take the plain one-datagram path, so the handshake is never segmented.
- The first real eligible transmit is the probe: a single `sendmsg` with the
  `UDP_SEGMENT` control message. On success the destination is marked working.
- On `EINVAL`/`EIO` the destination is marked GSO-disabled and the data is
  resent immediately, in the same call, as individual datagrams. No datagram is
  dropped.
- State is tracked per destination, so one GSO-hostile path does not disable GSO
  for other peers.
- No persistent socket-level `UDP_SEGMENT` option is set (only per-message
  control messages). The receive path is unchanged (no GRO/ECN/PMTUDISC).
- Mode is `Auto` by default on Linux; `ZUICITY_DISABLE_GSO=1` forces it off,
  mirroring upstream Go's `QUIC_GO_DISABLE_GSO`.

Cross-host verification showed GSO actually engaging on the veth path
(`udp gso engaged dest=...` on both client and server) while the IPv4 basic,
6-scenario comprehensive, and IPv6 suites all passed, proving the handshake
reliability is preserved.

Effect: throughput ~306 -> ~678 -> ~762 Mbps (now ~1.9x Go).

### 5. Non-blocking plain-send path (latent bug fix)

The custom `PlainUdpSocket` plain-send path, on a socket `WouldBlock`, slept the
tokio worker thread (`std::thread::sleep(1ms)`, up to 1024 times). Under rapid
loopback connection churn this starved co-scheduled handshake tasks and
intermittently tripped a benchmark connect deadline. A negative control proved
the trigger was the blocking sleep, not GSO: forcing GSO off still reproduced
the stall. The send path now performs one non-blocking send per datagram and
propagates `WouldBlock` to quinn, which re-arms writable readiness through the
poller's async `poll_writable` and retries without dropping packets.

Effect: fixed an intermittent connect-timeout under high connection churn;
removed a worker-thread-blocking sleep from the hot path.

### 6. GRO receive batching and socket buffer sizing

The send path used GSO but the receive path read one datagram per syscall, an
asymmetric bottleneck at multi-hundred-Mbps throughput. The receive path now
enables Linux UDP GRO so the kernel coalesces datagrams and one receive returns
a super-buffer that is split back into segments by quinn's segment-size cmsg
handling. The implementation reuses `quinn::udp::UdpSocketState` for the GRO
receive (correct cmsg parsing into per-datagram strides) under the workspace's
`unsafe_code = "forbid"` policy, while the send path remains the adaptive GSO
path. ECN is still forced off on the wire and the socket silently falls back to
the plain per-datagram receive if GRO setup fails on a hostile path. GRO is
gated by `ZUICITY_DISABLE_GRO=1`, default on for Linux. Send and receive socket
buffers are also sized up (4 MiB requested; the kernel clamps to its
`net.core.rmem_max`/`wmem_max`, verified via getsockopt).

A/B (GRO on vs off, 60-iter, repeated): throughput 750.7 -> 812.7 Mbps
(~+8.3%), latency-neutral, zero errors. The three-way benchmark median rose to
~817.7 Mbps (~2.0x Go). GRO is wire-invisible, so cross-host correctness and
handshake reliability are unaffected (verified by the two-namespace suite).

Effect: throughput ~762 -> ~818 Mbps (now ~2.0x Go), latency unchanged.

## Memory Footprint

Resident set size (RSS) was profiled under sustained connection churn followed by
idle, sampling the long-lived client and server processes on the two-namespace
path.

Findings:

- No leak. The client RSS plateaus during load and freezes flat on idle; the
  server RSS drifts up only during heavy new-connection churn and then freezes
  flat on idle (no further growth). The drift is glibc malloc arena page
  retention, not unbounded growth.
- Steady-state RSS is already small for a multi-threaded tokio + quinn proxy:
  roughly 11-13 MB client and 13-15 MB server with the default allocator.

The QUIC receive/stream/connection windows are intentionally large (2/32/32/64
MiB) because they are load-bearing for the 2x-Go throughput; shrinking them would
regress throughput, so they are left as is.

The one safe, zero-regression reduction is glibc allocator tuning applied via the
process environment (so it takes effect before the allocator initializes):

- `MALLOC_ARENA_MAX=2`
- `MALLOC_TRIM_THRESHOLD_=131072`

A/B over repeated trials (90 s churn + idle per trial): throughput held at ~770
Mbps in both arms (tuned marginally higher, within noise), while peak client RSS
dropped about 25% (~12.7 MB -> ~9.4 MB) and server RSS dropped about 5-8%. These
variables are wired into the shipped systemd units (`install/*.service`) so
deployed binaries get the lower footprint by default without any code change and
without touching the `unsafe_code = "forbid"` invariant.

Effect: about 25% lower client RSS and a smaller server footprint with no
throughput, latency, reliability, or compatibility regression.

## Reliability Invariants (preserved throughout)

- The client dialer binds the unspecified address of the server's family
  (`0.0.0.0`/`[::]`), never loopback, so cross-host egress works.
- Authentication happens once per connection.
- QUIC Initial/Handshake (long-header) packets are never segmented.
- GSO falls back per destination on `EINVAL`/`EIO` and never drops a datagram.
- The receive path adds GRO (coalesce only, wire-invisible) but carries no ECN
  feedback on the wire and no PMTUDISC; it falls back to plain receive on
  GRO-hostile paths.

## Validation Gates (all green at completion)

- `cargo fmt --all -- --check`
- `cargo check --workspace --all-targets`
- `cargo test --workspace --all-targets --exclude zuicity-benchmarks`
- `cargo test -p zuicity-benchmarks --test first_slice_smoke -- --test-threads=1`
- `python3 scripts/validate-packaging.py`
- Cross-host: `two-ns-runtime.sh`, `two-ns-comprehensive.sh`, `two-ns-ipv6.sh`
- New regression tests: connection reuse (TCP and UDP), concurrent multi-UDP
  stream reuse, GSO fallback resends both datagrams and marks the destination
  disabled, handshake survives a GSO-hostile path, long-header packets are neve
  segmented.

## Limitations

- Local single-host veth benchmark; absolute numbers differ on physical NICs and
  WAN links.
- Measures end-to-end forwarding through echo services, not isolated QUIC library
  primitives.
- The official `juicity/juicity-rs` release timed out during the benchmark, so
  its numbers are not a stable ranking.
- GSO throughput depends on kernel/NIC support; on GSO-hostile paths the port
  falls back to the plain path and tracks closer to the pre-GSO throughput while
  remaining correct.
