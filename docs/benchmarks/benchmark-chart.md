# zuicity QUIC proxy: performance comparison

Two-namespace veth benchmark, median of 5 reps per implementation.

| Implementation | TCP connect+RTT (ms) | TCP persistent RTT (ms) | TCP throughput (Mbps) | UDP RTT (ms) |
|---|---:|---:|---:|---:|
| zuicity (this port) | 0.96 | 0.41 | 621 | 10.35 |
| juicity (Go upstream) | 1.15 | 0.60 | 353 | 10.35 |
| juicity-rs (other) | 29.04 | 0.49 | 8.57 | 29.20 |

Lower is better for RTT metrics; higher is better for throughput.
