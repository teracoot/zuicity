# Zuicity v0.4.0: matched four-product benchmark

Two-namespace veth matched four-product benchmark; median of 8 accepted rotation-level row medians.

| Implementation | GSO | TCP connect+RTT (ms) | TCP persistent RTT (ms) | TCP throughput (Mbps) |
|---|---|---:|---:|---:|
| Zuicity v0.4.0 | on | 0.790 | 0.374 | 1278.97 |
| Stock Go v0.5.0 | on | 0.845 | 0.513 | 721.44 |
| Repaired Go v0.5.0 | on | 0.880 | 0.517 | 986.70 |
| juicity-rs beta.8 | on | 30.936 | 2.709 | 25.98 |
| Zuicity v0.4.0 | off | 0.890 | 0.403 | 737.47 |
| Stock Go v0.5.0 | off | 0.929 | 0.517 | 601.83 |
| Repaired Go v0.5.0 | off | 0.890 | 0.510 | 598.31 |
| juicity-rs beta.8 | off | 28.906 | 1.732 | 5.67 |

Lower is better for RTT; higher is better for throughput.

The common throughput payload was 512 KiB, not the canonical 4 MiB.
