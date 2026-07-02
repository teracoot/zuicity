# v0.2.2 veth benchmark evidence

Fast local two-network-namespace veth comparison. The client binary was held
constant at `zuicity-client 0.2.2`; only the server binary changed.

## Binaries

- Previous server: `zuicity-server version 0.2.1`, SHA256 `88ba21abd127ea5cfc441b731df584194c77c197c9e939fb0184893b322c28d8`
- New server: `zuicity-server version 0.2.2`, SHA256 `01719c0a54d53cefbfcf4421934121b3dd327f72210b39a32704252017bcd09e`
- Held-constant client: `zuicity-client version 0.2.2`, SHA256 `c79a7c0c3b0a1a50b222fa46e26e94154ec05b148c7e382abade843105cd3522`

## Performance medians

| Metric | 0.2.1 server | 0.2.2 server | Delta |
| --- | ---: | ---: | ---: |
| TCP connect+RTT median | 1.018 ms | 1.012 ms | -0.6% |
| TCP connect+RTT p95 | 1.644 ms | 1.463 ms | -11.0% |
| TCP persistent RTT median | 0.385 ms | 0.395 ms | +2.6% |
| TCP persistent RTT p95 | 0.526 ms | 0.468 ms | -11.0% |
| TCP throughput median | 107.59 Mbps | 101.25 Mbps | -5.9% |
| UDP RTT median | 10.273 ms | 10.242 ms | -0.3% |
| UDP RTT p95 | 10.834 ms | 10.569 ms | -2.4% |

## Server RSS medians

| Metric | 0.2.1 server | 0.2.2 server | Delta |
| --- | ---: | ---: | ---: |
| Peak server RSS | 8.95 MiB | 8.51 MiB | -4.9% |
| Post-run idle server RSS | 9.07 MiB | 9.33 MiB | +2.8% |

## Files

- `results.jsonl`: six native veth performance samples, three per server.
- `rss.jsonl`: six RSS-sampled veth runs, three per server.
- `binaries.sha256`: client and server binary identities used for the comparison.
- `SHA256SUMS`: hash manifest for this evidence directory.

No driver errors were reported in any captured sample.
