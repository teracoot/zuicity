# Vendored Quinn patches

This directory contains patched crates selected by the workspace's
`[patch.crates-io]` configuration.

## quinn 0.11.9

- Source: the `quinn` 0.11.9 crate published on crates.io.
- Patches: raise `MAX_TRANSMIT_SEGMENTS` from 10 to 128 so Quinn can expose the
  larger GSO batches selected by Zuicity's UDP transport, and raise the
  per-poll datagram budget from 20 to 88 so two 44-segment GSO transmits can be
  emitted before the connection driver yields.
- Ancillary change: trailing whitespace is normalized in `examples/README.md`.
- Licenses: MIT or Apache-2.0; see the crate's `LICENSE-MIT` and
  `LICENSE-APACHE` files.

## quinn-proto 0.11.14

- Source: the `quinn-proto` 0.11.14 crate published on crates.io.
- Patch: correct BBR bandwidth-filter handling so non-app-limited samples age
  the filter and app-limited samples can still raise its maximum.
- Proofs: regression tests are included in
  `src/congestion/bbr/bw_estimation.rs`.
- Licenses: MIT or Apache-2.0; see the crate's `LICENSE-MIT` and
  `LICENSE-APACHE` files.
