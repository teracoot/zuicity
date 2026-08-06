# TCP GSO release benchmark

This directory contains the canonical local release-comparison suite. It runs
real TCP forwarding through Juicity client/server pairs in two Linux network
namespaces connected by a `veth` pair. Traffic crosses the kernel IP and QUIC
stacks; it is not a loopback microbenchmark.

The release-lineage example manifest compares these four implementations with
both GSO-on and GSO-off treatments:

| ID | Artifact |
| --- | --- |
| `candidate` | v0.4.0 candidate under review |
| `v030` | released v0.3.0 package |
| `v040-prior` | previous accepted v0.4.0 package |
| `go-repaired` | pinned Juicity Go v0.5.0 package with the full GSO repair |

`tcp-gso-v040-go-jrs.example.json` provides the product comparison across the
current candidate, stock Go, repaired Go, and the latest official
`github.com/juicity/juicity-rs` release. Its stock-Go on treatment uses shipping
client-off/server-on behavior. Because `juicity-rs` has no GSO-off runtime
switch, its off treatment uses a hash-pinned preload control that denies Quinn's
`UDP_SEGMENT` capability probe while leaving the release binaries unchanged.

The manifest, not a directory label, defines artifact identity. Every client and
server has a required SHA256, and execution stops before timing if any hash does
not match.

## Suite files

- `tcp_gso_suite.py` validates manifests, builds schedules, runs campaigns, and
  summarizes accepted rotation rows.
- `run-comparison.sh` is the canonical wrapper for `tcp_gso_suite.py run`.
- `bench-one-tcp.sh` is the internal namespace and process-accounting harness.
  `BENCH_ZUICITY_CONGESTION_CONTROL` may select `bbr`, `cubic`, or `new_reno`
  for both generated Zuicity endpoint configs; it defaults to `bbr`.
- `tcp-driver.py` generates fresh-connect RTT, persistent RTT, and TCP echo
  throughput samples with `TCP_NODELAY`.
- `echo-server.py` provides the isolated target service.
- `tcp-gso-v040-candidate.example.json` pins the current eight binaries and mode
  controls.
- `tcp-gso-v040-go-jrs.example.json` pins the requested four-product comparison,
  including the latest official `juicity-rs` artifacts and GSO-off control.
- `test_tcp_gso_suite.py` covers manifest validation, scheduling, trace parsing,
  and rotation-level inference.

The current `benchmark-chart.svg`, `.png`, and `.md` under `docs/benchmarks/`
were rendered from the qualified four-product suite summary. The spreadsheet,
`results.jsonl`, and `memory.jsonl` in that directory are historical products of
the retired three-way harness and must not be relabeled as v0.3.0/v0.4.0 release
evidence.

## Requirements

- Linux, root privileges, and network namespace support.
- `bash`, `python3`, `iproute2`, `openssl`, `timeout`, and `strace`.
- `taskset` from util-linux when `--cpus` is used. Standard and release profiles
  require CPU affinity.
- Prebuilt executable client/server artifacts matching every manifest hash.
- An unused output path. The suite refuses to overwrite an existing directory.

The suite checks for stale `zuicity-bench-*` namespaces and fails closed rather
than deleting unexplained state.

Direct `bench-one-tcp.sh` runs use BBR by default. Preserve the captured
`client.json` and `server.json` files as evidence:

```bash
sudo scripts/benchmark/bench-one-tcp.sh <row arguments>
```

`BENCH_ZUICITY_CONGESTION_CONTROL` exists for explicit controller experiments;
it does not change the BBR default. The setting affects only Zuicity JSON
generation. Comparator wrappers may ignore those generated files and apply
their own pinned congestion profile.

## Prepare and validate

Set the four artifact directories referenced by the example manifest:

```bash
export CANDIDATE_BIN_DIR=/path/to/candidate/build
export V030_BIN_DIR=/path/to/released-v0.3.0/build
export V040_PRIOR_BIN_DIR=/path/to/prior-v0.4.0/build
export GO_REPAIRED_BIN_DIR=/path/to/repaired-go

python3 scripts/benchmark/tcp_gso_suite.py validate \
  --manifest scripts/benchmark/tcp-gso-v040-candidate.example.json
```

When privilege elevation is needed, preserve only those path variables:

```bash
sudo --preserve-env=CANDIDATE_BIN_DIR,V030_BIN_DIR,V040_PRIOR_BIN_DIR,GO_REPAIRED_BIN_DIR \
  scripts/benchmark/run-comparison.sh \
  --manifest scripts/benchmark/tcp-gso-v040-candidate.example.json \
  --out-dir benchmark-results/tcp-gso-$(date -u +%Y%m%dT%H%M%SZ) \
  --profile standard \
  --cpus 2-5
```

Use a CPU set suitable for the host. Do not reuse `2-5` without confirming its
topology and availability.

To inspect the schedule without executing binaries:

```bash
python3 scripts/benchmark/tcp_gso_suite.py schedule \
  --manifest scripts/benchmark/tcp-gso-v040-candidate.example.json \
  --blocks 1
```

## Profiles

| Profile | Rotations | Rows | RTT samples/row | Throughput samples/row | Payload | Warmups | Canonical |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| `smoke` | 1 | 8 | 2 | 3 | 1 MiB | 1 | No, incomplete square |
| `standard` | 8 | 64 | 60 | 100 | 4 MiB | 5 | Yes, one Williams block |
| `release` | 16 | 128 | 60 | 100 | 4 MiB | 5 | Yes, two blocks |

The eight treatments are scheduled as an even-treatment Williams square. One
complete block balances treatment position and first-order carryover. The second
release block traverses the rotations in reverse order. `smoke` exists only to
verify execution, probes, cleanup, and output shape; its performance numbers are
not ranking evidence.

Explicit sample/profile overrides are useful for development, but an overridden
campaign must describe those changes and should not be represented as the
standard or release protocol.

## GSO verification

Before measured rows, the suite runs one traced probe for every implementation
and mode. The probes use `strace` on `setsockopt`, `sendmsg`, and `sendmmsg`;
measured rows are not traced.

Probe traffic is deliberately small and is not a workload qualification. A mode
may explicitly accept a driver error after the required syscall evidence is
captured; this is used for latest `juicity-rs`, whose packet path becomes
pathologically slow under `strace`. Its untraced workload must still pass the
full measured-row contract, and any failure is retained and retried normally.

- GSO-on requires at least one successful `UDP_SEGMENT` data send.
- GSO-off requires zero `UDP_SEGMENT` data-send attempts.
- Every mode requires zero `UDP_SEGMENT` capability probes or persistent
  socket-option writes.
- The parser recognizes symbolic and numeric (`0x67`/`103`) forms in both
  `setsockopt` probes and send control messages under `SOL_UDP` or
  `IPPROTO_UDP`.
- Any failed probe, driver error, hash mismatch, or malformed result stops the
  campaign.

The pinned controls are:

| Family | GSO on | GSO off |
| --- | --- | --- |
| Rust | `ZUICITY_ENABLE_GSO=1`; unset `ZUICITY_DISABLE_GSO` | `ZUICITY_DISABLE_GSO=1`; unset `ZUICITY_ENABLE_GSO` |
| Go | `QUIC_GO_DISABLE_GSO=` | `QUIC_GO_DISABLE_GSO=true` |
| `juicity-rs` | Unmodified Quinn default | Unmodified release binary plus hash-pinned external `UDP_SEGMENT` capability denial |

Zuicity remains GSO-off unless explicitly enabled. `ZUICITY_DISABLE_GSO` takes
precedence if both variables are set.

## Statistical contract

The inference unit is one accepted rotation-level row median. Transfer samples
within a row are retained as raw evidence but are never treated as independent
replicates. Comparisons pair the reference and comparator rows from the same
rotation and GSO mode. Reports include paired median percent changes,
wins/losses/ties, and an exact one-sided sign test.

Host gates cover pre-row CPU activity, background CPU activity, frequency ratio,
and temperature when the host exposes those monitors. A rejected row is retained
in `rejected.jsonl` and retried up to `--max-row-attempts`. Monitor availability
is part of the summary and must be disclosed; missing telemetry is not silently
invented.

## Output

Each campaign creates:

```text
<out-dir>/
  captures/<row-tag>/
  meta/binaries.sha256
  meta/harness.sha256
  meta/host.json
  meta/method.json
  meta/resolved-manifest.json
  meta/schedule.json
  meta/versions/
  probes.jsonl
  rejected.jsonl
  results.jsonl
  summary.json
  summary.md
```

Raw probe traces can be large. Inspect file sizes before opening them and prefer
the bounded `probes.jsonl`, `summary.json`, and `summary.md` records first.

## Historical provenance

The remembered no-GSO result of 731.27 versus 660.86 Mbps was an `h156`
development artifact, not released v0.3.0. It also used a different Go client
from the repaired-Go package. The shared Go server hash does not make the client
pair equivalent.

| Artifact | Client SHA256 | Server SHA256 |
| --- | --- | --- |
| `h156` development build | `54a3d58247d2af84b8238b8b58f1e300a649b62dd3e67f838a77ceae79027e` | `42409a818639e38d56167a5a2edd1571ff81fe59782395031a606c467674262e` |
| Historical Go comparator | `a98d80d659cf4c7cbd1b8cca0c977f84d0ab1251194421714a6877cd5744abbf` | `f5af206e9f49c00ec7399da39da49a861c0b4081716604b7fd8c379304780198` |
| Released v0.3.0 | `c4abab90572efdbf825192ed35fbf4591d54cb854a14964b00c45a2517588f48` | `a6641746add705dd27ac6d8dc19663baf7582743234a3e2f37054ccb97be19b8` |
| Repaired Go | `995c20ddc6a10e9bf6e589bb09538c5692029ac4748cd4bcf684e4732091fafb` | `f5af206e9f49c00ec7399da39da49a861c0b4081716604b7fd8c379304780198` |
| Prior v0.4.0 | `3d749a927d6ee0c6d4f7a4af917554ccacf364a12a95e02f23ea2b7ba562d3ba` | `600e93e3b3ddffb19513abbb65fd9882ec8267e85a729956fcf74e1117d20c4a` |
| Current candidate | `079c7716959a2d05a02de74af4dddbb7df44fa18e5a9e04edff8ddc7ed75e3e7` | `cec42e54cd06e6861894352b635e22d04f08f2693cdb395f9649be426658b5a1` |

| Campaign | Rust artifact | Go artifact | GSO | Rust median | Go median | Result |
| --- | --- | --- | --- | ---: | ---: | --- |
| 2026-07-26 historical run | `h156` | historical Go | off | 731.27 Mbps | 660.86 Mbps | `h156` +10.654% |
| 2026-07-28 contemporaneous run | released v0.3.0 | repaired Go | off | 202.335 Mbps | 288.74 Mbps | v0.3.0 lost |
| 2026-07-28 repeat | released v0.3.0 | repaired Go | off | 193.095 Mbps | 267.62 Mbps | v0.3.0 lost |
| 2026-07-30 four-arm predecessor | released v0.3.0 | repaired Go | off | 137.76 Mbps | 449.98 Mbps | v0.3.0 lost |

The 2026-07-26 method used 60 fresh-connect samples, 60 persistent samples, 10
throughput samples, and a 4 MiB send-plus-full-echo operation per row with
transmit GSO forced off. Its result is valid for those exact hashes and method,
but it cannot support a claim about released v0.3.0.

The 2026-07-30 four-arm predecessor additionally reported these row medians:

| Mode | Candidate | Prior v0.4.0 | Repaired Go | Released v0.3.0 |
| --- | ---: | ---: | ---: | ---: |
| GSO on | 1378.505 | 862.455 | 728.51 | 490.02 |
| GSO off | 725.50 | 600.79 | 449.98 | 137.76 |

Those predecessor campaigns are retained as historical evidence, not as output
from the canonical combined-treatment suite. New release claims must use a
versioned manifest, complete Williams block, strict probes, and accepted
rotation-level rows.

## Validation

Run the local checks without creating namespaces:

```bash
python3 -m py_compile \
  scripts/benchmark/tcp-driver.py \
  scripts/benchmark/tcp_gso_suite.py
bash -n scripts/benchmark/bench-one-tcp.sh
python3 scripts/benchmark/test_tcp_gso_suite.py
```
