# Production-Readiness Test Handoff

This is the release qualification procedure for Zuicity and a starting point
for higher-risk network services built from it. It defines blocking gates,
acceptance criteria, evidence, deployment checks, and approval ownership. It is
a procedure, not a claim that the current checkout or any future candidate has
passed.

Run every required gate against the exact binaries proposed for release. A
historical result, a successful debug build, or a test of another binary hash
does not qualify a candidate.

The words **must**, **should**, and **may** are normative. Any waived must-pass
gate needs a written risk acceptance naming the failed gate, affected artifact,
owner, expiry, and rollback plan.

## Scope and privacy

This procedure covers:

- Rust formatting, linting, compilation, unit tests, integration tests,
  doctests, and all-target tests.
- Wire framing, authentication, malformed input, timeout, cancellation,
  shutdown, and resource ownership.
- Persistent QUIC connections, TCP forwarding, UDP-over-stream, SOCKS5 TCP,
  SOCKS5 UDP ASSOCIATE, HTTP CONNECT, and server egress proxies.
- Concurrency, reconnects, peer loss, backpressure, stress, leak tests, and
  soaks.
- Upstream interoperability, generated differential tests, and the vendored
  Quinn suites.
- Native Windows and WSL/Linux parity, Linux GSO/GRO behavior, local `veth`
  benchmarks, matched Hysteria2 comparison, and real WAN testing.
- Packaging, artifact digests, deployment smoke, canary, rollback, service
  health, observability, and production approval.
- Additional security, fuzzing, chaos, capacity, and disaster-recovery gates
  for a higher-risk project.

Do not put credentials, UUIDs, tokens, private keys, private certificate paths,
SSH identities, public IP addresses, or private SNI names in repository files or
public test artifacts. Use anonymized host labels and inject secrets at runtime.
Redact logs before publication. A private operator evidence store may retain
encrypted connection profiles separately from the public test packet.

## Release packet

Create an immutable evidence directory before testing. A recommended shape is:

```text
release-evidence/<version>-<utc-time>/
  meta/
    candidate.json
    source.txt
    toolchains.txt
    host-windows.txt
    host-linux.txt
    binaries.sha256
    test-plan.md
    exceptions.md
  static/
  windows/
  linux/
  interop/
  stress/
  benchmarks/
  packages/
  security/
  deployment/
  approval.md
```

`candidate.json` must identify the source commit, tree state, tag, build
workflow/run, compiler, build flags, target, binary names, and full SHA-256
hashes. Record whether the tree was clean; a dirty tree requires an archived
patch and cannot be represented as the named commit alone. `test-plan.md` must
freeze thresholds, environments, campaign manifests, and expected capability
skips before execution.

Capture command lines, exit status, stdout/stderr, start/end timestamps, host
metadata, and tool versions. On Linux, use `set -o pipefail` when piping output
through `tee`. On PowerShell, inspect `$LASTEXITCODE` after native commands.
Never replace a failed log with a successful retry: preserve both and document
the disposition.

Retain the final packet for at least one year and through two successor
releases, whichever is longer. Retain source, manifests, summaries, hashes, and
approval records longer if required by the product's incident-response or
compliance policy.

## Required environments

| Environment | Required purpose |
| --- | --- |
| Native Windows x86-64 | Workspace build/test, CLI process behavior, TCP/UDP runtime behavior, and vendored Quinn parity |
| WSL2 or native Linux x86-64 | Full workspace tests, Linux process semantics, GSO/GRO, leak/soak tests, packaging, and network namespaces |
| Hosted release matrix | Every supported archive target, native macOS/Windows rows, source archive, and digest production |
| Upstream Juicity fixture | Rust-client/Go-server and Go-client/Rust-server TCP/UDP interoperability |
| External SOCKS5 implementation | Authenticated TCP interoperability and invalid-password rejection |
| Isolated Linux benchmark host | Two-namespace `veth` campaigns with CPU, syscall, and resource controls |
| At least two real hosts | Cross-host/WAN TLS, TCP, UDP, reconnect, loss, and performance behavior |
| Staging/canary host | Installation, service management, monitoring, backup, rollback, and production-shaped traffic |

Use the same candidate hashes in every environment. If a target necessarily has
different bytes, tie every target hash to the same source identity and release
workflow. Capability skips are acceptable only when the capability is truly
absent, the skip is explicit in the log, and an environment that supports the
capability passes the same gate.

## Gate summary

| ID | Gate | Blocking acceptance |
| --- | --- | --- |
| G0 | Candidate freeze | Source, toolchains, flags, packages, and hashes are complete and immutable |
| G1 | Static quality | Format, compile, lint, and packaging validation exit zero with no unreviewed warning |
| G2 | Functional tests | Unit, integration, doctest, all-target, CLI runtime, and benchmark smoke tests pass |
| G3 | Protocol/runtime | TCP, UDP, proxy frontends, auth/failure paths, reuse, concurrency, and shutdown pass |
| G4 | Interoperability | Both Go/Rust directions, external SOCKS5, and all generated differential cases pass |
| G5 | Transport stress | Vendored Quinn normal/ignored tests, repeated stress, pressure leak, and soak pass |
| G6 | Linux offload | Default-off, forced-off, opt-in-on, syscall proof, fallback, and GRO controls pass |
| G7 | Performance | Required local and WAN schedules complete without correctness or regression failure |
| G8 | Packaging | Every target archive/source archive exists, contents and all digests validate, host packages run |
| G9 | Security | Advisories, licenses, sources, secrets, SBOM, signatures, and required fuzzing are accepted |
| G10 | Deployment | Backup, staged smoke, canary, SLO checks, rollback rehearsal, and post-deploy health pass |
| G11 | Approval | Test, security, operations, and release owners sign the exact hashes |

CI is necessary but not sufficient. The current CI covers much of G1, G2, G4,
and G8; ignored stress tests, long soaks, syscall proof, local/WAN campaigns,
security review, canary, and rollback remain release activities.

## G0: Freeze the candidate

Record at minimum:

```bash
git status --short --branch
git rev-parse HEAD
git diff --binary
rustc -vV
cargo -V
go version
python3 --version
```

Build release binaries once, or download the exact proof-build artifacts, then
hash them before any test or deployment:

```bash
cargo build --locked --release -p zuicity-cli --bins
sha256sum target/release/zuicity-client target/release/zuicity-server
```

Do not rebuild between qualification and deployment. If rebuilding is
unavoidable, treat the output as a new candidate unless reproducibility proves
the bytes are identical.

## G1-G2: Static and full test gates

Install the toolchain declared by the workspace and run from the repository
root. `clippy` is an explicit production gate even though the current hosted CI
does not run it:

```bash
cargo fmt --all -- --check
cargo check --locked --workspace --all-targets
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
python3 scripts/validate-packaging.py
python3 -m py_compile scripts/benchmark/tcp-driver.py scripts/benchmark/tcp_gso_suite.py
bash -n scripts/benchmark/bench-one-tcp.sh
python3 scripts/benchmark/test_tcp_gso_suite.py
```

Run and log each test class separately so a broad final command cannot hide a
missing class:

```bash
cargo test --locked --workspace --lib
cargo test --locked --workspace --tests
cargo test --locked --workspace --doc
cargo test --locked --workspace --all-targets
cargo test --locked -p zuicity-benchmarks --test first_slice_smoke -- --nocapture --test-threads=1
cargo test --locked -p zuicity-benchmarks --test comparative_smoke -- --nocapture --test-threads=1
```

The upstream binaries must be available before the broad integration commands;
otherwise interop tests may build from `UPSTREAM_JUICITY_DIR` or fail for an
environmental reason. Prefer immutable prebuilt fixtures:

```bash
export UPSTREAM_JUICITY_DIR=/path/to/pinned/juicity-source
export UPSTREAM_JUICITY_BIN_DIR=/path/to/pinned/juicity-binaries
```

Repeat the static and test commands on native Windows and Linux. On Windows,
set the equivalent variables in PowerShell and use the same Cargo arguments:

```powershell
$env:UPSTREAM_JUICITY_DIR = 'C:\path\to\pinned\juicity-source'
$env:UPSTREAM_JUICITY_BIN_DIR = 'C:\path\to\pinned\juicity-binaries'
cargo fmt --all -- --check
cargo check --locked --workspace --all-targets
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo test --locked --workspace --lib
cargo test --locked --workspace --tests
cargo test --locked --workspace --doc
cargo test --locked --workspace --all-targets
```

Acceptance:

- Every command exits zero with no panic, abort, hang, unexpected skip, or
  leaked child process.
- `clippy -D warnings` is clean. A pre-existing warning needs a time-bounded
  exception; new warnings are not accepted.
- Doctests and all targets run on both operating-system families.
- Generated temporary processes, listeners, and test artifacts are cleaned up.
- Test counts and skips are recorded so a later release can detect lost tests.

## G3: Protocol and runtime behavior

The full suite is the executable gate. During review, map its results to this
minimum behavior matrix so coverage is not inferred merely from a green total.

| Surface | Required cases |
| --- | --- |
| Authentication | Valid UUID/password; wrong password; unknown UUID; silent pre-auth peer; auth timeout; one bad peer cannot block a good peer |
| Framing | IPv4, IPv6, and domain targets; TCP and UDP frames; partial reads/writes; oversized fields; invalid network/address tags; truncated and malformed frames |
| TCP forwarding | Fresh and persistent relays; half-close; delayed target response; target refusal; peer loss; stalled writes; cancellation and shutdown |
| UDP forwarding | Multiple datagrams; source-peer isolation; association reuse; idle expiry; remote DNS/IP targets; malformed response; target timeout |
| SOCKS5 frontend | CONNECT and UDP ASSOCIATE; IPv4/IPv6/domain; unsupported auth, command, address type, reserved byte, fragments, and malformed datagrams |
| HTTP frontend | Valid CONNECT, concurrent clients, malformed request isolation, target failure, and active-relay shutdown |
| Server egress | Direct, `send_through`, SOCKS5, HTTP/HTTPS CONNECT, auth, chained dialers, unreachable proxy, silent proxy timeout, and session-local recovery |
| Lifecycle | Multiple connections until shutdown; mixed TCP/UDP on one QUIC connection; reconnect after close/restart; bounded relay drain; metrics return to zero |
| Backpressure | Slow reader, non-reading target, bounded buffers, write timeout, cancellation, and no runtime-worker blocking |

Important executable coverage includes:

- `crates/zuicity-client/src/lib.rs`: shared connection reuse, concurrent UDP
  streams, SOCKS5/HTTP listeners, malformed-client isolation, and active-relay
  shutdown.
- `crates/zuicity-server/src/lib.rs`: pre-auth isolation, TCP/UDP egress modes,
  concurrent mixed relays, multiple connections, and shutdown.
- `crates/zuicity-transport/src/lib.rs`: wire/authentication behavior, proxy
  negotiation, malformed replies, timeouts, GSO/GRO, and fallback.
- `crates/zuicity-cli/tests/run_runtime.rs`: real child-process configuration,
  signals, forwarders, upstream fixtures, and failure recovery.
- `crates/zuicity-benchmarks/tests/first_slice_smoke.rs`: live TCP/UDP,
  frontend, egress, lifecycle, concurrency, and throughput cells.

No failure may terminate the long-lived server unless process termination is the
case under test. After a session-local error, run a valid TCP and UDP request to
prove recovery instead of relying only on process liveness.

## G4: Interoperability and differential testing

Run upstream Go interoperability in both directions, serializing heavy
subprocess tests:

```bash
cargo test --locked -p zuicity-client --test upstream_tcp_interop -- --nocapture --test-threads=1
cargo test --locked -p zuicity-server --test upstream_client_interop -- --nocapture --test-threads=1
cargo test --locked -p zuicity-cli --test run_runtime -- --nocapture --test-threads=1
```

The minimum matrix is Rust client to upstream server and upstream client to Rust
server, for both TCP and UDP with real authentication. Cover direct egress and
the proxy modes affected by the release. Pin and hash the upstream source and
binaries; do not silently test a moving upstream branch.

Build and require the differential oracle rather than accepting its capability
skip:

```bash
go -C differential/oracle build -o dialer-link-oracle .
export ZUICITY_DIALER_ORACLE="$PWD/differential/oracle/dialer-link-oracle"
cargo test --locked -p zuicity-transport --test dialer_link_differential -- --nocapture
```

Acceptance is all `4,096` generated dialer-link cases and all `3,072` generated
config cases, `7,168` total, with no new divergence. Documented stricter Rust
rejections may remain only where the test explicitly classifies them; Rust must
never accept an input the upstream oracle rejects.

Run authenticated interoperability against an independently implemented SOCKS5
proxy. Inject `ZUICITY_EXTERNAL_SOCKS5_URL` and target values through the secret
store rather than a committed file or shared shell history:

```bash
cargo test --locked -p zuicity-transport --lib \
  external_socks5_authenticated_tcp_interop -- --ignored --nocapture
```

The external gate must prove a successful request with correct credentials and
rejection with an intentionally wrong password. Add external UDP ASSOCIATE
coverage for any release that changes SOCKS5 UDP behavior.

## G5: Repeated stress, leaks, and vendored Quinn

### Repeated runtime stress

Run five consecutive rounds without cleaning build state between rounds. Keep
each round's log and resource snapshot:

```bash
for run in 1 2 3 4 5; do
  cargo test --locked -p zuicity-client --lib -- --test-threads=1
  cargo test --locked -p zuicity-server --lib -- --test-threads=1
  cargo test --locked -p zuicity-server --test high_pressure_leak -- --nocapture --test-threads=1
  cargo test --locked -p zuicity-benchmarks --test first_slice_smoke -- --nocapture --test-threads=1
done
```

Every round must pass. Between rounds, confirm no stale Zuicity/upstream child
process, listening test port, or namespace remains. The pressure test's
`active_connections` gauge must return to zero within its deadline after all
clients disappear from wedged relays.

### Long soak

On Linux, run the mixed TCP/UDP relay soak for at least 30 minutes:

```bash
ZUICITY_SOAK_DURATION=30m cargo test --locked -p zuicity-benchmarks \
  --test first_slice_smoke relay_soak_sustains_tcp_udp_without_leaks \
  -- --nocapture --exact --test-threads=1
```

Use a 30-minute run for a routine release and an 8-hour minimum run for a new or
higher-risk service. Capture per-process RSS/HWM, file descriptors, threads,
sockets, relay counters, errors, timeouts, and post-load idle behavior at a fixed
interval. Unless stricter product thresholds are frozen in G0, the default gate
is:

- No failed or corrupted TCP/UDP relay and no panic, deadlock, or forced kill.
- Both protocols make continuous progress; no unexplained multi-interval stall.
- Active connections return to zero after load and shutdown.
- End RSS is no more than `1.5x` the post-warmup baseline and becomes flat during
  the idle tail.
- Open file descriptors grow by no more than `2` from post-warmup baseline and
  return to the platform-specific expected idle set.

An RSS threshold pass does not excuse monotonic growth. Any continuing upward
trend during the idle tail is a leak investigation, not a pass.

### Vendored Quinn

Test the exact vendored Quinn and Quinn-proto trees separately on Windows and
Linux. These excluded standalone packages do not have committed lockfiles, so
generate lockfiles at candidate freeze, archive their hashes in the evidence
packet, and use those same lockfiles on both platforms. Explicitly patch Quinn
to the checked-in Quinn-proto tree; otherwise a standalone invocation can
resolve `quinn-proto` from the registry:

```bash
QUINN_PROTO_PATCH="patch.crates-io.quinn-proto.path='vendor/quinn-proto-0.11.14'"
cargo generate-lockfile --manifest-path vendor/quinn-proto-0.11.14/Cargo.toml
cargo generate-lockfile --manifest-path vendor/quinn-0.11.9/Cargo.toml \
  --config "$QUINN_PROTO_PATCH"
sha256sum vendor/quinn-proto-0.11.14/Cargo.lock vendor/quinn-0.11.9/Cargo.lock
cargo test --locked --manifest-path vendor/quinn-proto-0.11.14/Cargo.toml --all-targets
cargo test --locked --manifest-path vendor/quinn-proto-0.11.14/Cargo.toml --doc
cargo test --locked --manifest-path vendor/quinn-0.11.9/Cargo.toml \
  --config "$QUINN_PROTO_PATCH" --all-targets
cargo test --locked --manifest-path vendor/quinn-0.11.9/Cargo.toml \
  --config "$QUINN_PROTO_PATCH" --doc
cargo test --locked --manifest-path vendor/quinn-0.11.9/Cargo.toml \
  --config "$QUINN_PROTO_PATCH" --lib stress_receive_window \
  -- --ignored --nocapture
cargo test --locked --manifest-path vendor/quinn-0.11.9/Cargo.toml \
  --config "$QUINN_PROTO_PATCH" --lib stress_stream_receive_window \
  -- --ignored --nocapture
cargo test --locked --manifest-path vendor/quinn-0.11.9/Cargo.toml \
  --config "$QUINN_PROTO_PATCH" --lib stress_both_windows \
  -- --ignored --nocapture
cargo test --locked --manifest-path vendor/quinn-0.11.9/Cargo.toml \
  --config "$QUINN_PROTO_PATCH" \
  --test many_connections connect_n_nodes_to_1_and_send_1mb_data \
  -- --ignored --exact --nocapture
```

In PowerShell, set
`$quinnProtoPatch = "patch.crates-io.quinn-proto.path='vendor/quinn-proto-0.11.14'"`
and pass `--config $quinnProtoPatch` to each Quinn command. Generate the same
named lockfiles once in G0 and transfer those evidence copies between operating
systems rather than independently resolving dependencies twice.

The many-connections gate creates 50 connections, sends approximately 1 MiB on
each, and verifies CRC integrity. The receive-window tests must complete without
corruption, hang, or connection error under constrained connection and stream
windows. Confirm the Quinn lockfile's `quinn-proto` package has no registry
`source` and is version `0.11.14`. Record exact test counts and `cargo tree`
output so a registry substitution cannot be mistaken for testing the
workspace-patched tree. The generated vendor lockfiles are release evidence;
do not commit them unless the repository adopts them as maintained inputs.

## G6: Linux GSO/GRO and syscall proof

The required mode matrix is:

| Mode | Environment | Expected behavior |
| --- | --- | --- |
| Default | Both GSO variables unset | Ordinary datagrams; no `UDP_SEGMENT` data send |
| Forced off | `ZUICITY_DISABLE_GSO=1` | Ordinary datagrams; disable overrides enable |
| Opt-in on | `ZUICITY_ENABLE_GSO=1` | Eligible post-handshake batches use per-message `UDP_SEGMENT` |
| Hostile path | Opt-in on plus forced/path `EINVAL` or `EIO` | Immediate lossless plain-datagram retry and per-destination disable |
| GRO default | `ZUICITY_DISABLE_GRO` unset | Coalesced receive when supported, integrity preserved |
| GRO off/fallback | `ZUICITY_DISABLE_GRO=1` or unsupported host | Plain receive, integrity preserved |

The transport unit tests must prove long-header bypass, mode precedence,
successful GSO delivery, `EINVAL`/`EIO` fallback without packet loss, destination
isolation, GRO integrity, and GRO-off transfer. Unit tests do not replace syscall
proof.

For every benchmark implementation/mode, trace a separate pre-measurement probe
with the repository benchmark suite. Inspect `setsockopt`, `sendmsg`, and
`sendmmsg`, including symbolic and numeric `UDP_SEGMENT` forms. Acceptance:

- GSO on records at least one successful `UDP_SEGMENT` data send.
- GSO off and default record zero `UDP_SEGMENT` data-send attempts.
- Every Zuicity mode records zero capability probes and zero persistent
  `UDP_SEGMENT` socket-option writes.
- Handshake traffic succeeds even when GSO is rejected.
- The fallback payload is byte-for-byte complete and subsequent traffic to that
  destination uses ordinary sends.
- Timed rows are not run under `strace`; raw probe shards remain in evidence.

Any mismatch fails the campaign. Do not downgrade it to a warning based on
throughput results.

## G7: Performance qualification

Correctness, artifact identity, and host-quality gates take precedence over
rankings. Freeze regression budgets before execution. Unless a release has
approved stricter budgets, investigate and block an unexplained candidate
regression greater than 5% in throughput, 10% in median latency, 20% in HWM, or
20% in proxy CPU against the last accepted candidate under the same treatment.
Do not average away a failed arm.

### Exact four-product 512 KiB replay

Run the packaged candidate under the preserved four-product contract using
`scripts/benchmark/tcp-gso-v050-go-jrs.example.json` as the template. Replace
candidate identity and hashes for a new release; leave comparators and controls
unchanged unless the test plan explicitly creates a new campaign lineage.

```bash
export CANDIDATE_BIN_DIR=/path/to/candidate/build
export GO_STOCK_BIN_DIR=/path/to/stock-go
export GO_REPAIRED_BIN_DIR=/path/to/repaired-go
export JUICITY_RS_BIN_DIR=/path/to/official-juicity-rs
export JUICITY_RS_GSO_SHIM=/path/to/hash-pinned-gso-off-control.so

sudo --preserve-env=CANDIDATE_BIN_DIR,GO_STOCK_BIN_DIR,GO_REPAIRED_BIN_DIR,JUICITY_RS_BIN_DIR,JUICITY_RS_GSO_SHIM \
  scripts/benchmark/run-comparison.sh \
  --manifest scripts/benchmark/tcp-gso-v050-go-jrs.example.json \
  --out-dir benchmark-results/<unique-campaign> \
  --profile standard \
  --rtt-samples 60 \
  --throughput-samples 10 \
  --throughput-bytes 524288 \
  --warmup-transfers 2 \
  --max-row-attempts 5 \
  --idle-wait-seconds 180 \
  --cpus <reviewed-monitored-cpu-union> \
  --server-cpus <reviewed-server-cpus> \
  --client-cpus <reviewed-client-cpus> \
  --driver-cpus <reviewed-driver-cpus>
```

This exact replay requires eight rotations, 64 accepted rows, eight independent
GSO probes, 60 fresh-connect RTT samples, 60 persistent RTT samples, 10
throughput transfers, a 512 KiB payload, two warmups, and no more than five
attempts per scheduled row. Preserve every rejected attempt and require a
complete byte-identical Williams schedule. This reduced-payload replay is a
historical regression comparison, not the canonical 4 MiB release profile.

Also run the canonical profile for the product set that can complete it: 60
fresh RTT, 60 persistent RTT, 100 full-echo transfers of 4 MiB, and five
warmups per row. Label any override and never describe a smoke or incomplete
schedule as release-ranking evidence.

Follow `scripts/benchmark/BENCHMARK_GUIDELINES.md` for artifact hashes, CPU and
thermal controls, rejection rules, statistical units, sign tests, evidence
shape, and privacy.

### Separate matched BBR/Hysteria2 campaign

Keep the two-product Oracle-style campaign separate from the four-product WSL2
campaign. Match both products on BBR and compare off/off and on/on, never GSO on
against GSO off. Use at least five alternating pairs; each row requires 60 fresh
RTT, 60 persistent RTT, 100 4 MiB send-plus-full-echo transfers, and five
warmups. Pin server/echo and client/driver to reviewed disjoint CPUs.

Require syscall proof for every arm, zero driver errors, all pairs complete,
resource logs present, and candidate regression budgets satisfied. Report pair
wins, median paired change, and the exact sign-test result. Do not merge these
samples with the local four-product campaign.

### Real WAN and cross-host

Use non-production ports and temporary configs on at least two real paths. Test
both directions when the release protocol requires them. Cover:

- System-root TLS validation, correct SNI, pinned-certificate mode, and explicit
  rejection of an invalid certificate/name.
- TCP fresh and persistent traffic, UDP traffic, DNS and IP targets, concurrent
  mixed protocols, and large transfers with content verification.
- GSO off and opt-in on where supported, plus a known or injected hostile path
  proving fallback.
- Client restart, server restart, peer disappearance, reconnect, idle timeout,
  packet loss, and path MTU changes.
- Base RTT, loss, throughput, proxy CPU, RSS/HWM, timeouts, errors, and cleanup.

Do not disturb a live service, firewall default, or production UDP port. WAN
results are their own population and must not be pooled with `veth` results.

## G8: Packaging and artifact validation

Run host packaging and deployment tests against the already-qualified release
binaries:

```bash
python3 scripts/validate-packaging.py
scripts/package-release.sh --target x86_64-unknown-linux-gnu --output-dir /tmp/zuicity-package --version <version> --skip-build
scripts/package-deb-smoke.sh --target x86_64-unknown-linux-gnu --output-dir /tmp/zuicity-deb --version <version> --skip-build
scripts/package-rpm-smoke.sh --target x86_64-unknown-linux-gnu --output-dir /tmp/zuicity-rpm --version <version> --skip-build
scripts/package-apk-smoke.sh --target x86_64-unknown-linux-gnu --output-dir /tmp/zuicity-apk --version <version> --skip-build
scripts/deployment-smoke.sh --target x86_64-unknown-linux-gnu --output-dir /tmp/zuicity-deploy --version <version> --duration 30 --skip-build
```

The deployment smoke must run staged package binaries, perform real TCP and UDP
round trips, receive SIGTERM, and report clean client/server exits. A `-v` smoke
alone is not sufficient.

Dispatch the full release workflow as a non-publishing proof build before
tagging. Require every supported platform row plus the source archive. For the
current matrix this means 18 platform archives and one full-source archive. For
each artifact:

- Verify archive name, target, executable names, example configs, service units
  where applicable, manifest, sizes, and permissions.
- Recompute and compare MD5, SHA-1, SHA-256, and SHA-512 values in `.dgst`, plus
  standalone SHA-256.
- Extract into a clean directory and run native-host binaries where executable.
- Confirm reported versions match the intended release and no debug/private
  files, credentials, absolute build paths, or unrelated artifacts are present.
- Confirm the release upload is blocked if any matrix row fails; never publish a
  partial set under the normal release tag.

Build the multi-platform container, inspect its contents and non-root/runtime
policy, smoke real traffic, scan it, publish by immutable digest, and verify its
cosign signature. Record the image digest rather than relying on a mutable tag.

## G9: Security and high-risk additions

For an ordinary maintenance release, all applicable rows below are required.
For a new Internet-facing project, every row is mandatory before production.
These gates are not fully automated in the current repository and must not be
marked passed merely because CI is green.

| Area | Required evidence and acceptance |
| --- | --- |
| Dependency advisories | `cargo audit` report; no unaccepted exploitable advisory in runtime or build dependencies |
| License/source policy | `cargo deny check advisories bans licenses sources` with a reviewed policy; only approved licenses and registries/git sources |
| Secrets | Full-history and worktree scan with redaction; no live secret in source, artifacts, images, logs, or test data |
| SBOM | CycloneDX or SPDX SBOM for source, each binary family, and container; hashes tie it to release artifacts |
| Vulnerability scan | Source/dependency, filesystem, package, and container scan; no unaccepted critical/high finding reachable in production |
| Provenance | Source commit, workflow identity, compiler, dependencies, artifact hashes, signature, and attestations are verifiable |
| TLS/credentials | Supported algorithms/protocols reviewed; key permissions, rotation, expiry alerts, revocation response, and invalid-cert tests pass |
| Abuse controls | Pre-auth bounds, connection/stream limits, timeout policy, amplification risk, logging redaction, and resource exhaustion reviewed |

Example tools may include `cargo-audit`, `cargo-deny`, `gitleaks`, Syft, Grype,
Trivy, and cosign. Pin and record tool/database versions. A scanner exit zero is
not the review: retain machine-readable output and document reachability,
mitigation, owner, and expiry for each exception.

### Fuzzing

Create persistent fuzz targets for externally controlled parsers and state
boundaries, at minimum:

- Authentication stream and proxy header decoding.
- UDP-over-stream framing and every supported proxy UDP frame.
- SOCKS5 greeting/request/reply/datagram parsing.
- HTTP CONNECT request/reply parsing.
- Config and `dialer_link` parsing, including chains and encoded credentials.
- TLS/certificate helper input and share-link parsing/generation.

Seed corpora with valid upstream traffic, unit-test edge cases, differential
cases, and incident reproductions. Use sanitizers where supported. A routine
release requires at least 60 minutes per changed target; a high-risk initial
release requires at least 24 aggregate target-hours and continuous scheduled
fuzzing thereafter. Acceptance is no crash, panic, OOM, timeout/hang, unbounded
allocation, sanitizer finding, or new upstream differential mismatch. Preserve
crash inputs and minimized regression cases permanently.

### Fault injection and chaos

In isolated namespaces or staging, inject loss, delay, jitter, reorder,
duplication, corruption, MTU reduction, ICMP blackholes, DNS failure, certificate
failure, proxy silence, target stalls, port exhaustion, and abrupt client/server
termination. Restart or replace each dependency during active mixed traffic.

Acceptance is bounded failure, no data corruption or credential disclosure, no
deadlock, no runaway retry loop, recovery within the frozen objective, and
resources returning to baseline. Every discovered failure needs a deterministic
regression test before approval.

### Capacity and load to failure

Run a staircase load across concurrent connections, streams per connection,
TCP/UDP mix, payload sizes, connection churn, and slow consumers until the first
SLO breach or resource saturation. Record throughput, latency distributions,
error rate, CPU, scheduler pressure, memory, FDs, sockets, packet drops, and
recovery at every step.

Define supported capacity no higher than 70% of the first repeatable saturation
point unless a lower product limit applies. Prove at least 30% headroom at the
declared production maximum, stable operation for the required soak duration,
admission behavior above the limit, and return to baseline after load.

## G10: Deployment, canary, and rollback

### Pre-deploy

- Confirm approved candidate hashes match the files on the deployment host.
- Capture current binary/config/unit hashes, version, permissions, service
  state, listener ownership, certificate expiry, and a functional TCP/UDP
  baseline without copying secret content into logs.
- Make encrypted backups of binaries, configs, units, and required certificate
  references. Test that the backup can be read and its hashes match.
- Write and peer-review exact install, start, health-check, and rollback commands.
- Confirm monitoring, alert routing, maintenance window, owner availability,
  firewall rules, disk space, and time synchronization.

### Staged and canary rollout

Install to a temporary path first, verify `-v`, configuration parsing, file
ownership, and binary hashes, then use the normal service manager. Exercise a
dedicated test identity through real TCP and UDP traffic. Also prove invalid
credentials are rejected without impacting valid traffic.

Use progressive exposure such as 5%, 25%, 50%, and 100%, with an observation
window at each step long enough to cover connection idle/reconnect behavior.
Freeze release-specific SLOs before rollout. At minimum monitor:

- Service active/enabled state, restart count, exit codes, and UDP listener
  ownership.
- Successful authentication/connection/relay rates and failure reasons.
- TCP and UDP request success, latency percentiles, throughput, and timeouts.
- Active QUIC connections/streams/relays and whether they drain after traffic.
- CPU, RSS/HWM, FDs, threads, sockets, UDP errors/drops, packet loss, and disk.
- GSO/GRO mode and fallback/errors where observable.
- Log panic/error rate, credential redaction, certificate expiry, and clock skew.

Automatically stop promotion and roll back on a frozen SLO breach, crash loop,
listener loss, authentication anomaly, data corruption, sustained resource
growth, or material increase in failure/latency. Do not improvise thresholds
after observing the candidate.

### Rollback and disaster recovery

Rehearse rollback in staging before production. Rollback must restore the prior
binary, config/unit state, permissions, service health, listener ownership, and
successful TCP/UDP traffic. Confirm new connections work and old failed
processes/listeners are gone.

For a higher-risk service, restore onto a clean replacement host from the actual
backup and infrastructure procedure. Freeze and measure recovery-time and
recovery-point objectives. Test lost host, lost config store, expired/rotated
certificate, unavailable upstream proxy, and regional/path failure. A written
procedure that has not completed a timed restore is not disaster-recovery
evidence.

After full rollout, repeat binary/config hashes, service state, listener owner,
version, TCP/UDP functional checks, invalid-auth check, and monitoring review.
Keep the prior known-good artifact and rollback packet until the observation
window closes.

## G11: Final approval

`approval.md` must identify the exact binary and package hashes and include:

| Role | Required sign-off |
| --- | --- |
| Change owner | Scope, intended behavior, known risks, and regression budget |
| Independent test reviewer | G0-G8 evidence completeness and unexplained skips/retries |
| Security reviewer | G9 findings, threat model, exceptions, SBOM, signatures, and secret handling |
| Operations owner | Capacity, SLOs, monitoring, backup, rollout, rollback, and DR readiness |
| Release owner | All blockers closed; tag/assets match qualified hashes; publication authorized |

Approval is invalidated by a source change, dependency change, rebuild producing
different bytes, package-content change, config-schema change, failed canary, or
expired exception. Re-enter at the earliest affected gate.

## Current historical baseline

The following results are useful as regression references, not substitutes for a
new candidate run:

- Full workspace/all-target and doctest suites passed on native Windows and WSL
  Linux for the previously qualified candidate.
- Vendored Quinn-proto passed 265 unit tests and three doctests on each platform;
  ignored receive-window tests and the 50-connection checksum transfer passed.
- Five repeated connection, concurrency, lifecycle, and high-pressure rounds
  passed on both platforms.
- A fresh 30-minute WSL soak completed 9,092 waves, 36,368 TCP relays, and
  36,368 UDP relays with `1.3314x` RSS growth and `+2` FDs.
- Authenticated interoperability with `serjs/go-socks5-proxy` passed, including
  invalid-password rejection.
- The differential oracle passed all 7,168 generated cases on Windows and
  Linux.
- Eighteen platform archives, the source archive, and MD5/SHA-1/SHA-256/SHA-512
  sidecars were validated for the prior release packet.
- The packaged v0.5.0 four-product replay and the separate matched
  BBR/Hysteria2 campaign are documented in the README and
  `docs/benchmarks/v0.5.0-four-product-512k.md`.

Treat this baseline as the comparison floor. Preserve failures and variance,
rerun affected gates for every changed artifact, and never generalize a result
beyond its hashes, host, mode controls, workload, and schedule.
