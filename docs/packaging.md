# Packaging and Deployment

This document records the Rust port's current packaging surface and the commands used to produce local release artifacts. It mirrors the upstream Juicity release shape: two binaries, example configs, systemd units on Linux, a server container image, compressed release archives, and digest files.

## Upstream Parity Inputs

Upstream Juicity packages are defined by:

- `Makefile`: builds `juicity-client` and `juicity-server` with trim/strip release flags.
- `Dockerfile`: builds a server-only container and runs `juicity-server run -c /etc/juicity/server.json`.
- `install/example-client.json` and `install/example-server.json`: sample config files.
- `install/juicity-client.service` and `install/juicity-server.service`: Linux systemd unit templates.
- `.github/workflows/seed-build.yml` and `seed-release-build.yml`: copy binaries, examples, and services into `build/`, smoke `-v`, zip the package, and emit digest files.

## Local Release Build

Run from the repository root:

```bash
scripts/package-release.sh --target x86_64-unknown-linux-gnu --output-dir /tmp/zuicity-package
```

The script mirrors the upstream seed-build packaging shape locally:

- builds `zuicity-client` and `zuicity-server` with `cargo build --release -p zuicity-cli --bins` unless `--skip-build` is passed;
- maps Rust target triples to upstream-style friendly asset names through `install/friendly-filenames.json`;
- stages both binaries, example configs, and Linux systemd units into `build/`;
- smoke-runs `zuicity-client -v` and `zuicity-server -v` from the staged directory;
- creates `zuicity-<friendlyName>.zip`;
- emits an upstream-style `.dgst` file with MD5, SHA1, SHA256, and SHA512 plus a standalone `.sha256` file and `manifest.txt`.

Expected local artifacts for the host Linux x86_64 build:

- `/tmp/zuicity-package/build/zuicity-client`
- `/tmp/zuicity-package/build/zuicity-server`
- `/tmp/zuicity-package/build/example-client.json`
- `/tmp/zuicity-package/build/example-server.json`
- `/tmp/zuicity-package/build/zuicity-client.service`
- `/tmp/zuicity-package/build/zuicity-server.service`
- `/tmp/zuicity-package/zuicity-linux-x86_64.zip`
- `/tmp/zuicity-package/zuicity-linux-x86_64.zip.dgst`
- `/tmp/zuicity-package/zuicity-linux-x86_64.zip.sha256`
- `/tmp/zuicity-package/manifest.txt`

## Distro package metadata

The Rust port now includes nFPM metadata for Linux distro package generation at `packaging/nfpm.yaml`. The metadata is intentionally static and validated by `scripts/validate-packaging.py` so CI catches drift in packaged paths before a release job attempts to produce `.deb`, `.rpm`, or `.apk` artifacts.

The distro package metadata installs:

- `zuicity-client` and `zuicity-server` into `/usr/bin`;
- example configs as `config|noreplace` files at `/etc/zuicity/client.json` and `/etc/zuicity/server.json`;
- systemd units into `/usr/lib/systemd/system`;
- post-install and post-remove maintainer scripts that reload systemd only when the host is running systemd.

A release job can build host distro packages after the release binaries exist, for example:

```bash
VERSION=0.1.0 NFPM_ARCH=amd64 nfpm package --packager deb --config packaging/nfpm.yaml --target dist/zuicity_0.1.0_amd64.deb
VERSION=0.1.0 NFPM_ARCH=amd64 nfpm package --packager rpm --config packaging/nfpm.yaml --target dist/zuicity-0.1.0-1.x86_64.rpm
VERSION=0.1.0 NFPM_ARCH=amd64 nfpm package --packager apk --config packaging/nfpm.yaml --target dist/zuicity-0.1.0-r1.apk
```

The packages do not enable or start services automatically. Operators should edit `/etc/zuicity/client.json` or `/etc/zuicity/server.json`, install certificate material for server mode, then enable the relevant systemd unit explicitly.

`scripts/package-deb-smoke.sh` builds a local `.deb` package with `dpkg-deb`/`fakeroot`, inspects package control and contents, extracts it into an isolated install root, runs the extracted `zuicity-client -v` and `zuicity-server -v`, installs it with `dpkg --force-not-root --admindir`/`--instdir` plus a writable `--log` into a repo-local root, and executes the packaged maintainer scripts with a fake `systemctl` shim. This gives CI a real Debian package build/install smoke path even when `nfpm` is not available on the host.

A verified local smoke run used:

```bash
scripts/package-deb-smoke.sh --target x86_64-unknown-linux-gnu --output-dir target/zuicity-logs/packaging-deb-smoke/artifacts --version 0.1.0+deb.smoke --skip-build
```

That run produced `target/zuicity-logs/packaging-deb-smoke/artifacts/dist/zuicity_0.1.0+deb.smoke_amd64.deb`, verified `Package: zuicity`, `Architecture: amd64`, `Depends: ca-certificates`, extracted the expected binaries/configs/systemd units, ran the installed client/server `-v` surfaces, and installed the package into an isolated `dpkg` root with `Status: install ok installed`. Hosted CI run `27530683943` then passed the same Debian package smoke on a non-root GitHub runner after the isolated install path was tightened with `--force-not-root` and a repo-local `dpkg.log`; the run also passed format, workspace check/test, benchmark smoke, packaging validation, local release package smoke, and release packaging benchmark.

`scripts/package-rpm-smoke.sh` builds a local `.rpm` package with `rpmbuild`/`fakeroot`, inspects package metadata, contents, dependencies, and scriptlets with `rpm -qpi`, `rpm -qpl`, `rpm -qpR`, and `rpm -qp --scripts`, extracts payload bytes with `rpm2archive -n` into `rpm-payload.tar`, lists and extracts that archive through `bsdtar`, installs the package into a repo-local RPM database with `rpm --root`, and runs packaged `zuicity-client -v` and `zuicity-server -v` from both the extracted payload and isolated RPM root. This gives CI a real RPM package build/install smoke path even when `nfpm` is not available on the host.

A verified local RPM smoke run used:

```bash
scripts/package-rpm-smoke.sh --target x86_64-unknown-linux-gnu --output-dir target/zuicity-logs/packaging-rpm-smoke/artifacts --version 0.1.0+rpm.smoke --skip-build
```

That run produced `target/zuicity-logs/packaging-rpm-smoke/artifacts/dist/x86_64/zuicity-0.1.0.rpm.smoke-1.x86_64.rpm`, verified `Name: zuicity`, `Version: 0.1.0.rpm.smoke`, `Architecture: x86_64`, `Requires: ca-certificates`, package contents, scriptlets, extracted payload contents, isolated `rpm --root` status `zuicity-0.1.0.rpm.smoke-1.x86_64`, and packaged client/server `-v` surfaces. The RPM was 5,018,174 bytes with SHA256 `08bdc1c3985cd99678d1766c18c7647ce9398f9bce19509af35d3271750ad818`.


`scripts/package-apk-smoke.sh` builds a local unsigned Alpine APK-format tarball with `.PKGINFO` and `.INSTALL`, inspects package metadata and contents with `tar`, extracts it into an isolated install root, and runs packaged `zuicity-client -v` and `zuicity-server -v` from that extracted root. This gives CI a host-tooling APK package smoke path even when Alpine `apk`/`abuild` are not available on the Ubuntu runner.

A verified local APK smoke run used:

```bash
scripts/package-apk-smoke.sh --target x86_64-unknown-linux-gnu --output-dir target/zuicity-logs/packaging-apk-smoke/current --version 0.1.0+apk.current
```

That run produced `target/zuicity-logs/packaging-apk-smoke/current/dist/zuicity-0.1.0.apk.current-r1.x86_64.apk`, verified `.PKGINFO` fields for `pkgname = zuicity`, `pkgver = 0.1.0.apk.current-r1`, `arch = x86_64`, `depend = ca-certificates`, package contents, `.INSTALL` systemd reload hooks, and packaged client/server `-v` surfaces. The APK-format artifact was 5,237,429 bytes with SHA256 `1debd13c71f1b7dbb41c0d94042ee3d58f0d46f61304dbaef85e8ebc4e8a712c`.


`scripts/deployment-smoke.sh` stages release assets into an isolated local deployment root, generates a temporary localhost certificate, rewrites deployment-local client/server configs, starts the staged `zuicity-server run` and `zuicity-client run` binaries, drives real TCP and UDP forward echo traffic for a bounded duration, then sends SIGTERM and verifies clean process exit plus deployment logs. This validates the package release assets, example/service install layout, runtime config paths, and process lifecycle together rather than only inspecting package metadata.

A verified local deployment smoke run uses:

```bash
scripts/deployment-smoke.sh --target x86_64-unknown-linux-gnu --output-dir target/zuicity-logs/deployment-smoke/current --version 0.1.0+deploy.current --duration 5 --skip-build
```

That run wrote `target/zuicity-logs/deployment-smoke/current/deployment-smoke-manifest.txt`, `deployment-driver.log`, `server.log`, and `client.log`; drove 21 TCP and 21 UDP forward round trips through the staged binaries; verified echo counters (`tcp_echo_connections=21`, `udp_echo_datagrams=21`), generated config paths, service asset paths, and clean process exits (`client_exit=0`, `server_exit=0`).

## Linux systemd install

Copy the release assets into place:

```bash
install -d -m 0755 /etc/zuicity
install -m 0644 example-client.json /etc/zuicity/client.json
install -m 0644 example-server.json /etc/zuicity/server.json
install -m 0755 zuicity-client /usr/bin/zuicity-client
install -m 0755 zuicity-server /usr/bin/zuicity-server
install -m 0644 zuicity-client.service /etc/systemd/system/zuicity-client.service
install -m 0644 zuicity-server.service /etc/systemd/system/zuicity-server.service
systemctl daemon-reload
systemctl enable --now zuicity-server.service
```

The server example expects `/etc/zuicity/fullchain.pem` and `/etc/zuicity/private.key` to exist. Replace UUIDs, passwords, SNI, listen addresses, and certificate paths before enabling services.

## Container image

The Rust Dockerfile builds the CLI binary package in a Rust builder stage and copies only `zuicity-server` plus the example server config into a `debian:trixie-slim` runtime image. The runtime base must provide a glibc new enough for the current Rust builder output; an earlier `debian:bookworm-slim` smoke test failed with a `GLIBC_2.38` loader error.

```bash
docker build -t zuicity:local .
docker run --rm -v /path/to/server.json:/etc/zuicity/server.json:ro zuicity:local
```

The container shape intentionally follows upstream's server-only image. Production images should mount a real server config and certificate/key material instead of using the included example.

## CI and release automation

The Rust port includes local packaging validation plus GitHub Actions workflows that mirror the upstream packaging intent without relying on upstream's Go-only seed jobs:

- `.github/workflows/ci.yml` runs formatting, workspace check/test, `scripts/validate-packaging.py`, a host `scripts/package-release.sh` package smoke, `scripts/package-deb-smoke.sh` for Debian package build/install smoke, `scripts/package-rpm-smoke.sh` for RPM package build/install smoke, `scripts/package-apk-smoke.sh` for APK-format package smoke, `scripts/deployment-smoke.sh` for bounded local deployment validation, a `dialer_link` differential parity job (builds the `differential/oracle` Go oracle and runs `cargo test -p zuicity-transport --test dialer_link_differential`), and a dedicated `alpine-package` job that runs inside an `alpine` container to perform a real native APK build and `apk add` install via `scripts/package-apk-native.sh`.
- `.github/workflows/release.yml` builds release archives for upstream-style binary names across Linux, macOS, Windows, and Android target rows. Linux cross rows use `CARGO_BUILD_TOOL=cross`; current Rust toolchains no longer ship prebuilt MIPS standard libraries, so the MIPS rows use nightly `rust-src` with `CARGO_BUILD_FLAGS=-Zbuild-std=std,panic_abort`. Android builds use the hosted Android SDK/NDK linker directly instead of the older `cross` Android image. macOS and Windows rows build on native hosted runners. The workflow can run targeted proof builds for `android-arm64`, `macos-x86_64`, `macos-arm64`, and the four MIPS rows through the `platform` and `source_ref` dispatch inputs; targeted proof builds upload workflow artifacts only, while `platform=all` checks out the release tag, builds the full matrix, uploads ZIP and `.dgst` files to the GitHub release to match upstream Go release file types, retains `.sha256` and uniquely named `.manifest.txt` files in workflow artifacts, and publishes `zuicity-full-src.zip` with a matching `.dgst` file. The full matrix includes `linux-x86_64`, `linux-x86_64_v2_sse`, `linux-x86_64_v3_avx2`, `linux-x86_32`, `linux-arm64`, `linux-armv5`, `linux-armv6`, `linux-armv7`, `linux-mips32`, `linux-mips32le`, `linux-mips64`, `linux-mips64le`, `linux-riscv64`, `macos-x86_64`, `macos-arm64`, `windows-x86_64`, `windows-arm64`, and `android-arm64`. Rows that share a Rust target triple pass `--friendly-name` to keep distinct upstream-style asset names.
- `.github/workflows/docker-publish.yml` builds the server-only container for `linux/amd64` and `linux/arm64`, publishes to GHCR outside pull requests, and signs pushed images with cosign.

For non-host targets, the release workflow uses `scripts/package-release.sh --skip-smoke` because CI cannot execute foreign-architecture binaries after cross compilation. Host Linux x86_64 packages still run both staged `-v` smoke checks. The matrix keeps `fail-fast: false` so all rows report their status, but the release upload is blocked unless every platform row succeeds; this preserves the upstream Go release asset count instead of publishing a partial release.

The CI workflow checks out upstream `juicity/juicity`, installs Go from upstream `go.mod`, builds upstream `juicity-client` and `juicity-server` once into `UPSTREAM_JUICITY_BIN_DIR`, and then runs Rust workspace tests with that bin dir available to interop tests. It keeps ordinary workspace tests broad while running the live `zuicity-benchmarks` smoke harness serially with `--test-threads=1`; this avoids overloading shared runners with concurrent loopback QUIC fixtures while preserving benchmark smoke coverage. After the host package smoke, `scripts/benchmark-package-release.sh` can reuse the release binaries with `--skip-build` to record release-automation `elapsed_millis`, artifact byte sizes, archive path, and the package command log in `package-release-benchmark.txt`.

## Packaging parity scope and environment limitations

Packaging parity for the Rust port is tracked as a closed, evidenced set rather than an
open-ended claim. The following surfaces are implemented and maintained:

- Local release staging and upstream-style friendly target naming for Rust triples.
- Host release archive creation with MD5/SHA1/SHA256/SHA512 `.dgst` files, standalone `.sha256` files for CI artifacts, `manifest.txt`, and release-safe `zuicity-<friendlyName>.manifest.txt` workflow manifests.
- Static packaging validation (`scripts/validate-packaging.py`), including JSON/service asset checks.
- Debian package build/install smoke (`scripts/package-deb-smoke.sh`).
- RPM package build/install smoke (`scripts/package-rpm-smoke.sh`).
- APK-format package smoke (`scripts/package-apk-smoke.sh`).
- Real native Alpine APK build + `apk add` install + run smoke (`scripts/package-apk-native.sh`, executed by the `alpine-package` CI job).
- Bounded local deployment smoke (`scripts/deployment-smoke.sh`) running the
  packaged `zuicity-client` and `zuicity-server` binaries through real TCP and
  UDP forward round-trips with clean process exits.
- Release archive workflows are statically validated locally, including the expanded upstream-style platform matrix; hosted release dispatch remains the target-specific proof point for non-host rows.
- Signed container publish workflows.

The deployment smoke is the strongest local evidence: it proves the *packaged
binaries actually run and relay traffic*, which is the runtime guarantee
packaging exists to provide. The latest local deployment smoke staged release
assets, generated a localhost certificate, ran packaged client/server binaries,
completed 21 TCP and 21 UDP forward round trips, and exited cleanly
(`client_exit=0`, `server_exit=0`).

### Alpine native packaging (hosted CI)

The previously-deferred native Alpine APK gap is now closed by hosted CI rather
than a development host without `apk`/`abuild`:

- The `alpine-package` job in `.github/workflows/ci.yml` runs inside an
  `alpine` container, installs `alpine-sdk`/`abuild`, and executes
  `scripts/package-apk-native.sh`.
- `scripts/package-apk-native.sh` builds static musl release binaries
  (`-C target-feature=+crt-static`), generates an `APKBUILD`, produces a real
  signed `.apk` with `abuild -r`, installs it with `apk add --allow-untrusted`,
  verifies installation with `apk info -e zuicity`, and runs the installed
  `/usr/bin/zuicity-client -v` and `/usr/bin/zuicity-server -v` as a post-install
  smoke.

### Local environment limitation

- A development host without Alpine tooling cannot install `apk`/`abuild`, so the native
  APK build/install path is exercised in the hosted `alpine-package` CI job
  rather than locally. Locally, `scripts/package-apk-smoke.sh` still validates
  the **package-format level** (builds a format-conformant `.apk`, verifies its
  structure, content/script hooks, extracts into an isolated root, and runs the
  packaged client/server `-v` surfaces). This is a local-environment constraint,
  not a code or parity gap: the same artifact is natively built and installed by
  CI on real Alpine.
