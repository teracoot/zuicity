#!/usr/bin/env python3
"""Validate Zuicity Rust packaging and deployment automation files."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def read_text(path: str) -> str:
    file_path = ROOT / path
    if not file_path.exists():
        raise AssertionError(f"missing {path}")
    return file_path.read_text()


def require_terms(path: str, terms: list[str]) -> None:
    text = read_text(path)
    missing = [term for term in terms if term not in text]
    if missing:
        raise AssertionError(f"{path} missing terms: {', '.join(missing)}")


def normalize_yaml_value(value: str) -> str:
    return value.strip().strip('"').strip("'").removeprefix("./")


def require_nfpm_metadata() -> None:
    text = read_text("packaging/nfpm.yaml")
    require_terms(
        "packaging/nfpm.yaml",
        [
            "name: zuicity",
            "arch: ${NFPM_ARCH}",
            "platform: linux",
            "version: ${VERSION}",
            "license: AGPL-3.0-only",
            "maintainer:",
            "homepage:",
            "contents:",
            "/usr/bin/zuicity-client",
            "/usr/bin/zuicity-server",
            "/etc/zuicity/client.json",
            "/etc/zuicity/server.json",
            "type: config|noreplace",
            "/usr/lib/systemd/system/zuicity-client.service",
            "/usr/lib/systemd/system/zuicity-server.service",
            "scripts:",
            "postinstall:",
            "postremove:",
            "deb:",
            "rpm:",
            "apk:",
            "ca-certificates",
        ],
    )
    expected_sources = {
        "install/example-client.json",
        "install/example-server.json",
        "install/zuicity-client.service",
        "install/zuicity-server.service",
    }
    found_sources = {
        normalize_yaml_value(match)
        for match in re.findall(r"^\s*-?\s*src:\s*(.+?)\s*$", text, flags=re.MULTILINE)
    }
    missing_sources = sorted(expected_sources.difference(found_sources))
    if missing_sources:
        raise AssertionError(
            "packaging/nfpm.yaml missing source assets: " + ", ".join(missing_sources)
        )
    for source in expected_sources:
        if not (ROOT / source).exists():
            raise AssertionError(f"packaging/nfpm.yaml references missing asset {source}")

    expected_scripts = {
        "packaging/systemd/postinstall.sh",
        "packaging/systemd/postremove.sh",
    }
    found_scripts = {
        normalize_yaml_value(match)
        for match in re.findall(
            r"^\s*(?:postinstall|postremove):\s*(.+?)\s*$",
            text,
            flags=re.MULTILINE,
        )
    }
    missing_scripts = sorted(expected_scripts.difference(found_scripts))
    if missing_scripts:
        raise AssertionError(
            "packaging/nfpm.yaml missing maintainer scripts: " + ", ".join(missing_scripts)
        )
    for script in expected_scripts:
        path = ROOT / script
        if not path.exists():
            raise AssertionError(f"packaging/nfpm.yaml references missing script {script}")
        if path.stat().st_mode & 0o111 == 0:
            raise AssertionError(f"{script} is not executable")


def require_executable(path: str) -> None:
    file_path = ROOT / path
    if not file_path.exists():
        raise AssertionError(f"missing {path}")
    if file_path.stat().st_mode & 0o111 == 0:
        raise AssertionError(f"{path} is not executable")


def require_json_targets() -> None:
    mapping = json.loads(read_text("install/friendly-filenames.json"))
    required = {
        "x86_64-unknown-linux-gnu",
        "i686-unknown-linux-gnu",
        "aarch64-unknown-linux-gnu",
        "armv7-unknown-linux-gnueabihf",
        "arm-unknown-linux-gnueabihf",
        "arm-unknown-linux-gnueabi",
        "mips-unknown-linux-gnu",
        "mipsel-unknown-linux-gnu",
        "mips64-unknown-linux-gnuabi64",
        "mips64el-unknown-linux-gnuabi64",
        "riscv64gc-unknown-linux-gnu",
        "x86_64-apple-darwin",
        "aarch64-apple-darwin",
        "x86_64-pc-windows-msvc",
        "aarch64-pc-windows-msvc",
        "aarch64-linux-android",
    }
    missing = sorted(required.difference(mapping))
    if missing:
        raise AssertionError(f"install/friendly-filenames.json missing targets: {', '.join(missing)}")
    for target, value in mapping.items():
        friendly = value.get("friendlyName")
        if not isinstance(friendly, str) or not friendly:
            raise AssertionError(f"{target} has invalid friendlyName")


def validate() -> list[str]:
    errors: list[str] = []
    checks = [
        lambda: require_terms(
            "scripts/package-release.sh",
            [
                "CARGO_BUILD_TOOL",
                "CARGO_BUILD_FLAGS",
                "ZUICITY_VERSION=",
                "install/example-client.json",
                "install/example-server.json",
                "zuicity-client.service",
                "zuicity-server.service",
                "zip -9qr",
                "md5sum",
                "sha1sum",
                "sha256sum",
                "sha512sum",
                "--friendly-name",
                "friendly_name_override",
                "build_flags",
                "validate_friendly_name",
                "invalid friendly name",
                "release_manifest=",
                ".manifest.txt",
            ],
        ),
        lambda: require_terms(
            "scripts/benchmark-package-release.sh",
            [
                "scripts/package-release.sh",
                "elapsed_millis=",
                "archive_bytes=",
                "package-release-benchmark.txt",
                "package-release-command.log",
            ],
        ),
        lambda: require_terms(
            "scripts/package-deb-smoke.sh",
            [
                "dpkg-deb",
                "fakeroot",
                "--root-owner-group",
                "Package: zuicity",
                "Depends: ca-certificates",
                "/usr/bin/zuicity-client",
                "/usr/bin/zuicity-server",
                "/etc/zuicity/client.json",
                "/etc/zuicity/server.json",
                "/usr/lib/systemd/system/zuicity-client.service",
                "/usr/lib/systemd/system/zuicity-server.service",
                "dpkg-deb --extract",
                "dpkg --admindir",
                "--force-not-root",
                "--log=\"$output_dir/dpkg.log\"",
                "--force-script-chrootless",
                "dpkg.log",
                "dpkg-status.txt",
                "installed-client-version.txt",
                "installed-server-version.txt",
                "systemctl-shim.log",
                "deb-smoke-manifest.txt",
            ],
        ),
        lambda: require_terms(
            "scripts/package-rpm-smoke.sh",
            [
                "rpmbuild",
                "rpm2archive",
                "bsdtar",
                "rpm-payload.tar",
                "rpm-archive-contents.txt",
                "Name: zuicity",
                "Requires: ca-certificates",
                "/usr/bin/zuicity-client",
                "/usr/bin/zuicity-server",
                "/etc/zuicity/client.json",
                "/etc/zuicity/server.json",
                "/usr/lib/systemd/system/zuicity-client.service",
                "/usr/lib/systemd/system/zuicity-server.service",
                "rpm -qp",
                "rpm -qpl",
                "rpm --root",
                "rpm-status.txt",
                "installed-client-version.txt",
                "installed-server-version.txt",
                "rpm-smoke-manifest.txt",
            ],
        ),

        lambda: require_terms(
            "scripts/package-apk-smoke.sh",
            [
                ".PKGINFO",
                ".INSTALL",
                "tar --format=ustar",
                "pkgname = zuicity",
                "depend = ca-certificates",
                "license = AGPL-3.0-only",
                "/usr/bin/zuicity-client",
                "/usr/bin/zuicity-server",
                "/etc/zuicity/client.json",
                "/etc/zuicity/server.json",
                "/usr/lib/systemd/system/zuicity-client.service",
                "/usr/lib/systemd/system/zuicity-server.service",
                "systemctl daemon-reload",
                "apk-pkginfo.txt",
                "apk-contents.txt",
                "apk-sha256.txt",
                "installed-client-version.txt",
                "installed-server-version.txt",
                "apk-smoke-manifest.txt",
            ],
        ),

        lambda: require_terms(
            "scripts/deployment-smoke.sh",
            [
                "scripts/package-release.sh",
                "openssl req",
                "zuicity-server",
                "zuicity-client",
                "\"run\", \"-c\"",
                "deployment-driver.log",
                "deployment-smoke-manifest.txt",
                "tcp_round_trips",
                "udp_round_trips",
                "server_log",
                "client_log",
                "--duration",
                "SIGTERM",
            ],
        ),
        lambda: require_terms(
            "scripts/package-apk-native.sh",
            [
                "require_tool abuild",
                "require_tool apk",
                "abuild-keygen",
                "abuild checksum",
                "abuild -r",
                "x86_64-unknown-linux-musl",
                "+crt-static",
                "pkgname=zuicity",
                "license=\"AGPL-3.0-only\"",
                "depends=\"ca-certificates\"",
                "/usr/bin/zuicity-client",
                "/usr/bin/zuicity-server",
                "apk add --allow-untrusted",
                "apk info -e zuicity",
                "installed-client-version.txt",
                "installed-server-version.txt",
                "apk-native-manifest.txt",
            ],
        ),
        lambda: require_terms(
            ".github/workflows/ci.yml",
            [
                "UPSTREAM_JUICITY_DIR:",
                "UPSTREAM_JUICITY_BIN_DIR:",
                "upstream/juicity-bin",
                "repository: juicity/juicity",
                "actions/setup-go@v5",
                "go-version-file: upstream/juicity/go.mod",
                "go -C \"$UPSTREAM_JUICITY_DIR\" build",
                "cargo fmt --all -- --check",
                "cargo check --workspace --all-targets",
                "cargo test --workspace --all-targets --exclude zuicity-benchmarks",
                "cargo test -p zuicity-benchmarks --test first_slice_smoke",
                "--test-threads=1",
                "scripts/validate-packaging.py",
                "scripts/package-release.sh",
                "scripts/package-deb-smoke.sh",
                "scripts/package-rpm-smoke.sh",
                "scripts/package-apk-smoke.sh",
                "scripts/deployment-smoke.sh",
                "scripts/benchmark-package-release.sh",
                "fakeroot",
                "rpm",
                "libarchive-tools",
                "scripts/package-rpm-smoke.sh",
                "Local RPM package smoke",
                "Local APK package smoke",
                "Local deployment smoke",
                "packaging/**",
                "Build dialer_link differential oracle",
                "differential/oracle/dialer-link-oracle",
                "Dialer_link differential parity tests",
                "alpine-package:",
                "image: alpine",
                "abuild",
                "scripts/package-apk-native.sh",
                "apk add --allow-untrusted",
                "apk info -e zuicity",
            ],
        ),
        lambda: require_terms(
            ".github/workflows/release.yml",
            [
                "workflow_dispatch",
                "source_ref:",
                "platform:",
                "source_ref is only allowed for targeted proof builds",
                "checkout_ref:",
                "fromJSON(needs.validate-tag.outputs.matrix)",
                "needs.validate-tag.outputs.checkout_ref",
                "refs/tags/{tag}",
                "persist-credentials: false",
                "validate-tag:",
                "Validate release inputs",
                "invalid release tag",
                "invalid platform",
                "CARGO_BUILD_TOOL:",
                "CARGO_BUILD_FLAGS:",
                "RUSTFLAGS:",
                "RELEASE_TAG:",
                "rust-src",
                "-Zbuild-std=std,panic_abort",
                "android-actions/setup-android@v3",
                "aarch64-linux-android24-clang",
                '"build_tool": "cross"',
                '"friendly_name":',
                "linux-x86_64",
                "linux-x86_64_v2_sse",
                "linux-x86_64_v3_avx2",
                "linux-x86_32",
                "linux-arm64",
                "linux-armv5",
                "linux-armv6",
                "linux-armv7",
                "linux-mips32",
                "linux-mips32le",
                "linux-mips64",
                "linux-mips64le",
                "linux-riscv64",
                "macos-x86_64",
                "macos-arm64",
                "windows-x86_64",
                "windows-arm64",
                "android-arm64",
                "inputs.platform == 'all'",
                "macos-15-intel",
                "macos-14",
                "windows-latest",
                "scripts/package-release.sh",
                "--friendly-name",
                "zuicity-full-src.zip",
                ".manifest.txt",
                "actions/upload-artifact@v4",
                "actions/download-artifact@v4",
                "softprops/action-gh-release@v2",
                "release/**/*.zip",
                "release/**/*.zip.dgst",
                "contents: read",
                "contents: write",
            ],
        ),
        lambda: require_terms(
            ".github/workflows/docker-publish.yml",
            [
                "ghcr.io",
                "docker/setup-buildx-action@v3",
                "docker/build-push-action@v6",
                "sigstore/cosign-installer@v3",
                "cosign sign",
                "id-token: write",
            ],
        ),
        lambda: require_terms(
            "Dockerfile",
            [
                "cargo build --release -p zuicity-cli --bins",
                "COPY --from=builder /src/target/release/zuicity-server",
                'CMD ["zuicity-server", "run", "-c", "/etc/zuicity/server.json"]',
            ],
        ),
        lambda: require_terms(
            "docs/packaging.md",
            [
                ".github/workflows/ci.yml",
                ".github/workflows/release.yml",
                ".github/workflows/docker-publish.yml",
                "scripts/benchmark-package-release.sh",
                "scripts/package-deb-smoke.sh",
                "scripts/package-rpm-smoke.sh",
                "scripts/package-apk-smoke.sh",
                "scripts/package-apk-native.sh",
                "scripts/deployment-smoke.sh",
                "packaging/nfpm.yaml",
                "--test-threads=1",
                "CARGO_BUILD_TOOL=cross",
                "--friendly-name",
                "linux-x86_64_v2_sse",
                "linux-x86_64_v3_avx2",
                "linux-armv6",
                "macos-arm64",
                "windows-x86_64",
                "android-arm64",
                "zuicity-full-src.zip",
                "targeted proof builds",
            ],
        ),
        require_nfpm_metadata,
        lambda: require_executable("scripts/package-deb-smoke.sh"),
        lambda: require_executable("scripts/package-rpm-smoke.sh"),
        lambda: require_executable("scripts/package-apk-smoke.sh"),
        lambda: require_executable("scripts/package-apk-native.sh"),
        lambda: require_executable("scripts/deployment-smoke.sh"),
        require_json_targets,
    ]
    for check in checks:
        try:
            check()
        except AssertionError as exc:
            errors.append(str(exc))
    return errors


def main() -> int:
    errors = validate()
    if errors:
        print("packaging validation failed:")
        for error in errors:
            print(f"- {error}")
        return 1
    print("packaging validation passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
