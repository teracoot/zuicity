#!/usr/bin/env bash
set -euo pipefail

export PATH="$HOME/.cargo/bin:/root/.cargo/bin:$PATH"

usage() {
  cat <<'USAGE'
Usage: scripts/package-rpm-smoke.sh [OPTIONS]

Build and smoke-test a local RPM package from Zuicity Rust release assets.

Options:
  --target <triple>      Host Linux Rust target triple. Defaults to rustc host triple.
  --output-dir <path>    Output directory. Defaults to /tmp/zuicity-rpm-smoke.
  --version <version>    Version string used for release staging. Defaults to Cargo workspace version.
  --skip-build           Reuse existing release binaries when staging release assets.
  -h, --help             Print this help.
USAGE
}

repo_root() {
  local script_dir
  script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  cd "$script_dir/.." && pwd
}

host_triple() {
  rustc -vV | awk '/^host: / { print $2 }'
}

cargo_workspace_version() {
  python3 - <<'PY'
from pathlib import Path
for line in Path('Cargo.toml').read_text().splitlines():
    if line.strip().startswith('version = '):
        print(line.split('=', 1)[1].strip().strip('"'))
        raise SystemExit(0)
raise SystemExit('workspace version not found')
PY
}

require_tool() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "missing required tool: $1" >&2
    exit 2
  }
}

rpm_arch_for_target() {
  case "$1" in
    x86_64-unknown-linux-gnu) printf 'x86_64\n' ;;
    i686-unknown-linux-gnu) printf 'i686\n' ;;
    aarch64-unknown-linux-gnu) printf 'aarch64\n' ;;
    armv7-unknown-linux-gnueabihf) printf 'armv7hl\n' ;;
    *)
      echo "unsupported RPM smoke target: $1" >&2
      echo "supported host targets: x86_64-unknown-linux-gnu, i686-unknown-linux-gnu, aarch64-unknown-linux-gnu, armv7-unknown-linux-gnueabihf" >&2
      exit 2
      ;;
  esac
}

normalize_rpm_version() {
  local raw normalized
  raw="$1"
  normalized="$(printf '%s' "$raw" | sed -E 's/[^A-Za-z0-9._~]+/./g; s/^[^A-Za-z0-9]+//; s/\.+/./g; s/\.$//')"
  if [ -z "$normalized" ]; then
    normalized="0.0.0"
  fi
  case "$normalized" in
    [0-9]*) ;;
    *) normalized="0.0.0.$normalized" ;;
  esac
  printf '%s\n' "$normalized"
}

require_file() {
  [ -f "$1" ] || { echo "missing expected file: $1" >&2; exit 1; }
}

require_executable() {
  [ -x "$1" ] || { echo "missing expected executable: $1" >&2; exit 1; }
}

require_grep() {
  local pattern file
  pattern="$1"
  file="$2"
  grep -F -- "$pattern" "$file" >/dev/null || {
    echo "missing pattern in $file: $pattern" >&2
    exit 1
  }
}

print_failure_context() {
  local rc="$1"
  trap - ERR
  set +e
  local dir="${output_dir:-}"
  echo "package-rpm-smoke failed with exit code $rc" >&2
  if [ -n "$dir" ]; then
    echo "output_dir=$dir" >&2
    for name in \
      package-release.log \
      rpmbuild.log \
      rpm-info.txt \
      rpm-contents.txt \
      rpm-requires.txt \
      rpm-scripts.txt \
      rpm2archive.log \
      rpm-archive-contents.txt \
      rpm-install.log \
      rpm-status.txt \
      installed-client-version.txt \
      installed-server-version.txt \
      installed-root-client-version.txt \
      installed-root-server-version.txt \
      rpm-smoke-manifest.txt; do
      local file="$dir/$name"
      if [ -f "$file" ]; then
        echo "===== $file =====" >&2
        sed -n '1,220p' "$file" >&2
      fi
    done
    if command -v find >/dev/null 2>&1; then
      echo "===== $dir file tree =====" >&2
      find "$dir" -maxdepth 4 -type f -printf '%M %s %p\n' 2>/dev/null | sort | sed -n '1,180p' >&2
    fi
  fi
  exit "$rc"
}

target=""
output_dir="/tmp/zuicity-rpm-smoke"
version=""
skip_build=0
trap 'print_failure_context "$?"' ERR
while [ "$#" -gt 0 ]; do
  case "$1" in
    --target)
      [ "$#" -ge 2 ] || { echo "--target requires a value" >&2; exit 2; }
      target="$2"
      shift 2
      ;;
    --output-dir)
      [ "$#" -ge 2 ] || { echo "--output-dir requires a value" >&2; exit 2; }
      output_dir="$2"
      shift 2
      ;;
    --version)
      [ "$#" -ge 2 ] || { echo "--version requires a value" >&2; exit 2; }
      version="$2"
      shift 2
      ;;
    --skip-build)
      skip_build=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

root="$(repo_root)"
cd "$root"
case "$output_dir" in
  /*) ;;
  *) output_dir="$root/$output_dir" ;;
esac
require_tool bash
require_tool bsdtar
require_tool fakeroot
require_tool install
require_tool python3
require_tool rpm
require_tool rpmbuild
require_tool rpm2archive
require_tool rustc
require_tool sed

target="${target:-$(host_triple)}"
host="$(host_triple)"
if [ "$target" != "$host" ]; then
  echo "RPM install smoke executes packaged binaries and must use the host target ($host), got $target" >&2
  exit 2
fi

version="${version:-$(cargo_workspace_version)}"
rpm_version="$(normalize_rpm_version "$version")"
rpm_release="1"
rpm_arch="$(rpm_arch_for_target "$target")"
release_dir="$output_dir/release"
rpmbuild_dir="$output_dir/rpmbuild"
spec_dir="$rpmbuild_dir/SPECS"
rpm_dir="$output_dir/dist"
install_root="$output_dir/install-root"
rpm_root="$output_dir/rpm-root"
manifest="$output_dir/rpm-smoke-manifest.txt"
spec_file="$spec_dir/zuicity.spec"

rm -rf "$output_dir"
mkdir -p "$output_dir" "$rpm_dir" "$spec_dir" "$rpmbuild_dir/BUILD" "$rpmbuild_dir/BUILDROOT" "$rpmbuild_dir/RPMS" "$rpmbuild_dir/SOURCES" "$rpmbuild_dir/SRPMS"

release_args=(scripts/package-release.sh --target "$target" --output-dir "$release_dir" --version "$version")
if [ "$skip_build" -eq 1 ]; then
  release_args+=(--skip-build)
fi
"${release_args[@]}" >"$output_dir/package-release.log" 2>&1

release_build="$release_dir/build"
require_executable "$release_build/zuicity-client"
require_executable "$release_build/zuicity-server"
require_file "$release_build/example-client.json"
require_file "$release_build/example-server.json"
require_file "$release_build/zuicity-client.service"
require_file "$release_build/zuicity-server.service"

changelog_date="$(LC_ALL=C date '+%a %b %d %Y')"
cat >"$spec_file" <<SPEC
Name: zuicity
Version: $rpm_version
Release: $rpm_release
Summary: Rust port of Zuicity
License: AGPL-3.0-only
URL: https://github.com/teracoot/zuicity
Group: Applications/Internet
BuildArch: $rpm_arch
Requires: ca-certificates
AutoReqProv: no

%description
Rust port of Zuicity, including zuicity-client and zuicity-server.
This package includes example configuration files and systemd unit templates.

%prep

%build

%install
rm -rf %{buildroot}
install -d -m 0755 %{buildroot}/usr/bin
install -d -m 0755 %{buildroot}/etc/zuicity
install -d -m 0755 %{buildroot}/usr/lib/systemd/system
install -m 0755 $release_build/zuicity-client %{buildroot}/usr/bin/zuicity-client
install -m 0755 $release_build/zuicity-server %{buildroot}/usr/bin/zuicity-server
install -m 0644 $release_build/example-client.json %{buildroot}/etc/zuicity/client.json
install -m 0644 $release_build/example-server.json %{buildroot}/etc/zuicity/server.json
install -m 0644 $release_build/zuicity-client.service %{buildroot}/usr/lib/systemd/system/zuicity-client.service
install -m 0644 $release_build/zuicity-server.service %{buildroot}/usr/lib/systemd/system/zuicity-server.service

%post
if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
  systemctl daemon-reload
fi

%postun
if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
  systemctl daemon-reload
fi

%files
%defattr(-,root,root,-)
/usr/bin/zuicity-client
/usr/bin/zuicity-server
%config(noreplace) /etc/zuicity/client.json
%config(noreplace) /etc/zuicity/server.json
/usr/lib/systemd/system/zuicity-client.service
/usr/lib/systemd/system/zuicity-server.service

%changelog
* $changelog_date Zuicity Rust maintainers <noreply@github.com> - $rpm_version-$rpm_release
- Local smoke package
SPEC

fakeroot rpmbuild \
  --define "_topdir $rpmbuild_dir" \
  --define "_rpmdir $rpm_dir" \
  --define "_build_id_links none" \
  --define "debug_package %{nil}" \
  -bb "$spec_file" >"$output_dir/rpmbuild.log" 2>&1

package_file="$(find "$rpm_dir" -type f -name '*.rpm' | sort | head -n 1)"
[ -n "$package_file" ] || { echo "rpmbuild did not produce an RPM" >&2; exit 1; }
require_file "$package_file"

rpm -qpi "$package_file" >"$output_dir/rpm-info.txt"
rpm -qpl "$package_file" >"$output_dir/rpm-contents.txt"
rpm -qpR "$package_file" >"$output_dir/rpm-requires.txt"
rpm -qp --scripts "$package_file" >"$output_dir/rpm-scripts.txt"

[ "$(rpm -qp --queryformat '%{NAME}' "$package_file")" = "zuicity" ] || { echo "unexpected package name" >&2; exit 1; }
[ "$(rpm -qp --queryformat '%{VERSION}' "$package_file")" = "$rpm_version" ] || { echo "unexpected package version" >&2; exit 1; }
[ "$(rpm -qp --queryformat '%{ARCH}' "$package_file")" = "$rpm_arch" ] || { echo "unexpected package architecture" >&2; exit 1; }
require_grep "ca-certificates" "$output_dir/rpm-requires.txt"
require_grep "/usr/bin/zuicity-client" "$output_dir/rpm-contents.txt"
require_grep "/usr/bin/zuicity-server" "$output_dir/rpm-contents.txt"
require_grep "/etc/zuicity/client.json" "$output_dir/rpm-contents.txt"
require_grep "/etc/zuicity/server.json" "$output_dir/rpm-contents.txt"
require_grep "/usr/lib/systemd/system/zuicity-client.service" "$output_dir/rpm-contents.txt"
require_grep "/usr/lib/systemd/system/zuicity-server.service" "$output_dir/rpm-contents.txt"
require_grep "systemctl daemon-reload" "$output_dir/rpm-scripts.txt"

archive_file="$output_dir/rpm-payload.tar"
rpm2archive -n "$package_file" >"$archive_file" 2>"$output_dir/rpm2archive.log"
require_file "$archive_file"
mkdir -p "$install_root"
bsdtar -tf "$archive_file" >"$output_dir/rpm-archive-contents.txt"
bsdtar -xf "$archive_file" -C "$install_root"

require_executable "$install_root/usr/bin/zuicity-client"
require_executable "$install_root/usr/bin/zuicity-server"
require_file "$install_root/etc/zuicity/client.json"
require_file "$install_root/etc/zuicity/server.json"
require_file "$install_root/usr/lib/systemd/system/zuicity-client.service"
require_file "$install_root/usr/lib/systemd/system/zuicity-server.service"
"$install_root/usr/bin/zuicity-client" -v >"$output_dir/installed-client-version.txt" 2>&1
"$install_root/usr/bin/zuicity-server" -v >"$output_dir/installed-server-version.txt" 2>&1

mkdir -p "$rpm_root"
rpm --root "$rpm_root" --initdb >"$output_dir/rpm-initdb.log" 2>&1
rpm --root "$rpm_root" --nodeps --nosignature --noscripts --install "$package_file" >"$output_dir/rpm-install.log" 2>&1
require_executable "$rpm_root/usr/bin/zuicity-client"
require_executable "$rpm_root/usr/bin/zuicity-server"
require_file "$rpm_root/etc/zuicity/client.json"
require_file "$rpm_root/etc/zuicity/server.json"
require_file "$rpm_root/usr/lib/systemd/system/zuicity-client.service"
require_file "$rpm_root/usr/lib/systemd/system/zuicity-server.service"
rpm --root "$rpm_root" -q zuicity >"$output_dir/rpm-status.txt"
require_grep "zuicity-$rpm_version-$rpm_release" "$output_dir/rpm-status.txt"
"$rpm_root/usr/bin/zuicity-client" -v >"$output_dir/installed-root-client-version.txt" 2>&1
"$rpm_root/usr/bin/zuicity-server" -v >"$output_dir/installed-root-server-version.txt" 2>&1

sha256sum "$package_file" >"$output_dir/rpm-sha256.txt"

cat >"$manifest" <<MANIFEST
version=$version
rpm_version=$rpm_version
rpm_release=$rpm_release
target=$target
rpm_arch=$rpm_arch
release_dir=$release_dir
package_file=$package_file
archive_file=$archive_file
install_root=$install_root
rpm_root=$rpm_root
rpm_info=$output_dir/rpm-info.txt
rpm_contents=$output_dir/rpm-contents.txt
rpm_requires=$output_dir/rpm-requires.txt
rpm_scripts=$output_dir/rpm-scripts.txt
client_version=$output_dir/installed-client-version.txt
server_version=$output_dir/installed-server-version.txt
root_client_version=$output_dir/installed-root-client-version.txt
root_server_version=$output_dir/installed-root-server-version.txt
package_release_log=$output_dir/package-release.log
rpmbuild_log=$output_dir/rpmbuild.log
rpm_install_log=$output_dir/rpm-install.log
rpm_status=$output_dir/rpm-status.txt
rpm_sha256=$output_dir/rpm-sha256.txt
MANIFEST

printf 'rpm=%s\n' "$package_file"
printf 'manifest=%s\n' "$manifest"
printf 'install_root=%s\n' "$install_root"
printf 'rpm_root=%s\n' "$rpm_root"
printf 'contents=%s\n' "$output_dir/rpm-contents.txt"
printf 'info=%s\n' "$output_dir/rpm-info.txt"
