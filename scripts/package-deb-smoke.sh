#!/usr/bin/env bash
set -euo pipefail

export PATH="$HOME/.cargo/bin:/root/.cargo/bin:$PATH"

usage() {
  cat <<'USAGE'
Usage: scripts/package-deb-smoke.sh [OPTIONS]

Build and smoke-test a local Debian package from Zuicity Rust release assets.

Options:
  --target <triple>      Host Linux Rust target triple. Defaults to rustc host triple.
  --output-dir <path>    Output directory. Defaults to /tmp/zuicity-deb-smoke.
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

deb_arch_for_target() {
  case "$1" in
    x86_64-unknown-linux-gnu) printf 'amd64\n' ;;
    i686-unknown-linux-gnu) printf 'i386\n' ;;
    aarch64-unknown-linux-gnu) printf 'arm64\n' ;;
    armv7-unknown-linux-gnueabihf) printf 'armhf\n' ;;
    *)
      echo "unsupported Debian smoke target: $1" >&2
      echo "supported host targets: x86_64-unknown-linux-gnu, i686-unknown-linux-gnu, aarch64-unknown-linux-gnu, armv7-unknown-linux-gnueabihf" >&2
      exit 2
      ;;
  esac
}

normalize_deb_version() {
  local raw normalized
  raw="$1"
  normalized="$(printf '%s' "$raw" | sed -E 's/[^A-Za-z0-9.+:~-]+/+/g')"
  case "$normalized" in
    [0-9]*) ;;
    *) normalized="0.0.0+$normalized" ;;
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
  echo "package-deb-smoke failed with exit code $rc" >&2
  if [ -n "$dir" ]; then
    echo "output_dir=$dir" >&2
    for name in \
      package-release.log \
      dpkg-build.log \
      dpkg-install.log \
      dpkg-status.txt \
      deb-control.txt \
      deb-contents.txt \
      deb-info.txt \
      installed-client-version.txt \
      installed-server-version.txt \
      systemctl-shim.log \
      deb-smoke-manifest.txt; do
      local file="$dir/$name"
      if [ -f "$file" ]; then
        echo "===== $file =====" >&2
        sed -n '1,220p' "$file" >&2
      fi
    done
    if command -v find >/dev/null 2>&1; then
      echo "===== $dir file tree =====" >&2
      find "$dir" -maxdepth 3 -type f -printf '%M %s %p\n' 2>/dev/null | sort | sed -n '1,160p' >&2
    fi
  fi
  exit "$rc"
}

target=""
output_dir="/tmp/zuicity-deb-smoke"
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
require_tool dpkg
require_tool dpkg-deb
require_tool fakeroot
require_tool install
require_tool python3
require_tool rustc
require_tool sed

target="${target:-$(host_triple)}"
host="$(host_triple)"
if [ "$target" != "$host" ]; then
  echo "Debian install smoke executes packaged binaries and must use the host target ($host), got $target" >&2
  exit 2
fi

version="${version:-$(cargo_workspace_version)}"
deb_version="$(normalize_deb_version "$version")"
dpkg --validate-version "$deb_version" >/dev/null

deb_arch="$(deb_arch_for_target "$target")"
release_dir="$output_dir/release"
package_root="$output_dir/deb-root"
install_root="$output_dir/install-root"
control_root="$output_dir/control"
dpkg_root="$output_dir/dpkg-root"
dpkg_admindir="$output_dir/dpkg-admin"
deb_dir="$output_dir/dist"
fake_bin="$output_dir/fake-bin"
systemctl_log="$output_dir/systemctl-shim.log"
manifest="$output_dir/deb-smoke-manifest.txt"

rm -rf "$output_dir"
mkdir -p "$output_dir" "$deb_dir"

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

mkdir -p \
  "$package_root/DEBIAN" \
  "$package_root/usr/bin" \
  "$package_root/etc/zuicity" \
  "$package_root/usr/lib/systemd/system"
install -m 0755 "$release_build/zuicity-client" "$package_root/usr/bin/zuicity-client"
install -m 0755 "$release_build/zuicity-server" "$package_root/usr/bin/zuicity-server"
install -m 0644 "$release_build/example-client.json" "$package_root/etc/zuicity/client.json"
install -m 0644 "$release_build/example-server.json" "$package_root/etc/zuicity/server.json"
install -m 0644 "$release_build/zuicity-client.service" "$package_root/usr/lib/systemd/system/zuicity-client.service"
install -m 0644 "$release_build/zuicity-server.service" "$package_root/usr/lib/systemd/system/zuicity-server.service"
install -m 0755 packaging/systemd/postinstall.sh "$package_root/DEBIAN/postinst"
install -m 0755 packaging/systemd/postremove.sh "$package_root/DEBIAN/postrm"

installed_size="$(du -sk "$package_root/usr" "$package_root/etc" | awk '{ total += $1 } END { print total + 0 }')"
cat >"$package_root/DEBIAN/control" <<CONTROL
Package: zuicity
Version: $deb_version
Section: net
Priority: optional
Architecture: $deb_arch
Maintainer: Zuicity Rust maintainers <noreply@github.com>
Installed-Size: $installed_size
Depends: ca-certificates
Homepage: https://github.com/teracoot/zuicity
Description: Rust port of Zuicity
 Rust port of Zuicity, including zuicity-client and zuicity-server.
 This package includes example configuration files and systemd unit templates.
CONTROL

package_file="$deb_dir/zuicity_${deb_version}_${deb_arch}.deb"
fakeroot dpkg-deb --root-owner-group --build "$package_root" "$package_file" >"$output_dir/dpkg-build.log" 2>&1
require_file "$package_file"

dpkg-deb --info "$package_file" >"$output_dir/deb-info.txt"
dpkg-deb --contents "$package_file" >"$output_dir/deb-contents.txt"
dpkg-deb --field "$package_file" >"$output_dir/deb-control.txt"
dpkg-deb --extract "$package_file" "$install_root"
dpkg-deb --control "$package_file" "$control_root"

[ "$(dpkg-deb -f "$package_file" Package)" = "zuicity" ] || { echo "unexpected package name" >&2; exit 1; }
[ "$(dpkg-deb -f "$package_file" Version)" = "$deb_version" ] || { echo "unexpected package version" >&2; exit 1; }
[ "$(dpkg-deb -f "$package_file" Architecture)" = "$deb_arch" ] || { echo "unexpected package architecture" >&2; exit 1; }
require_grep "Depends: ca-certificates" "$output_dir/deb-control.txt"
require_grep "./usr/bin/zuicity-client" "$output_dir/deb-contents.txt"
require_grep "./usr/bin/zuicity-server" "$output_dir/deb-contents.txt"
require_grep "./etc/zuicity/client.json" "$output_dir/deb-contents.txt"
require_grep "./etc/zuicity/server.json" "$output_dir/deb-contents.txt"
require_grep "./usr/lib/systemd/system/zuicity-client.service" "$output_dir/deb-contents.txt"
require_grep "./usr/lib/systemd/system/zuicity-server.service" "$output_dir/deb-contents.txt"

require_executable "$install_root/usr/bin/zuicity-client"
require_executable "$install_root/usr/bin/zuicity-server"
require_file "$install_root/etc/zuicity/client.json"
require_file "$install_root/etc/zuicity/server.json"
require_file "$install_root/usr/lib/systemd/system/zuicity-client.service"
require_file "$install_root/usr/lib/systemd/system/zuicity-server.service"
"$install_root/usr/bin/zuicity-client" -v >"$output_dir/installed-client-version.txt" 2>&1
"$install_root/usr/bin/zuicity-server" -v >"$output_dir/installed-server-version.txt" 2>&1

mkdir -p "$fake_bin" "$dpkg_root" "$dpkg_admindir"
cat >"$fake_bin/systemctl" <<SH
#!/usr/bin/env sh
printf '%s\n' "\$*" >>"$systemctl_log"
SH
chmod 0755 "$fake_bin/systemctl"
: >"$systemctl_log"
: >"$dpkg_admindir/status"
PATH="$fake_bin:/usr/sbin:/usr/bin:/sbin:/bin" dpkg \
  --force-not-root \
  --log="$output_dir/dpkg.log" \
  --admindir="$dpkg_admindir" \
  --instdir="$dpkg_root" \
  --force-depends \
  --force-script-chrootless \
  --install "$package_file" >"$output_dir/dpkg-install.log" 2>&1
require_executable "$dpkg_root/usr/bin/zuicity-client"
require_executable "$dpkg_root/usr/bin/zuicity-server"
require_file "$dpkg_root/etc/zuicity/client.json"
require_file "$dpkg_root/etc/zuicity/server.json"
require_file "$dpkg_root/usr/lib/systemd/system/zuicity-client.service"
require_file "$dpkg_root/usr/lib/systemd/system/zuicity-server.service"
dpkg --admindir="$dpkg_admindir" --status zuicity >"$output_dir/dpkg-status.txt"
require_grep "Status: install ok installed" "$output_dir/dpkg-status.txt"
PATH="$fake_bin:/usr/sbin:/usr/bin:/sbin:/bin" "$control_root/postrm"

cat >"$manifest" <<MANIFEST
version=$version
deb_version=$deb_version
target=$target
deb_arch=$deb_arch
release_dir=$release_dir
package_file=$package_file
install_root=$install_root
control_root=$control_root
dpkg_root=$dpkg_root
dpkg_admindir=$dpkg_admindir
deb_info=$output_dir/deb-info.txt
deb_contents=$output_dir/deb-contents.txt
deb_control=$output_dir/deb-control.txt
client_version=$output_dir/installed-client-version.txt
server_version=$output_dir/installed-server-version.txt
package_release_log=$output_dir/package-release.log
dpkg_build_log=$output_dir/dpkg-build.log
dpkg_install_log=$output_dir/dpkg-install.log
dpkg_status=$output_dir/dpkg-status.txt
systemctl_shim_log=$systemctl_log
MANIFEST

printf 'deb=%s\n' "$package_file"
printf 'manifest=%s\n' "$manifest"
printf 'install_root=%s\n' "$install_root"
printf 'dpkg_root=%s\n' "$dpkg_root"
printf 'contents=%s\n' "$output_dir/deb-contents.txt"
printf 'control=%s\n' "$output_dir/deb-control.txt"
