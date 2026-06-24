#!/usr/bin/env bash
set -euo pipefail

export PATH="$HOME/.cargo/bin:/root/.cargo/bin:$PATH"

usage() {
  cat <<'USAGE'
Usage: scripts/package-apk-smoke.sh [OPTIONS]

Build and smoke-test a local Alpine APK-format package from Zuicity Rust release assets.

Options:
  --target <triple>      Host Linux Rust target triple. Defaults to rustc host triple.
  --output-dir <path>    Output directory. Defaults to /tmp/zuicity-apk-smoke.
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

apk_arch_for_target() {
  case "$1" in
    x86_64-unknown-linux-gnu) printf 'x86_64\n' ;;
    i686-unknown-linux-gnu) printf 'x86\n' ;;
    aarch64-unknown-linux-gnu) printf 'aarch64\n' ;;
    armv7-unknown-linux-gnueabihf) printf 'armv7\n' ;;
    *)
      echo "unsupported APK smoke target: $1" >&2
      echo "supported host targets: x86_64-unknown-linux-gnu, i686-unknown-linux-gnu, aarch64-unknown-linux-gnu, armv7-unknown-linux-gnueabihf" >&2
      exit 2
      ;;
  esac
}

normalize_apk_version() {
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
  echo "package-apk-smoke failed with exit code $rc" >&2
  if [ -n "$dir" ]; then
    echo "output_dir=$dir" >&2
    for name in \
      package-release.log \
      apk-pkginfo.txt \
      apk-install-script.txt \
      apk-contents.txt \
      apk-listing.txt \
      apk-sha256.txt \
      installed-client-version.txt \
      installed-server-version.txt \
      apk-smoke-manifest.txt; do
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
output_dir="/tmp/zuicity-apk-smoke"
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
require_tool awk
require_tool bash
require_tool gzip
require_tool install
require_tool python3
require_tool rustc
require_tool sed
require_tool sha256sum
require_tool tar

target="${target:-$(host_triple)}"
host="$(host_triple)"
if [ "$target" != "$host" ]; then
  echo "APK extraction smoke executes packaged binaries and must use the host target ($host), got $target" >&2
  exit 2
fi

version="${version:-$(cargo_workspace_version)}"
apk_version="$(normalize_apk_version "$version")"
apk_release="1"
apk_pkgver="$apk_version-r$apk_release"
apk_arch="$(apk_arch_for_target "$target")"
release_dir="$output_dir/release"
package_root="$output_dir/apk-root"
install_root="$output_dir/install-root"
apk_dir="$output_dir/dist"
manifest="$output_dir/apk-smoke-manifest.txt"

rm -rf "$output_dir"
mkdir -p "$output_dir" "$apk_dir"

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
  "$package_root/usr/bin" \
  "$package_root/etc/zuicity" \
  "$package_root/usr/lib/systemd/system"
install -m 0755 "$release_build/zuicity-client" "$package_root/usr/bin/zuicity-client"
install -m 0755 "$release_build/zuicity-server" "$package_root/usr/bin/zuicity-server"
install -m 0644 "$release_build/example-client.json" "$package_root/etc/zuicity/client.json"
install -m 0644 "$release_build/example-server.json" "$package_root/etc/zuicity/server.json"
install -m 0644 "$release_build/zuicity-client.service" "$package_root/usr/lib/systemd/system/zuicity-client.service"
install -m 0644 "$release_build/zuicity-server.service" "$package_root/usr/lib/systemd/system/zuicity-server.service"

installed_size="$(du -sb "$package_root/usr" "$package_root/etc" | awk '{ total += $1 } END { print total + 0 }')"
builddate="$(date '+%s')"
cat >"$package_root/.PKGINFO" <<PKGINFO
# Generated by scripts/package-apk-smoke.sh
pkgname = zuicity
pkgver = $apk_pkgver
pkgdesc = Rust port of Zuicity
url = https://github.com/teracoot/zuicity
builddate = $builddate
packager = Zuicity Rust maintainers <noreply@github.com>
size = $installed_size
arch = $apk_arch
license = AGPL-3.0-only
depend = ca-certificates
PKGINFO

cat >"$package_root/.INSTALL" <<'INSTALL'
post_install() {
  if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
    systemctl daemon-reload
  fi
}

post_deinstall() {
  if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
    systemctl daemon-reload
  fi
}
INSTALL
chmod 0755 "$package_root/.INSTALL"

package_file="$apk_dir/zuicity-$apk_pkgver.$apk_arch.apk"
(
  cd "$package_root"
  tar --format=ustar --owner=0 --group=0 --numeric-owner -czf "$package_file" .PKGINFO .INSTALL usr etc
)
require_file "$package_file"

tar -tzf "$package_file" >"$output_dir/apk-contents.txt"
tar -tvzf "$package_file" >"$output_dir/apk-listing.txt"
cp "$package_root/.PKGINFO" "$output_dir/apk-pkginfo.txt"
cp "$package_root/.INSTALL" "$output_dir/apk-install-script.txt"
mkdir -p "$install_root"
tar -xzf "$package_file" -C "$install_root"

require_grep "pkgname = zuicity" "$output_dir/apk-pkginfo.txt"
require_grep "pkgver = $apk_pkgver" "$output_dir/apk-pkginfo.txt"
require_grep "arch = $apk_arch" "$output_dir/apk-pkginfo.txt"
require_grep "depend = ca-certificates" "$output_dir/apk-pkginfo.txt"
require_grep "license = AGPL-3.0-only" "$output_dir/apk-pkginfo.txt"
require_grep ".PKGINFO" "$output_dir/apk-contents.txt"
require_grep ".INSTALL" "$output_dir/apk-contents.txt"
require_grep "usr/bin/zuicity-client" "$output_dir/apk-contents.txt"
require_grep "usr/bin/zuicity-server" "$output_dir/apk-contents.txt"
require_grep "etc/zuicity/client.json" "$output_dir/apk-contents.txt"
require_grep "etc/zuicity/server.json" "$output_dir/apk-contents.txt"
require_grep "usr/lib/systemd/system/zuicity-client.service" "$output_dir/apk-contents.txt"
require_grep "usr/lib/systemd/system/zuicity-server.service" "$output_dir/apk-contents.txt"
require_grep "systemctl daemon-reload" "$output_dir/apk-install-script.txt"

require_executable "$install_root/usr/bin/zuicity-client"
require_executable "$install_root/usr/bin/zuicity-server"
require_file "$install_root/etc/zuicity/client.json"
require_file "$install_root/etc/zuicity/server.json"
require_file "$install_root/usr/lib/systemd/system/zuicity-client.service"
require_file "$install_root/usr/lib/systemd/system/zuicity-server.service"
"$install_root/usr/bin/zuicity-client" -v >"$output_dir/installed-client-version.txt" 2>&1
"$install_root/usr/bin/zuicity-server" -v >"$output_dir/installed-server-version.txt" 2>&1

sha256sum "$package_file" >"$output_dir/apk-sha256.txt"

cat >"$manifest" <<MANIFEST
version=$version
apk_version=$apk_version
apk_release=$apk_release
apk_pkgver=$apk_pkgver
target=$target
apk_arch=$apk_arch
release_dir=$release_dir
package_file=$package_file
install_root=$install_root
apk_pkginfo=$output_dir/apk-pkginfo.txt
apk_install_script=$output_dir/apk-install-script.txt
apk_contents=$output_dir/apk-contents.txt
apk_listing=$output_dir/apk-listing.txt
client_version=$output_dir/installed-client-version.txt
server_version=$output_dir/installed-server-version.txt
package_release_log=$output_dir/package-release.log
apk_sha256=$output_dir/apk-sha256.txt
MANIFEST

printf 'apk=%s\n' "$package_file"
printf 'manifest=%s\n' "$manifest"
printf 'install_root=%s\n' "$install_root"
printf 'contents=%s\n' "$output_dir/apk-contents.txt"
printf 'pkginfo=%s\n' "$output_dir/apk-pkginfo.txt"
