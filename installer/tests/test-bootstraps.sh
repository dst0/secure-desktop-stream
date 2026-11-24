#!/usr/bin/env bash
# End-to-end bootstrapper, uninstaller, packager, syntax, and static security tests.
set -euo pipefail

script_dir=$(cd "$(dirname "$0")" && pwd)
installer_root=$(cd "$script_dir/.." && pwd)

echo "-- 1. Shell syntax checks"
bash -n "$installer_root/bootstrap/get.sh"
bash -n "$installer_root/bootstrap/install-macos.sh"
bash -n "$installer_root/bootstrap/uninstall.sh"
bash -n "$installer_root/packaging/package-release.sh"
bash -n "$installer_root/tests/test-bootstraps.sh"
sh -n "$installer_root/bootstrap/install-linux.sh"

echo "-- 2. Native GUI / TUI architecture checks (no leftover web_gui/assets)"
if [ -d "$installer_root/assets" ]; then
  echo "ERROR: legacy installer/assets directory should not exist" >&2
  exit 1
fi
if [ -f "$installer_root/src/web_gui.rs" ]; then
  echo "ERROR: legacy src/web_gui.rs should not exist" >&2
  exit 1
fi
if grep -rnE 'start_web_gui|try_open_browser|web_gui' "$installer_root/src/" "$installer_root/tests/integration_tests.rs"; then
  echo "ERROR: legacy web_gui reference found in Rust source/tests" >&2
  exit 1
fi

echo "-- 3. Uninstaller CLI help & isolated dry-run checks"
tmp_home=$(mktemp -d)
trap 'rm -rf "$tmp_home"' EXIT
HOME="$tmp_home" bash "$installer_root/bootstrap/uninstall.sh" --help | grep -q 'purge-config'
HOME="$tmp_home" bash "$installer_root/bootstrap/uninstall.sh" --component all --user-only --dry-run >/dev/null
HOME="$tmp_home" bash "$installer_root/bootstrap/install-macos.sh" --help | grep -q 'auto-deps'
HOME="$tmp_home" sh "$installer_root/bootstrap/install-linux.sh" --help | grep -q 'auto-deps'

echo "-- 4. PowerShell static security & zip-slip checks"
grep -q 'ConvertStringSecurityDescriptorToSecurityDescriptorW' "$installer_root/bootstrap/install-windows.ps1"
grep -q 'OpenRead' "$installer_root/bootstrap/install-windows.ps1"
grep -q 'FullName' "$installer_root/bootstrap/install-windows.ps1"
grep -q 'ReparsePoint' "$installer_root/bootstrap/uninstall.ps1"
grep -q 'SDS-\*' "$installer_root/bootstrap/uninstall.ps1"

echo "-- 5. End-to-end macOS packager, install, and uninstall verification (when on Darwin + cargo)"
if [ "$(uname -s)" = Darwin ] && command -v cargo >/dev/null 2>&1; then
  work="$tmp_home/mac-work"
  mkdir -p "$work"
  version=$(sed -n 's/^version = "\(.*\)"/\1/p' "$installer_root/Cargo.toml" | head -n1)
  (cd "$installer_root" && cargo build --release --locked)
  bin="$installer_root/target/release/sds-installer"
  bash "$installer_root/packaging/package-release.sh" --version "$version" --binary "$bin" --out "$work/dist"

  arch=$(uname -m)
  zip_file=$(ls "$work/dist"/sds-installer-*-macos-"$arch".zip)
  sha=$(awk '{print $1}' "$work/dist/SHA256SUMS")

  # Dry-run archive verification
  HOME="$work/home1" bash "$installer_root/bootstrap/install-macos.sh" \
    --archive "$zip_file" --sha256 "$sha" --user --dry-run

  # Isolated real install under temporary HOME (never touches real /Applications or ~/Applications)
  mkdir -p "$work/home2/Applications" "$work/home2/.local/bin"
  HOME="$work/home2" bash "$installer_root/bootstrap/install-macos.sh" \
    --archive "$zip_file" --sha256 "$sha" --user --allow-unnotarized --no-gui

  installed_app="$work/home2/Applications/Secure Desktop Stream Installer.app"
  [ -x "$installed_app/Contents/MacOS/sds-installer" ]
  /usr/bin/codesign --verify --deep --strict "$installed_app"
  "$installed_app/Contents/MacOS/sds-installer" --version | grep -q 'sds-installer '
  deps_rc=0
  deps_out=$(HOME="$work/home2" "$installed_app/Contents/MacOS/sds-installer" deps check --role client --json) || deps_rc=$?
  [ "$deps_rc" -eq 0 ] || [ "$deps_rc" -eq 10 ]
  printf '%s' "$deps_out" | grep -q '"role"'

  # Dry-run + real clean uninstall inside isolated HOME
  HOME="$work/home2" bash "$installer_root/bootstrap/uninstall.sh" --component installer --user-only --dry-run
  HOME="$work/home2" bash "$installer_root/bootstrap/uninstall.sh" --component installer --user-only
  [ ! -e "$installed_app" ]

  # Symlink destination rejection test
  mkdir -p "$work/home3/Applications"
  ln -s /tmp "$work/home3/Applications/Secure Desktop Stream Installer.app"
  if HOME="$work/home3" bash "$installer_root/bootstrap/install-macos.sh" \
    --archive "$zip_file" --sha256 "$sha" --user --no-gui 2>/dev/null; then
    echo "ERROR: expected symlink destination rejection" >&2
    exit 1
  fi

  # Checksum mismatch rejection test
  bad_sha=$(printf '%064d' 0)
  if HOME="$work/home4" bash "$installer_root/bootstrap/install-macos.sh" \
    --archive "$zip_file" --sha256 "$bad_sha" --user --no-gui 2>/dev/null; then
    echo "ERROR: expected checksum mismatch rejection" >&2
    exit 1
  fi
fi

echo "PASS: all bootstrap, uninstaller, packager, and static security checks succeeded."
