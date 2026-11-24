#!/usr/bin/env bash
# Deterministic release packager for sds-installer (produces verified archive + release manifests).
set -euo pipefail
umask 077

script_dir=$(cd "$(dirname "$0")" && pwd)
installer_root=$(cd "$script_dir/.." && pwd)
out_dir=""
bin_arg=""
version_arg=""

while [ "$#" -gt 0 ]; do
  case "$1" in
    --out)
      [ "$#" -ge 2 ] || { printf '%s\n' '--out requires a directory path' >&2; exit 2; }
      out_dir=$2; shift 2 ;;
    --out=*)
      out_dir=${1#--out=}; shift ;;
    --binary)
      [ "$#" -ge 2 ] || { printf '%s\n' '--binary requires a file path' >&2; exit 2; }
      bin_arg=$2; shift 2 ;;
    --binary=*)
      bin_arg=${1#--binary=}; shift ;;
    --version)
      [ "$#" -ge 2 ] || { printf '%s\n' '--version requires a value' >&2; exit 2; }
      version_arg=$2; shift 2 ;;
    --version=*)
      version_arg=${1#--version=}; shift ;;
    --help|-h)
      printf '%s\n' 'Usage: bash package-release.sh [--out DIR] [--binary PATH] [--version VER] [OUT_DIR]'
      exit 0 ;;
    -*)
      printf 'Unknown option: %s\n' "$1" >&2; exit 2 ;;
    *)
      if [ -z "$out_dir" ]; then
        out_dir=$1; shift
      else
        printf 'Unexpected positional argument: %s\n' "$1" >&2; exit 2
      fi ;;
  esac
done

out_dir=${out_dir:-"$installer_root/dist"}

os_raw=$(uname -s)
arch_raw=$(uname -m)
case "$os_raw" in
  Darwin) platform=macos ;;
  Linux) platform=linux ;;
  *) printf 'Unsupported host OS for packager: %s\n' "$os_raw" >&2; exit 1 ;;
esac
case "$arch_raw" in
  arm64|aarch64) arch=$arch_raw ;;
  x86_64) arch=x86_64 ;;
  *) printf 'Unsupported arch: %s\n' "$arch_raw" >&2; exit 1 ;;
esac

if [ -n "$bin_arg" ]; then
  bin=$bin_arg
else
  cargo build --manifest-path "$installer_root/Cargo.toml" --release --locked
  bin="$installer_root/target/release/sds-installer"
fi
[ -x "$bin" ] || { printf 'sds-installer binary missing or not executable: %s\n' "$bin" >&2; exit 1; }

if [ -n "$version_arg" ]; then
  version=$version_arg
else
  version=$("$bin" --version | awk '{print $2; exit}')
  version=${version:-0.1.0}
fi
revision=$(git -C "$installer_root/.." rev-parse HEAD 2>/dev/null || printf '%040d' 0)

mkdir -p -- "$out_dir"
work=$(mktemp -d "${TMPDIR:-/tmp}/sds-package.XXXXXXXX")
trap 'rm -rf "$work"' EXIT

if [ "$platform" = macos ]; then
  app_name="Secure Desktop Stream Installer.app"
  app="$work/$app_name"
  mkdir -p "$app/Contents/MacOS" "$app/Contents/Resources"
  cp "$bin" "$app/Contents/MacOS/sds-installer"
  chmod 755 "$app/Contents/MacOS/sds-installer"
  cat > "$app/Contents/Info.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleIdentifier</key>
  <string>local.secure-desktop-stream.Installer</string>
  <key>CFBundleName</key>
  <string>Secure Desktop Stream Installer</string>
  <key>CFBundleExecutable</key>
  <string>sds-installer</string>
  <key>CFBundlePackageType</key>
  <string>APPL</string>
  <key>CFBundleShortVersionString</key>
  <string>${version}</string>
  <key>CFBundleVersion</key>
  <string>${version}</string>
  <key>NSHighResolutionCapable</key>
  <true/>
</dict>
</plist>
EOF
  printf 'APPL????' > "$app/Contents/PkgInfo"
  printf '{"identity":"local.secure-desktop-stream.Installer","platform":"macos","arch":"%s","revision":"%s","version":"%s"}\n' \
    "$arch" "$revision" "$version" > "$app/Contents/Resources/release.json"
  sign_id=${MAC_CODESIGN_IDENTITY:--}
  /usr/bin/codesign --force --options runtime -s "$sign_id" "$app"
  /usr/bin/codesign --verify --deep --strict "$app"

  archive_name="sds-installer-${version}-macos-${arch}.zip"
  archive_path="$out_dir/$archive_name"
  rm -f "$archive_path"
  /usr/bin/ditto -c -k --sequesterRsrc --keepParent "$app" "$archive_path"

  sha256=$(/usr/bin/shasum -a 256 "$archive_path" | awk '{print $1}')
  bytes=$(/usr/bin/stat -f '%z' "$archive_path")
  cat > "$out_dir/latest.json" <<EOF
{
  "format": 1,
  "version": "${version}",
  "revision": "${revision}",
  "builds": {
    "${arch}": {
      "file": "${archive_name}",
      "sha256": "${sha256}",
      "bytes": ${bytes}
    }
  }
}
EOF
else
  stage="$work/stage"
  mkdir -p "$stage"
  cp "$bin" "$stage/sds-installer"
  chmod 755 "$stage/sds-installer"
  printf '{"arch":"%s","identity":"local.secure-desktop-stream.Installer","platform":"linux","revision":"%s","version":"%s"}\n' \
    "$arch" "$revision" "$version" > "$stage/release.json"
  archive_name="sds-installer-${version}-linux-${arch}.zip"
  archive_path="$out_dir/$archive_name"
  rm -f "$archive_path"
  (cd "$stage" && zip -q "$archive_path" sds-installer release.json)
  sha256=$(sha256sum "$archive_path" | awk '{print $1}')
  bytes=$(stat -c '%s' "$archive_path")
  cat > "$out_dir/linux-latest.txt" <<EOF
format=1
version=${version}
revision=${revision}
file=${archive_name}
sha256=${sha256}
bytes=${bytes}
EOF
fi

"$bin" verify-archive --archive "$archive_path" --sha256 "$sha256" --platform "$platform"
printf '%s  %s\n' "$sha256" "$archive_name" > "$out_dir/SHA256SUMS"
printf 'Packaged %s (sha256=%s, bytes=%s)\n' "$archive_path" "$sha256" "$bytes"
