#!/bin/bash
# Secure Desktop Stream macOS CLI bootstrapper (hardened native model + --from-source).
# No sudo required for --user, no automatic launch of streamed apps, no global Gatekeeper changes.
set -euo pipefail
umask 077

script_dir=$(cd "$(dirname "$0")" && pwd)
installer_root=$(cd "$script_dir/.." && pwd)

allow_unnotarized=0
auto_deps=0
dry_run=0
from_source=0
no_gui=0
scope=
release_base=
archive_path=
archive_sha256=

while [ "$#" -gt 0 ]; do
  case "$1" in
    --system|--user)
      requested=${1#--}
      [ -z "$scope" ] || [ "$scope" = "$requested" ] || { printf '%s\n' 'Choose either --system or --user.' >&2; exit 2; }
      scope=$requested
      shift ;;
    --scope)
      [ "$#" -ge 2 ] || { printf '%s\n' '--scope requires user or system.' >&2; exit 2; }
      case "$2" in user|system) scope=$2 ;; *) printf '%s\n' 'Invalid --scope (use user or system).' >&2; exit 2 ;; esac
      shift 2 ;;
    --scope=*)
      val=${1#--scope=}
      case "$val" in user|system) scope=$val ;; *) printf '%s\n' 'Invalid --scope (use user or system).' >&2; exit 2 ;; esac
      shift ;;
    --allow-unnotarized) allow_unnotarized=1; shift ;;
    --auto-deps) auto_deps=1; shift ;;
    --dry-run) dry_run=1; shift ;;
    --from-source) from_source=1; shift ;;
    --no-gui) no_gui=1; shift ;;
    --release-base)
      [ "$#" -ge 2 ] || exit 2
      release_base=$2; shift 2 ;;
    --release-base=*)
      release_base=${1#--release-base=}; shift ;;
    --archive)
      [ "$#" -ge 2 ] || exit 2
      archive_path=$2; shift 2 ;;
    --archive=*)
      archive_path=${1#--archive=}; shift ;;
    --sha256)
      [ "$#" -ge 2 ] || exit 2
      archive_sha256=$2; shift 2 ;;
    --sha256=*)
      archive_sha256=${1#--sha256=}; shift ;;
    --help|-h)
      printf '%s\n' \
        'Usage: bash install-macos.sh [--user|--system] [--from-source | --release-base=https://... | --archive=PATH --sha256=HEX] [--auto-deps] [--allow-unnotarized] [--no-gui] [--dry-run]' \
        'Installs Secure Desktop Stream Installer.app (ad-hoc or local signing config; never disables Gatekeeper globally).'
      exit 0 ;;
    *) printf 'Unknown option: %s\n' "$1" >&2; exit 2 ;;
  esac
done

[ "$(uname -s)" = Darwin ] || { printf '%s\n' 'This installer requires macOS.' >&2; exit 1; }
arch=$(uname -m)
case "$arch" in arm64|x86_64) ;; *) printf '%s\n' 'Unsupported macOS architecture.' >&2; exit 1 ;; esac

if [ "$from_source" = 0 ] && [ -z "$archive_path" ] && [ -z "$release_base" ]; then
  if [ -f "$installer_root/Cargo.toml" ]; then
    from_source=1
  else
    printf '%s\n' 'Specify --from-source, --archive + --sha256, or --release-base.' >&2
    exit 2
  fi
fi

if [ -n "$release_base" ]; then
  case "$release_base" in https://*) ;; *) printf '%s\n' '--release-base must start with https://' >&2; exit 2 ;; esac
fi

# Optional owner-only local signing configuration.
signing_identity=${SDS_CODESIGN_IDENTITY:-}
expected_requirement=${SDS_CODESIGN_DESIGNATED_REQUIREMENT:-}
signing_config=${SDS_CODESIGN_CONFIG:-$HOME/Library/Application Support/SecureDesktopStream/code-signing.json}

if [ -z "$signing_identity" ] && [ -z "$expected_requirement" ] &&
   [ -n "${SDS_CODESIGN_CONFIG:-}" ] && [ ! -e "$signing_config" ] && [ ! -L "$signing_config" ]; then
  printf '%s\n' 'SDS_CODESIGN_CONFIG does not name an existing file.' >&2; exit 1
fi

if [ -n "$signing_identity" ] || [ -n "$expected_requirement" ]; then
  [ -n "$signing_identity" ] && [ -n "$expected_requirement" ] || {
    printf '%s\n' 'Set both SDS_CODESIGN_IDENTITY and SDS_CODESIGN_DESIGNATED_REQUIREMENT.' >&2; exit 1
  }
elif [ -e "$signing_config" ] || [ -L "$signing_config" ]; then
  [ -f "$signing_config" ] && [ ! -L "$signing_config" ] || { printf '%s\n' 'Signing config must be a regular file, not a symlink.' >&2; exit 1; }
  [ "$(/usr/bin/stat -f '%u' "$signing_config")" = "$(/usr/bin/id -u)" ] || { printf '%s\n' 'Signing config must be owned by current user.' >&2; exit 1; }
  config_mode=$(/usr/bin/stat -f '%Lp' "$signing_config")
  case $config_mode in *[!0-7]*|'') printf '%s\n' 'Cannot read signing config file mode.' >&2; exit 1 ;; esac
  [ $((8#$config_mode & 077)) -eq 0 ] || { printf '%s\n' 'Signing config must not grant group or other access.' >&2; exit 1; }
  /usr/bin/plutil -convert xml1 -o /dev/null "$signing_config" >/dev/null 2>&1 || {
    printf '%s\n' 'Signing config is not valid JSON or plist.' >&2; exit 1
  }
  signing_identity=$(/usr/bin/plutil -extract identity_sha1 raw -o - "$signing_config") || exit 1
  expected_requirement=$(/usr/bin/plutil -extract designated_requirement raw -o - "$signing_config") || exit 1
fi

if [ -n "$signing_identity" ]; then
  [[ $signing_identity =~ ^[[:xdigit:]]{40}$ ]] || { printf '%s\n' 'Code-signing identity must be 40-digit SHA-1.' >&2; exit 1; }
  case $expected_requirement in
    'identifier "local.secure-desktop-stream.Installer"'*) ;;
    *) printf '%s\n' 'Designated requirement must start with local.secure-desktop-stream.Installer.' >&2; exit 1 ;;
  esac
  /usr/bin/csreq -r "=$expected_requirement" -t >/dev/null || { printf '%s\n' 'Invalid designated requirement syntax.' >&2; exit 1; }
  identity_found=$(/usr/bin/security find-identity -v -p codesigning | /usr/bin/awk -v wanted="$signing_identity" 'toupper($2) == toupper(wanted) { found = 1 } END { print found + 0 }')
  [ "$identity_found" = 1 ] || { printf '%s\n' 'Configured signing identity is not valid in user Keychain.' >&2; exit 1; }
fi

app_name='Secure Desktop Stream Installer.app'
has_app() { [ -e "$1/$app_name" ] || [ -L "$1/$app_name" ]; }

if [ -z "$scope" ] && [ "$dry_run" != 1 ]; then
  if [ ! -t 0 ]; then
    scope=user
  else
    default=1
    if has_app /Applications && ! has_app "$HOME/Applications"; then default=2; fi
    printf '%s\n' 'Where should Secure Desktop Stream Installer be placed?' '  1) Only me: ~/Applications' '  2) All users: /Applications'
    while :; do
      printf 'Choose 1 or 2 [%s]: ' "$default"
      if ! IFS= read -r choice; then printf '\nInstallation cancelled.\n' >&2; exit 2; fi
      case "${choice:-$default}" in
        1) scope=user; break ;;
        2) scope=system; break ;;
        *) printf '%s\n' 'Enter 1 or 2.' ;;
      esac
    done
  fi
fi

if [ "${scope:-user}" = user ]; then
  destination="$HOME/Applications"
  other=/Applications
else
  destination=/Applications
  other="$HOME/Applications"
fi

if [ "$dry_run" != 1 ] && has_app "$other"; then
  printf 'Installer already exists at %s. Choose that scope or remove it first.\n' "$other" >&2
  exit 1
fi

work=$(mktemp -d "${TMPDIR:-/tmp}/sds-macos-install.XXXXXXXX")
staging=""
cleanup() {
  [ -z "$staging" ] || rm -rf "$staging"
  rm -rf "$work"
}
trap cleanup EXIT

bundle_id='local.secure-desktop-stream.Installer'
source_app=""

if [ "$from_source" = 1 ]; then
  [ -f "$installer_root/Cargo.toml" ] || { printf '%s\n' 'Missing installer/Cargo.toml for --from-source.' >&2; exit 1; }
  if ! command -v cargo >/dev/null 2>&1; then
    if [ "$auto_deps" = 1 ] && [ "$dry_run" != 1 ]; then
      if command -v brew >/dev/null 2>&1; then
        printf '%s\n' 'Installing Rust toolchain via Homebrew (--auto-deps)...'
        brew install rust
        brew_bin_dir=$(dirname "$(command -v brew)")
        export PATH="$brew_bin_dir:$HOME/.cargo/bin:$PATH"
      fi
    fi
    command -v cargo >/dev/null 2>&1 || {
      printf '%s\n' 'Rust cargo is required for --from-source. Install via Homebrew (brew install rust) or https://rustup.rs, or pass --auto-deps.' >&2
      exit 1
    }
  fi
  if ! /usr/bin/xcode-select -p >/dev/null 2>&1; then
    printf '%s\n' 'Xcode Command Line Tools are required. Run: xcode-select --install' >&2
    exit 1
  fi
  avail_mb=$(( $(df -k "$HOME" | awk 'NR==2 {print $4}') / 1024 ))
  [ "$avail_mb" -ge 1024 ] || { printf 'Need at least 1024 MB free disk (have %s MB).\n' "$avail_mb" >&2; exit 1; }

  if [ "$dry_run" = 1 ]; then
    printf 'Dry run: would build %s with cargo build --release --locked and install to %s/%s\n' "$installer_root" "$destination" "$app_name"
    exit 0
  fi

  printf '%s\n' 'Building sds-installer from source (release, --locked)...'
  cargo build --manifest-path "$installer_root/Cargo.toml" --release --locked
  built_bin="$installer_root/target/release/sds-installer"
  [ -x "$built_bin" ] || { printf '%s\n' 'Built sds-installer binary missing.' >&2; exit 1; }

  source_app="$work/$app_name"
  mkdir -p "$source_app/Contents/MacOS" "$source_app/Contents/Resources"
  cp "$built_bin" "$source_app/Contents/MacOS/sds-installer"
  chmod 755 "$source_app/Contents/MacOS/sds-installer"
  version=$("$built_bin" --version | awk '{print $2; exit}')
  version=${version:-0.1.0}
  cat > "$source_app/Contents/Info.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleIdentifier</key>
  <string>${bundle_id}</string>
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
  printf 'APPL????' > "$source_app/Contents/PkgInfo"
  /usr/bin/codesign --force --options runtime -s "${signing_identity:--}" "$source_app"
else
  fetch() { /usr/bin/curl --fail --show-error --silent --location --proto '=https' --proto-redir '=https' --tlsv1.2 "$1" -o "$2"; }
  if [ -n "$archive_path" ]; then
    [ -n "$archive_sha256" ] || { printf '%s\n' '--sha256 is required with --archive.' >&2; exit 2; }
    [ -f "$archive_path" ] && [ ! -L "$archive_path" ] || { printf '%s\n' 'Archive must be an existing regular file.' >&2; exit 1; }
    expected=$(printf '%s' "$archive_sha256" | /usr/bin/tr '[:upper:]' '[:lower:]')
    case "$expected" in *[!a-f0-9]*|'') printf '%s\n' 'Invalid SHA-256 hex.' >&2; exit 1 ;; esac
    [ "${#expected}" = 64 ] || { printf '%s\n' 'SHA-256 must be 64 hex chars.' >&2; exit 1; }
    cp "$archive_path" "$work/app.zip"
  else
    if ! fetch "${release_base%/}/latest.json" "$work/latest.json"; then
      printf '%s\n' \
        "Failed to fetch release manifest from ${release_base%/}/latest.json." \
        'If prebuilt releases are not published yet, clone the repository and build from source:' \
        '  git clone --recursive https://github.com/dst0/secure-desktop-stream.git && cd secure-desktop-stream' \
        '  bash installer/bootstrap/get.sh --from-source --auto-deps' >&2
      exit 1
    fi
    field() { /usr/bin/plutil -extract "$1" raw -o - "$work/latest.json"; }
    file=$(field "builds.$arch.file") || { printf 'No release build for %s.\n' "$arch" >&2; exit 1; }
    case "$file" in sds-installer-*-macos-"$arch".zip) ;; *) printf '%s\n' 'Invalid release filename.' >&2; exit 1 ;; esac
    case "$file" in *[!a-zA-Z0-9._-]*) printf '%s\n' 'Unsafe release filename.' >&2; exit 1 ;; esac
    expected=$(field "builds.$arch.sha256")
    case "$expected" in *[!a-f0-9]*|'') printf '%s\n' 'Invalid checksum in manifest.' >&2; exit 1 ;; esac
    [ "${#expected}" = 64 ] || exit 1
    printf 'Downloading %s...\n' "$file"
    fetch "${release_base%/}/$file" "$work/app.zip"
  fi

  actual=$(/usr/bin/shasum -a 256 "$work/app.zip")
  [ "${actual%% *}" = "$expected" ] || { printf '%s\n' 'Archive SHA-256 mismatch. Nothing installed.' >&2; exit 1; }
  /usr/bin/ditto -x -k "$work/app.zip" "$work/unpacked"
  source_app="$work/unpacked/$app_name"
  [ -d "$source_app" ] && [ ! -L "$source_app" ] || { printf '%s\n' 'Missing installer app bundle inside archive.' >&2; exit 1; }
  identity=$(/usr/bin/plutil -extract CFBundleIdentifier raw -o - "$source_app/Contents/Info.plist")
  [ "$identity" = "$bundle_id" ] || { printf 'Unexpected CFBundleIdentifier: %s\n' "$identity" >&2; exit 1; }
  /usr/bin/codesign --verify --deep --strict "$source_app"
  [ -x "$source_app/Contents/MacOS/sds-installer" ] || { printf '%s\n' 'Missing sds-installer executable in bundle.' >&2; exit 1; }
  version=$(/usr/bin/plutil -extract CFBundleShortVersionString raw -o - "$source_app/Contents/Info.plist")
  printf 'Verified Secure Desktop Stream Installer %s (%s).\n' "$version" "$arch"
  if [ "$dry_run" = 1 ]; then
    printf '%s\n' 'Dry run complete. Nothing installed or launched.'
    exit 0
  fi
fi

if /usr/bin/pgrep -x sds-installer >/dev/null; then
  printf '%s\n' 'Quit running sds-installer before installing an update.' >&2
  exit 1
fi

[ "$scope" != user ] || mkdir -p "$destination"
[ -d "$destination" ] && [ -w "$destination" ] || {
  printf '%s\n' "$destination must be writable by your account." >&2
  exit 1
}

target="$destination/$app_name"
[ ! -L "$target" ] || { printf '%s\n' 'Refusing to replace symlink target.' >&2; exit 1; }

staging=$(mktemp -d "$destination/.sds-installer-stage.XXXXXXXX")
backup=
/usr/bin/ditto "$source_app" "$staging/$app_name"

if [ -n "$signing_identity" ]; then
  /usr/bin/codesign --force --deep --options runtime --sign "$signing_identity" "$staging/$app_name"
  /usr/bin/codesign --verify --deep --strict "$staging/$app_name"
  actual_req=$(/usr/bin/codesign --display --requirements - "$staging/$app_name" 2>&1 | /usr/bin/sed -n 's/^designated => //p')
  [ "$actual_req" = "$expected_requirement" ] || { printf '%s\n' 'Designated requirement mismatch after re-signing.' >&2; exit 1; }
fi
/usr/bin/codesign --verify --deep --strict "$staging/$app_name"

if [ "$allow_unnotarized" = 1 ]; then
  /usr/bin/xattr -dr com.apple.quarantine "$staging/$app_name"
fi

if [ -e "$target" ]; then
  existing_id=$(/usr/bin/plutil -extract CFBundleIdentifier raw -o - "$target/Contents/Info.plist")
  [ "$existing_id" = "$bundle_id" ] || { printf '%s\n' 'Destination contains a different app.' >&2; exit 1; }
  backup="$destination/Secure Desktop Stream Installer.previous.$(date +%Y%m%d%H%M%S).$$.app"
  mv "$target" "$backup"
fi

if ! mv "$staging/$app_name" "$target"; then
  if [ -n "$backup" ] && [ -e "$backup" ]; then mv "$backup" "$target"; fi
  exit 1
fi

mkdir -p "$HOME/.local/bin"
ln -sf "$target/Contents/MacOS/sds-installer" "$HOME/.local/bin/sds-installer"
printf 'Installed: %s\nCLI symlink: %s/.local/bin/sds-installer\n' "$target" "$HOME"
if [ -n "$backup" ]; then printf 'Previous bundle preserved: %s\n' "$backup"; fi

if [ "$no_gui" = 0 ]; then
  exec "$target/Contents/MacOS/sds-installer" gui
fi
