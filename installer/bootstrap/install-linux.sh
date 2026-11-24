#!/bin/sh
# Secure Desktop Stream Linux POSIX sh bootstrapper (hardened native model + --from-source).
# Requires sh, curl, unzip, coreutils; zero Python or jq needed for release verification.
set -eu
umask 077

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
installer_root=$(CDPATH= cd -- "$script_dir/.." && pwd)

dry_run=0
auto_deps=0
from_source=0
no_gui=0
release_base=
archive_path=
archive_sha256=

while [ "$#" -gt 0 ]; do
  case "$1" in
    --dry-run) dry_run=1; shift ;;
    --auto-deps) auto_deps=1; shift ;;
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
    --allow-unnotarized|--user|--system) shift ;;
    --scope=*) shift ;;
    --scope) [ "$#" -ge 2 ] && shift 2 || exit 2 ;;
    --help|-h)
      printf '%s\n' \
        'Usage: sh install-linux.sh [--from-source | --release-base=https://... | --archive=PATH --sha256=HEX] [--auto-deps] [--no-gui] [--dry-run]'
      exit 0 ;;
    *) printf 'Unknown argument: %s\n' "$1" >&2; exit 2 ;;
  esac
done

fail() { printf '%s\n' "$*" >&2; exit 1; }

[ "$(uname -s)" = Linux ] || fail 'This installer supports Linux only'
arch=$(uname -m)
case "$arch" in
  x86_64) elf_machine=3e00 ;;
  aarch64) elf_machine=b700 ;;
  *) fail "Unsupported Linux architecture: $arch" ;;
esac

if [ "$from_source" = 0 ] && [ -z "$archive_path" ] && [ -z "$release_base" ]; then
  if [ -f "$installer_root/Cargo.toml" ]; then
    from_source=1
  else
    fail 'Specify --from-source, --archive + --sha256, or --release-base'
  fi
fi

for tool in mktemp timeout od readlink; do
  command -v "$tool" >/dev/null 2>&1 || fail "Required tool missing: $tool"
done

work=$(mktemp -d)
stage=
backup=
target=
installed=0
cleanup() {
  if [ "$installed" = 0 ] && [ -n "$backup" ] && [ -d "$backup" ] && [ ! -e "$target" ]; then
    mv "$backup" "$target"
  fi
  [ -z "$stage" ] || rm -rf "$stage"
  rm -rf "$work"
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM

mkdir -p "$work/app"

if [ "$from_source" = 1 ]; then
  [ -f "$installer_root/Cargo.toml" ] || fail 'Missing installer/Cargo.toml for --from-source'
  if [ "$dry_run" = 1 ]; then
    if ! command -v cargo >/dev/null 2>&1; then
      printf 'Dry run: would require cargo/rustc + X11/fontconfig/cmake dev packages and build %s\n' "$installer_root"
    else
      printf 'Dry run: would build %s with cargo build --release --locked\n' "$installer_root"
    fi
    exit 0
  fi
  if [ "$auto_deps" = 1 ]; then
    if command -v apt-get >/dev/null 2>&1; then
      sudo apt-get update && sudo apt-get install -y --no-install-recommends \
        build-essential pkg-config clang cmake cargo rustc \
        libx11-dev libxcursor-dev libxrandr-dev libxi-dev \
        libxkbcommon-dev libxkbcommon-x11-dev libwayland-dev libfontconfig1-dev \
        libxcb1-dev libxcb-render0-dev libxcb-shape0-dev libxcb-xfixes0-dev curl unzip
    elif command -v dnf >/dev/null 2>&1; then
      sudo dnf install -y gcc gcc-c++ clang cmake pkgconf-pkg-config cargo rust \
        libX11-devel libXcursor-devel libXrandr-devel libXi-devel \
        libxkbcommon-devel libxkbcommon-x11-devel wayland-devel fontconfig-devel \
        libxcb-devel curl unzip
    elif command -v pacman >/dev/null 2>&1; then
      sudo pacman -S --needed --noconfirm base-devel clang cmake pkgconf rust \
        libx11 libxcursor libxrandr libxi \
        libxkbcommon libxkbcommon-x11 wayland fontconfig libxcb curl unzip
    elif command -v zypper >/dev/null 2>&1; then
      sudo zypper --non-interactive install -y gcc gcc-c++ clang cmake pkg-config cargo rust \
        libX11-devel libXcursor-devel libXrandr-devel libXi-devel \
        libxkbcommon-devel libxkbcommon-x11-devel wayland-devel fontconfig-devel \
        libxcb-devel curl unzip
    fi
  fi
  command -v cargo >/dev/null 2>&1 || fail 'Rust cargo is required for --from-source (install via rustup or pass --auto-deps)'
  printf '%s\n' 'Building sds-installer from source (release, --locked)...'
  cargo build --manifest-path "$installer_root/Cargo.toml" --release --locked
  cp "$installer_root/target/release/sds-installer" "$work/app/sds-installer"
  chmod 755 "$work/app/sds-installer"
  ver=$("$work/app/sds-installer" --version | awk '{print $2; exit}')
  printf '{"identity":"local.secure-desktop-stream.Installer","platform":"linux","arch":"%s","version":"%s"}\n' "$arch" "${ver:-0.1.0}" > "$work/app/release.json"
else
  for tool in curl unzip sha256sum; do
    command -v "$tool" >/dev/null 2>&1 || fail "Required tool missing: $tool"
  done
  if [ -n "$archive_path" ]; then
    [ -n "$archive_sha256" ] || fail '--sha256 is required with --archive'
    [ -f "$archive_path" ] && [ ! -L "$archive_path" ] || fail 'Archive must be a regular file'
    digest=$(printf '%s' "$archive_sha256" | tr '[:upper:]' '[:lower:]')
    printf '%s\n' "$digest" | LC_ALL=C grep -Eq '^[a-f0-9]{64}$' || fail 'Invalid SHA-256 hex'
    cp "$archive_path" "$work/download.zip"
    bytes=$(wc -c < "$work/download.zip")
  else
    case "$release_base" in https://*) ;; *) fail '--release-base must start with https://' ;; esac
    if ! curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' --tlsv1.2 \
      --connect-timeout 10 --max-time 120 "${release_base%/}/linux-latest.txt" -o "$work/manifest"; then
      printf '%s\n' \
        "Failed to fetch release manifest from ${release_base%/}/linux-latest.txt." \
        'If prebuilt releases are not published yet, clone the repository and build from source:' \
        '  git clone --recursive https://github.com/dst0/secure-desktop-stream.git && cd secure-desktop-stream' \
        '  bash installer/bootstrap/get.sh --from-source --auto-deps' >&2
      exit 1
    fi
    [ "$(wc -c < "$work/manifest")" -le 1024 ] || fail 'Invalid release manifest'
    [ "$(wc -l < "$work/manifest")" -eq 6 ] || fail 'Invalid release manifest'
    field() { awk -F= -v key="$1" '$1 == key { if (NF != 2 || seen++) exit 1; value=$2 } END { if (seen != 1) exit 1; print value }' "$work/manifest"; }
    [ "$(field format)" = 1 ] || fail 'Invalid release format'
    version=$(field version); revision=$(field revision); file=$(field file); digest=$(field sha256); bytes=$(field bytes)
    printf '%s\n' "$version" | LC_ALL=C grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z.]+)?$' || fail 'Invalid version'
    printf '%s\n' "$revision" | LC_ALL=C grep -Eq '^[a-f0-9]{40}$' || fail 'Invalid revision'
    printf '%s\n' "$digest" | LC_ALL=C grep -Eq '^[a-f0-9]{64}$' || fail 'Invalid checksum'
    printf '%s\n' "$bytes" | LC_ALL=C grep -Eq '^[0-9]{1,9}$' || fail 'Invalid archive size'
    [ "$bytes" -gt 0 ] && [ "$bytes" -le 268435456 ] || fail 'Invalid archive size'
    [ "$file" = "sds-installer-$version-linux-$arch.zip" ] || fail 'Invalid archive filename'
    printf 'Downloading %s\n' "$file"
    curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' --tlsv1.2 \
      --connect-timeout 10 --max-time 120 "${release_base%/}/$file" -o "$work/download.zip"
    [ "$(wc -c < "$work/download.zip")" -eq "$bytes" ] || fail 'Archive size mismatch'
  fi

  printf '%s  %s\n' "$digest" "$work/download.zip" | sha256sum -c - >/dev/null || fail 'Archive checksum mismatch'
  unzip -Z -1 "$work/download.zip" | LC_ALL=C sort > "$work/members"
  awk 'NR > 1000 || seen[$0]++ || /(^|\/)\.\.?($|\/)/ || /^\// || /\\/ { exit 1 }' "$work/members" || fail 'Unsafe or duplicate archive member'
  grep -Fqx 'sds-installer' "$work/members" || fail 'Missing sds-installer in archive'
  grep -Fqx 'release.json' "$work/members" || fail 'Missing release.json in archive'
  unzip -Z -l "$work/download.zip" > "$work/listing"
  awk '$1 ~ /^[bclps]/ { exit 1 } $1 ~ /^[-d]/ { total += $4; if ($4 > 268435456 || total > 268435456) exit 1 }' "$work/listing" || fail 'Unsafe archive member size/type'

  unzip -q "$work/download.zip" -d "$work/app"
  find "$work/app" -type l | grep . >/dev/null && fail 'Archive symlinks are not allowed'

  header=$(od -An -tx1 -N20 "$work/app/sds-installer" | tr -d '[:space:]')
  case "$header" in
    7f454c460201????????????????????????"$elf_machine") ;;
    *) fail "Expected Linux $arch ELF executable" ;;
  esac
  chmod 755 "$work/app/sds-installer"
  case "$(timeout 15 "$work/app/sds-installer" --version 2>/dev/null || :)" in
    "sds-installer "*) ;;
    *) fail 'Executable --version check failed' ;;
  esac
  if [ "$dry_run" = 1 ]; then
    printf '%s\n' 'Dry run complete; nothing installed or launched'
    exit 0
  fi
fi

destination=$HOME/.local/share/sds-installer
target=$destination/app
launcher=$HOME/.local/bin/sds-installer
desktop=$HOME/.local/share/applications/sds-installer.desktop

[ ! -L "$destination" ] && [ ! -L "$target" ] || fail 'Refusing symlink installation destination'
if [ -e "$launcher" ] || [ -L "$launcher" ]; then
  [ -L "$launcher" ] && [ "$(readlink "$launcher")" = "$target/sds-installer" ] || fail 'Existing sds-installer command preserved; nothing installed'
fi
[ ! -L "$desktop" ] || fail 'Existing desktop entry is a symlink; refusing to overwrite'

if [ -e "$target" ]; then
  for process in /proc/[0-9]*/exe; do
    proc_exe=$(readlink "$process" 2>/dev/null || :)
    [ "$proc_exe" != "$target/sds-installer" ] || fail 'Quit sds-installer before updating'
    proc_dir=${process%/exe}
    proc_arg=$(awk 'BEGIN { RS="\0" } NR == 1 { printf "%s", $0; exit }' "$proc_dir/cmdline" 2>/dev/null || :)
    case $proc_arg in
      /*) proc_arg=$(readlink -f -- "$proc_arg" 2>/dev/null || :) ;;
      '') ;;
      *) proc_arg=$(readlink -f -- "$proc_dir/cwd/$proc_arg" 2>/dev/null || :) ;;
    esac
    [ "$proc_arg" != "$target/sds-installer" ] || fail 'Quit sds-installer before updating'
  done
fi

mkdir -p "$destination" "$HOME/.local/bin" "$HOME/.local/share/applications"
stage=$(mktemp -d "$destination/.install-XXXXXX")
cp -R "$work/app" "$stage/app"
executable=$(printf '%s' "$target/sds-installer" | sed 's/\\/\\\\/g; s/"/\\"/g; s/`/\\`/g; s/\$/\\$/g; s/%/%%/g')
printf '[Desktop Entry]\nType=Application\nName=Secure Desktop Stream Installer\nExec="%s" gui\nTerminal=false\nCategories=System;Utility;\n' "$executable" > "$stage/sds-installer.desktop"

if [ -e "$target" ]; then
  backup=$destination/previous-$(date +%s)-$$
  [ ! -e "$backup" ] || fail 'Backup destination already exists'
  mv "$target" "$backup"
fi
mv "$stage/app" "$target"
ln -s "$target/sds-installer" "$stage/launcher"
mv -f "$stage/launcher" "$launcher"
mv -f "$stage/sds-installer.desktop" "$desktop"
installed=1

printf 'Installed: %s\nLauncher: %s\n' "$target" "$launcher"

if [ "$no_gui" = 0 ]; then
  if [ -n "${SSH_CONNECTION:-}" ] || { [ -z "${DISPLAY:-}" ] && [ -z "${WAYLAND_DISPLAY:-}" ]; }; then
    if [ -t 0 ]; then
      exec "$target/sds-installer" tui
    else
      printf 'Headless session without TTY: run "%s tui" interactively or use CLI subcommands.\n' "$launcher"
    fi
  else
    exec "$target/sds-installer" gui
  fi
fi
