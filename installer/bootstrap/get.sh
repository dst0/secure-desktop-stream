#!/bin/bash
# Secure Desktop Stream universal CLI bootstrapper (macOS & Linux).
# Supports verified release archives and building directly from source (unsigned/ad-hoc).
set -euo pipefail
umask 077

script_dir=$(cd "$(dirname "$0")" && pwd)
release_base=""
from_source=0
forward_args=()

for arg in "$@"; do
  case "$arg" in
    --from-source)
      from_source=1
      forward_args+=("$arg")
      ;;
    --release-base=*)
      release_base=${arg#--release-base=}
      forward_args+=("$arg")
      ;;
    --help|-h)
      printf '%s\n' \
        'Usage: bash get.sh [--from-source | --release-base=https://... | --archive=PATH --sha256=HEX] [--auto-deps] [--scope user|system] [--allow-unnotarized] [--no-gui] [--dry-run]' \
        'Installs or builds sds-installer and launches its pure native GUI (or TUI over SSH/headless TTY).' \
        'No paid Apple/Microsoft code-signing certs required; Gatekeeper stays enabled unless --allow-unnotarized opts in for this app only.'
      exit 0
      ;;
    *)
      forward_args+=("$arg")
      ;;
  esac
done

case "$(uname -s)" in
  Darwin) target_script=install-macos.sh ;;
  Linux) target_script=install-linux.sh ;;
  *)
    printf '%s\n' 'Unsupported OS for get.sh. On Windows run bootstrap/install-windows.ps1.' >&2
    exit 1
    ;;
esac

# Default to --from-source automatically when invoked inside a checkout without --release-base or --archive.
if [ "$from_source" = 0 ] && [ -z "$release_base" ]; then
  has_archive=0
  for a in "${forward_args[@]+"${forward_args[@]}"}"; do
    case "$a" in --archive|--archive=*) has_archive=1 ;; esac
  done
  if [ "$has_archive" = 0 ] && [ -f "$script_dir/../Cargo.toml" ]; then
    forward_args+=(--from-source)
  fi
fi

if [ -f "$script_dir/$target_script" ]; then
  if [ "$target_script" = install-macos.sh ]; then
    exec bash "$script_dir/$target_script" "${forward_args[@]+"${forward_args[@]}"}"
  else
    exec /bin/sh "$script_dir/$target_script" "${forward_args[@]+"${forward_args[@]}"}"
  fi
fi

[ -n "$release_base" ] || {
  printf '%s\n' 'Provide --release-base=https://... when running get.sh outside the repository checkout.' >&2
  exit 2
}
case "$release_base" in
  https://*) ;;
  *) printf '%s\n' '--release-base must start with https://' >&2; exit 2 ;;
esac

work=$(mktemp -d "${TMPDIR:-/tmp}/sds-bootstrap.XXXXXXXX")
trap 'rm -rf "$work"' EXIT
if ! curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' --tlsv1.2 \
  --connect-timeout 10 --max-time 60 "${release_base%/}/$target_script" -o "$work/$target_script"; then
  printf '%s\n' \
    "Failed to download bootstrap script from ${release_base%/}/$target_script." \
    'If prebuilt releases are not published yet, clone the repository and build from source:' \
    '  git clone --recursive https://github.com/dst0/secure-desktop-stream.git && cd secure-desktop-stream' \
    '  bash installer/bootstrap/get.sh --from-source --auto-deps' >&2
  exit 1
fi

if [ "$target_script" = install-macos.sh ]; then
  bash "$work/$target_script" "${forward_args[@]+"${forward_args[@]}"}"
else
  /bin/sh "$work/$target_script" "${forward_args[@]+"${forward_args[@]}"}"
fi
