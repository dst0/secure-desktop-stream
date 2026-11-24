#!/usr/bin/env bash
# Download the MSYS2 UCRT64 packages listed in packages.lock, verify each against the SHA-256
# recorded from the signature-verified repository database, and extract them into <dest>.
# The ucrt64/ prefix inside each package is stripped, so <dest> mirrors MSYS2's /ucrt64.
#
# Usage: fetch-msys2.sh <packages.lock> <dest> [cache-dir]
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
LOCK=${1:?packages.lock}; DEST=${2:?dest}; CACHE=${3:-/tmp/msys2-cache}
MIRROR=${MSYS2_MIRROR:-https://repo.msys2.org/mingw/ucrt64}
[[ $MIRROR == https://* ]] || { echo "MSYS2_MIRROR must start with https://" >&2; exit 1; }
mkdir -p "$CACHE" "$DEST"
while read -r file sha; do
  case $file in ''|'#'*) continue ;; esac
  [[ $file =~ ^[A-Za-z0-9_.+~-]+$ && $file != "." && $file != ".." ]] || {
    echo "invalid package filename in lock: $file" >&2
    exit 1
  }
  [[ $sha =~ ^[0-9a-f]{64}$ ]] || {
    echo "invalid sha256 in lock for $file: $sha" >&2
    exit 1
  }
  pkg="$CACHE/$file"
  [ ! -L "$pkg" ] || { echo "refusing symlinked cache file: $pkg" >&2; exit 1; }
  if ! { [ -f "$pkg" ] && [ ! -L "$pkg" ] && printf '%s  %s\n' "$sha" "$pkg" | sha256sum -c --quiet - >/dev/null 2>&1; }; then
    rm -f -- "$pkg.part"
    curl -fsSL --proto =https --tlsv1.2 --retry 3 -o "$pkg.part" "$MIRROR/$file"
    if ! printf '%s  %s\n' "$sha" "$pkg.part" | sha256sum -c --quiet -; then
      rm -f -- "$pkg.part"
      exit 1
    fi
    mv -f -- "$pkg.part" "$pkg"
  fi
  [ -f "$pkg" ] && [ ! -L "$pkg" ] || { echo "missing regular cache file: $pkg" >&2; exit 1; }
  printf '%s  %s\n' "$sha" "$pkg" | sha256sum -c --quiet -
  python3 -I "$HERE/extract-msys2.py" "$pkg" "$DEST"
  echo "extracted $file"
done < "$LOCK"
