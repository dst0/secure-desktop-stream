#!/usr/bin/env bash
# Build isolated microphone tests with fake capture; never requests microphone access.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
SRC=$(cd "${1:?usage: $0 <moonlight-qt-worktree>}" && pwd)
OUT="$ROOT/build/$(basename "$SRC")/tests-mic"
if [[ "${SDS_MIC_BUILD_PHASE:-}" != 1 ]]; then
    mkdir -p "$ROOT/build"
    env SDS_MIC_BUILD_PHASE=1 /usr/bin/lockf -k "$ROOT/build/.mac-build.lock" "$0" "$SRC"
    cd "$OUT"
    exec ./moonlight-mic-tests
fi
avail_mb=$(( $(df -k "$ROOT" | awk 'NR==2 {print $4}') / 1024 ))
(( avail_mb >= 2048 )) || { echo "Insufficient build space" >&2; exit 3; }
"$ROOT/tools/ensure-mac-deps.sh" "$SRC"
OPENSSL_PKGCONFIG="/opt/homebrew/opt/openssl/lib/pkgconfig"
if [[ ! -d "$OPENSSL_PKGCONFIG" && -d "/usr/local/opt/openssl/lib/pkgconfig" ]]; then
    OPENSSL_PKGCONFIG="/usr/local/opt/openssl/lib/pkgconfig"
fi
export PKG_CONFIG_PATH="${OPENSSL_PKGCONFIG}${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}"
mkdir -p "$OUT"
cd "$OUT"
"${QMAKE:-/opt/homebrew/bin/qmake6}" "$SRC/tests/mic/mic.pro" CONFIG+=release
make -j"${MAKE_JOBS:-3}"
