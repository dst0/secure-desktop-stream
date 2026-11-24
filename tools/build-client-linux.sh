#!/usr/bin/env bash
# Build a moonlight-qt checkout on Linux with Qt 6 (qmake6), stage the binary and
# desktop metadata into build/<worktree-name>/app/, and verify dynamic runtime linkage.
#
# Usage: tools/build-client-linux.sh <moonlight-qt-dir> [--clean]
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
if [[ -z "${SDS_LINUX_BUILD_LOCKED:-}" ]]; then
    mkdir -p "$ROOT/build"
    if command -v flock >/dev/null 2>&1; then
        exec env SDS_LINUX_BUILD_LOCKED=1 flock "$ROOT/build/.linux-client-build.lock" "$0" "$@"
    fi
fi

SRC=${1:?usage: $0 <moonlight-qt-dir> [--clean]}
SRC=$(cd "$SRC" && pwd)
NAME=$(basename "$SRC")
OUT="$ROOT/build/$NAME"
JOBS=${MAKE_JOBS:-$(nproc 2>/dev/null || echo 4)}
MIN_FREE_MB=2048

QMAKE=${QMAKE:-$(command -v qmake6 || command -v qmake-qt6 || true)}
if [[ -z "$QMAKE" && -x /usr/lib/qt6/bin/qmake ]]; then
    QMAKE=/usr/lib/qt6/bin/qmake
elif [[ -z "$QMAKE" && -x /usr/lib64/qt6/bin/qmake ]]; then
    QMAKE=/usr/lib64/qt6/bin/qmake
fi
[[ -n "$QMAKE" && -x "$QMAKE" ]] || {
    echo "error: qmake6 not found (run 'sds-installer deps install --role client-build --execute-sudo')" >&2
    exit 2
}

for cmd in make pkg-config; do
    command -v "$cmd" >/dev/null 2>&1 || {
        echo "error: required build tool '$cmd' is missing" >&2
        exit 2
    }
done

df_target="$OUT"
[[ -d "$df_target" ]] || df_target="$ROOT"
avail_mb=$(( $(df -k "$df_target" | awk 'NR==2 {print $4}') / 1024 ))
if (( avail_mb < MIN_FREE_MB )); then
    echo "error: only ${avail_mb} MB free (need ${MIN_FREE_MB} MB)" >&2
    exit 3
fi

[[ -f "$SRC/moonlight-qt.pro" ]] || { echo "error: $SRC is not a moonlight-qt checkout" >&2; exit 2; }
[[ -f "$SRC/moonlight-common-c/moonlight-common-c/src/Limelight.h" ]] || {
    echo "error: moonlight-common-c submodule inside $SRC is not initialized (run git submodule update --init --recursive)" >&2
    exit 2
}

if [[ "${2:-}" == "--clean" ]]; then
    rm -rf "$OUT"
fi

mkdir -p "$OUT/app"
cd "$OUT"

"$QMAKE" -r "$SRC/moonlight-qt.pro" CONFIG+=release
make -j"$JOBS" release

BIN="$OUT/app/moonlight"
if [[ ! -x "$BIN" ]]; then
    found=$(find "$OUT" -maxdepth 3 -type f -name moonlight -perm -u+x | head -n 1 || true)
    [[ -n "$found" ]] || { echo "error: built moonlight binary not found under $OUT" >&2; exit 4; }
    cp "$found" "$BIN"
    chmod 755 "$BIN"
fi

echo "Built Linux Moonlight client at: $BIN"
if command -v ldd >/dev/null 2>&1; then
    missing=$(ldd "$BIN" | grep "not found" || true)
    if [[ -n "$missing" ]]; then
        echo "error: unresolved shared libraries in $BIN:" >&2
        echo "$missing" >&2
        exit 5
    fi
fi
