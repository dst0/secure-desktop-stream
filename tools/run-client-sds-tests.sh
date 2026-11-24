#!/usr/bin/env bash
# Build and run the secure-desktop-stream client tests (moonlight-qt tests/sds, Qt Test).
#
# Usage: tools/run-client-sds-tests.sh [moonlight-qt worktree] [extra test args...]
#   default worktree: moonlight-qt
#   SDS_TEST_ONLY=<suite>   run one suite: sanitizer, downloaddir, clipboard, controller, client
#   SDS_TEST_BUILD_DIR=...  build directory (default build/<worktree-name>/tests-sds, next to
#                           the app build of tools/build-client-mac.sh)
#
# Needs Homebrew Qt 6 (qmake6), openssl and python3. The build step takes the same lock as
# tools/build-client-mac.sh (Mac builds are serialized across agents), builds without debug
# info and refuses to start with less than 2 GB free. The tests run after the lock is released.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WT="${1:-$ROOT/moonlight-qt}"
if [[ $# -gt 0 ]]; then
    shift
fi
WT="$(cd "$WT" && pwd)"
BUILD="${SDS_TEST_BUILD_DIR:-$ROOT/build/$(basename "$WT")/tests-sds}"

build() {
    if [[ ! -f "$WT/tests/sds/sds.pro" ]]; then
        echo "error: $WT/tests/sds/sds.pro not found" >&2
        exit 2
    fi
    "$ROOT/tools/ensure-mac-deps.sh" "$WT"

    local avail_mb
    avail_mb=$(( $(df -k "$HOME" | awk 'NR==2 {print $4}') / 1024 ))
    if (( avail_mb < 2048 )); then
        echo "error: only ${avail_mb} MB free on the data volume (need 2048 MB); not building" >&2
        exit 3
    fi

    local qmake
    qmake="${QMAKE:-$(command -v qmake6 || true)}"
    if [[ -z "$qmake" ]]; then
        echo "error: qmake6 not found (brew install qt)" >&2
        exit 2
    fi

    local openssl_pkgconfig="/opt/homebrew/opt/openssl/lib/pkgconfig"
    if [[ ! -d "$openssl_pkgconfig" && -d "/usr/local/opt/openssl/lib/pkgconfig" ]]; then
        openssl_pkgconfig="/usr/local/opt/openssl/lib/pkgconfig"
    fi
    export PKG_CONFIG_PATH="${openssl_pkgconfig}${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}"
    # No debug info: the Mac this runs on is short on disk
    export CFLAGS="-g0" CXXFLAGS="-g0"

    mkdir -p "$BUILD"
    cd "$BUILD"
    "$qmake" "$WT/tests/sds/sds.pro" CONFIG+=release
    make -j"${MAKE_JOBS:-6}"
}

if [[ "${SDS_TEST_BUILD_PHASE:-}" == "1" ]]; then
    build
    exit 0
fi

mkdir -p "$ROOT/build"
env SDS_TEST_BUILD_PHASE=1 /usr/bin/lockf -k "$ROOT/build/.mac-build.lock" "$0" "$WT"

echo "== running $BUILD/sds_tests"
cd "$BUILD"
./sds_tests "$@"
