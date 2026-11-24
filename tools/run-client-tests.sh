#!/usr/bin/env bash
# Build and run the client unit tests (tests/unit in a moonlight-qt worktree) with Homebrew Qt 6.
#
# usage: tools/run-client-tests.sh <moonlight-qt-worktree> [extra test binary arguments]
#
# The tests are built out of tree in build/<worktree-name>/tests-unit (next to the app build,
# so there is still only one build directory per worktree). They create and delete
# Keychain items under a test-only service name; the production identity item is never touched.
# The build step takes .mac-build.lock, builds without debug info, and releases the lock before
# running the test binary.
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
SRC=${1:?usage: $0 <moonlight-qt-worktree> [test args]}
SRC=$(cd "$SRC" && pwd)
shift
NAME=$(basename "$SRC")
OUT="$ROOT/build/$NAME/tests-unit"
JOBS=${MAKE_JOBS:-6}
MIN_FREE_MB=1536
QMAKE=${QMAKE:-/opt/homebrew/bin/qmake6}

build_tests() {
    local avail_mb
    avail_mb=$(( $(df -k "$HOME" | awk 'NR==2 {print $4}') / 1024 ))
    if (( avail_mb < MIN_FREE_MB )); then
        echo "error: only ${avail_mb} MB free on the data volume (need ${MIN_FREE_MB} MB)" >&2
        exit 3
    fi

    [[ -f "$SRC/tests/unit/unit.pro" ]] || { echo "error: $SRC/tests/unit/unit.pro not found" >&2; exit 2; }
    "$ROOT/tools/ensure-mac-deps.sh" "$SRC"

    local openssl_pkgconfig="/opt/homebrew/opt/openssl/lib/pkgconfig"
    if [[ ! -d "$openssl_pkgconfig" && -d "/usr/local/opt/openssl/lib/pkgconfig" ]]; then
        openssl_pkgconfig="/usr/local/opt/openssl/lib/pkgconfig"
    fi
    export PKG_CONFIG_PATH="${openssl_pkgconfig}${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}"

    mkdir -p "$OUT"
    cd "$OUT"
    "$QMAKE" "$SRC/tests/unit/unit.pro" CONFIG+=release \
        "QMAKE_CFLAGS_RELEASE_WITH_DEBUGINFO=-O2" "QMAKE_CXXFLAGS_RELEASE_WITH_DEBUGINFO=-O2" \
        "QMAKE_LFLAGS_RELEASE_WITH_DEBUGINFO=" \
        -after "CONFIG-=force_debug_info"

    # Refuse to build with debug info: it does not fit on this machine's disk.
    local gflag_re='^(CFLAGS|CXXFLAGS|OBJECTIVE_CFLAGS)[[:space:]]*=.*[[:space:]]-g([[:space:]]|$)'
    if [[ -n "$(find . -name Makefile.Release -print -quit)" ]]; then
        if grep -rqsE "$gflag_re" --include='Makefile.Release' .; then
            echo "error: generated release Makefiles still contain -g:" >&2
            grep -rnsE "$gflag_re" --include='Makefile.Release' . | head >&2
            exit 4
        fi
    elif [[ -f Makefile ]]; then
        if grep -qsE "$gflag_re" Makefile; then
            echo "error: generated Makefile still contains -g:" >&2
            grep -nsE "$gflag_re" Makefile | head >&2
            exit 4
        fi
    else
        echo "error: no Makefile generated" >&2
        exit 4
    fi

    make -j"$JOBS"
}

if [[ "${SDS_UNIT_BUILD_PHASE:-}" == "1" ]]; then
    build_tests
    exit 0
fi

if [[ "${SDS_MAC_BUILD_LOCKED:-}" == "1" ]]; then
    build_tests
else
    mkdir -p "$ROOT/build"
    env SDS_UNIT_BUILD_PHASE=1 SDS_MAC_BUILD_LOCKED=1 /usr/bin/lockf -k "$ROOT/build/.mac-build.lock" "$0" "$SRC"
fi

# The static source test reads the sources of this worktree
cd "$OUT"
export SDS_SOURCE_ROOT="$SRC"
exec ./moonlight-unit-tests ${@+"$@"}
