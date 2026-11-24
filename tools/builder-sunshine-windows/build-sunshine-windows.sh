#!/usr/bin/env bash
# Runs INSIDE the sds-sunshine-windows-cross image. Configures, builds and packages Sunshine for
# Windows x64 from the source tree mounted at /src, mirroring .github/workflows/ci-windows.yml.
#
# Usage: build-sunshine-windows.sh [--build-dir=DIR] [--jobs=N] [--build-type=T] [--tests]
#                                  [--package|--portable-package] [--native-test-bundle=MANIFEST] [--reconfigure]
#                                  [--out=DIR] [-- extra cmake args]
#   --tests      also build tests/test_sunshine.exe (it can only be run on Windows)
#   --package           build the portable ZIP and NSIS installer
#   --portable-package  build and check the portable ZIP only
#   --out=DIR            copy and hash only the artifacts requested by this run
#   --native-test-bundle=MANIFEST  export all admitted fixtures with the native test executable
#     Requires SDS_SOURCE_DIGEST and SDS_IMAGE_ID from the verified candidate/image receipt.
# Environment: BUILD_VERSION, BRANCH, COMMIT (version metadata, as in CI),
#              SUNSHINE_PUBLISHER_NAME/WEBSITE/ISSUE_URL.
set -euo pipefail

SRC=${SRC:-/src}
TOOLS=$(cd "$(dirname "$0")" && pwd)
BUILD=$SRC/cmake-build-windows-cross
JOBS=2
BUILD_TYPE=Release
TESTS=0; PACKAGE=0; INSTALLER=0; RECONF=0; OUT=""
BUNDLE_MANIFEST=""
EXTRA=()
while [ $# -gt 0 ]; do
  case $1 in
    --build-dir=*) BUILD=${1#*=} ;;
    --jobs=*) JOBS=${1#*=} ;;
    --build-type=*) BUILD_TYPE=${1#*=} ;;
    --tests) TESTS=1 ;;
    --package) PACKAGE=1; INSTALLER=1 ;;
    --portable-package) PACKAGE=1 ;;
    --reconfigure) RECONF=1 ;;
    --out=*) OUT=${1#*=} ;;
    --native-test-bundle=*) BUNDLE_MANIFEST=${1#*=}; TESTS=1; RECONF=1 ;;
    --) shift; EXTRA=("$@"); break ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
  shift
done

PORTABLE_TEST_ARGS=()
if [ -n "$BUNDLE_MANIFEST" ]; then
  [ -f "$BUNDLE_MANIFEST" ] && [ -n "$OUT" ] || { echo "native test bundle requires an admitted fixture manifest and --out" >&2; exit 2; }
  [[ ${SDS_SOURCE_DIGEST:-} =~ ^[0-9a-f]{64}$ ]] && [[ ${SDS_IMAGE_ID:-} =~ ^sha256:[0-9a-f]{64}$ ]] || { echo "native test bundle requires verified SDS_SOURCE_DIGEST and SDS_IMAGE_ID" >&2; exit 2; }
  PORTABLE_TEST_ARGS=(-DSUNSHINE_TEST_SOURCE_DIR:STRING=../source -DSUNSHINE_TEST_RUNTIME_DIR:STRING=.)
fi
ARTIFACTS=()
if [ "$PACKAGE" = 1 ]; then
  ARTIFACTS+=(Sunshine-Windows-AMD64-portable.zip)
fi
if [ "$INSTALLER" = 1 ]; then
  ARTIFACTS+=(Sunshine-Windows-AMD64-installer.exe)
fi
if [ -n "$BUNDLE_MANIFEST" ]; then
  ARTIFACTS+=(Sunshine-Windows-AMD64-tests.zip)
fi
if [ -n "$OUT" ] && [ "${#ARTIFACTS[@]}" -gt 0 ]; then
  for name in SHA256SUMS "${ARTIFACTS[@]}"; do
    if [[ -e $OUT/$name || -L $OUT/$name ]]; then
      echo "refusing to replace existing artifact output $name; use a fresh directory" >&2
      exit 2
    fi
  done
fi

# Prebuilt FFmpeg from LizardByte/build-deps, pinned to the tag of the third-party/build-deps
# submodule commit (d0ac5ef4 = v2026.1017.131201). ffmpeg.cmake would otherwise need tag lookups
# through git inside the container and fall back to the "latest" release when they fail.
FFMPEG_TAG=${FFMPEG_TAG:-v2026.1017.131201}
FFMPEG_SHA256=${FFMPEG_SHA256:-5e644e2446ceb6c243eefb88788eadcad454a73f30410f1107c036bf2ad86916}
[[ $FFMPEG_TAG =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ && $FFMPEG_SHA256 =~ ^[0-9a-f]{64}$ ]] || {
  echo "Windows FFmpeg requires a versioned release and SHA-256 pin" >&2
  exit 2
}
FFMPEG_DIR=$BUILD/_deps/ffmpeg-$FFMPEG_TAG
mkdir -p "$FFMPEG_DIR"
[ ! -L "$FFMPEG_DIR" ] || { echo "refusing a symlink for the FFmpeg cache" >&2; exit 2; }
FFMPEG_DIR=$(cd "$FFMPEG_DIR" && pwd -P)
FFMPEG_ARCHIVE=$FFMPEG_DIR/ffmpeg.tar.gz
if [[ ! -e $FFMPEG_ARCHIVE && ! -L $FFMPEG_ARCHIVE ]]; then
  FFMPEG_DOWNLOAD=$(mktemp "$FFMPEG_DIR/.ffmpeg-download-XXXXXXXX")
  trap 'rm -f -- "$FFMPEG_DOWNLOAD"' EXIT
  curl -fsSL --retry 3 -o "$FFMPEG_DOWNLOAD" \
    "https://github.com/LizardByte/build-deps/releases/download/$FFMPEG_TAG/Windows-AMD64-ffmpeg.tar.gz"
  printf '%s  %s\n' "$FFMPEG_SHA256" "$FFMPEG_DOWNLOAD" | sha256sum -c --quiet -
  ln -T -- "$FFMPEG_DOWNLOAD" "$FFMPEG_ARCHIVE"
  rm -f -- "$FFMPEG_DOWNLOAD"
  trap - EXIT
fi
python3 -I "$TOOLS/prepare-ffmpeg.py" "$FFMPEG_ARCHIVE" "$FFMPEG_SHA256"

export HOME=${HOME:-/tmp}
[ -w "$HOME" ] || export HOME=/tmp
export npm_config_cache=${npm_config_cache:-$HOME/.npm}
export BUILD_VERSION=${BUILD_VERSION:-}
export BRANCH=${BRANCH:-}
export COMMIT=${COMMIT:-}

# Windows-SDK spellings (Windows.h, WinSock2.h, D3DCompiler, ...) -> MinGW's lower-case files.
ALIAS=$BUILD/case-aliases
python3 -I "$TOOLS/case-aliases.py" headers "$SRC" /ucrt64/include "$ALIAS/include" | tail -1
# The test project replaces CMAKE_C_FLAGS/CMAKE_CXX_FLAGS with coverage flags.
# Keep SDK spelling aliases available to those targets as system include paths;
# explicit project -I paths still take precedence. Do not inherit host paths.
export C_INCLUDE_PATH="$ALIAS/include"
export CPLUS_INCLUDE_PATH="$ALIAS/include"

# Sunshine's Windows resource setup selects bare windres. Bind that name to
# the pinned target tool and target preprocessor, never a Linux-host compiler.
mkdir -p "$ALIAS/bin"
cat > "$ALIAS/bin/windres" <<'WINDRES'
#!/bin/sh
exec /ucrt64/bin/x86_64-w64-mingw32-windres \
  --preprocessor=/ucrt64/bin/x86_64-w64-mingw32-gcc \
  --preprocessor-arg=-E --preprocessor-arg=-xc-header --preprocessor-arg=-DRC_INVOKED "$@"
WINDRES
chmod +x "$ALIAS/bin/windres"
for cross_tool in /ucrt64/bin/x86_64-w64-mingw32-*; do
  case "$cross_tool" in
    *.exe) ;;
    *) [ -x "$cross_tool" ] && ln -sf "$cross_tool" "$ALIAS/bin/${cross_tool##*/}" ;;
  esac
done
export PATH="$ALIAS/bin:$PATH"
for rust_bin in /cargo/bin "$HOME/.cargo/bin"; do
  if [ -d "$rust_bin" ] && [[ ":$PATH:" != *":$rust_bin:"* ]]; then
    export PATH="$rust_bin:$PATH"
  fi
done
command -v cargo >/dev/null 2>&1 || { echo "cargo is missing in Windows cross-build container (mount /cargo and /rustup or install Rust)" >&2; exit 1; }
command -v cc >/dev/null 2>&1 || { echo "host C compiler /usr/bin/cc is missing in Windows cross-build container (rebuild image with gcc libc6-dev)" >&2; exit 1; }
command -v x86_64-w64-mingw32-dlltool >/dev/null 2>&1 || { echo "x86_64-w64-mingw32-dlltool is missing on PATH" >&2; exit 1; }


CMAKE_CACHE=$BUILD/CMakeCache.txt
# Reconfigure old trees that retained the MinGW OpenSSL DLL import libraries.
# Reject a different cached FFmpeg prefix: FindPkgConfig can keep its earlier
# result alongside the new prefix, so use a fresh tree for a release change.
if [ -f "$CMAKE_CACHE" ]; then
  CACHED_FFMPEG=$(awk '/^FFMPEG_PREPARED_BINARIES:[^=]*=/ {sub(/^[^=]*=/, ""); print}' "$CMAKE_CACHE")
  [[ -z $CACHED_FFMPEG || $CACHED_FFMPEG == "$FFMPEG_DIR/ffmpeg" ]] || {
    echo "Windows FFmpeg prefix changed; use a fresh build directory" >&2
    exit 2
  }
fi
static_openssl_cached() {
  [ -f "$CMAKE_CACHE" ] &&
    grep -Fxq 'LIB_EAY:FILEPATH=/ucrt64/lib/libcrypto.a' "$CMAKE_CACHE" &&
    grep -Fxq 'SSL_EAY:FILEPATH=/ucrt64/lib/libssl.a' "$CMAKE_CACHE"
}
if [ "$RECONF" = 1 ] || [ ! -f "$BUILD/build.ninja" ] || ! static_openssl_cached; then
  cmake -S "$SRC" -B "$BUILD" -G Ninja \
    -ULIB_EAY -USSL_EAY \
    -DOPENSSL_USE_STATIC_LIBS:BOOL=TRUE \
    -DCMAKE_C_FLAGS="-idirafter $ALIAS/include" \
    -DCMAKE_CXX_FLAGS="-idirafter $ALIAS/include" \
    -DCMAKE_EXE_LINKER_FLAGS="-L$ALIAS/lib" \
    -DCMAKE_SHARED_LINKER_FLAGS="-L$ALIAS/lib" \
    -DCMAKE_TOOLCHAIN_FILE="$TOOLS/toolchain-mingw-ucrt64.cmake" \
    -DCMAKE_BUILD_TYPE="$BUILD_TYPE" \
    -DBUILD_DOCS=OFF \
    -DBUILD_TESTS=$([ "$TESTS" = 1 ] && echo ON || echo OFF) \
    -DBUILD_WERROR=OFF \
    -DSUNSHINE_ASSETS_DIR=assets \
    -DSUNSHINE_PUBLISHER_NAME="${SUNSHINE_PUBLISHER_NAME:-secure-desktop-stream}" \
    -DSUNSHINE_PUBLISHER_WEBSITE="${SUNSHINE_PUBLISHER_WEBSITE:-https://localhost.invalid}" \
    -DSUNSHINE_PUBLISHER_ISSUE_URL="${SUNSHINE_PUBLISHER_ISSUE_URL:-https://localhost.invalid}" \
    -DFFMPEG_PREPARED_BINARIES:PATH="$FFMPEG_DIR/ffmpeg" \
    -DZLIB=/ucrt64/bin/zlib1.dll \
    -DCMAKE_PROJECT_INCLUDE="$TOOLS/qt-host-moc.cmake" \
    "${PORTABLE_TEST_ARGS[@]}" \
    "${EXTRA[@]}"
fi
static_openssl_cached || { echo "Windows build did not resolve pinned static OpenSSL libraries" >&2; exit 2; }

python3 -I "$TOOLS/case-aliases.py" libs "$BUILD/build.ninja" /ucrt64/lib "$ALIAS/lib"

targets=(sunshine sunshinesvc audio-info dxgi-info web-ui)
[ "$TESTS" = 1 ] && targets+=(test_sunshine)
ninja -C "$BUILD" -j"$JOBS" "${targets[@]}"

if [ "$PACKAGE" = 1 ]; then
  PACKAGE_DIR=$(mktemp -d "$BUILD/cpack-XXXXXXXX")
  PACKAGE_DIR=$(cd "$PACKAGE_DIR" && pwd -P)
  (cd "$BUILD" && cpack -B "$PACKAGE_DIR" -G ZIP)
  check_dir=$(mktemp -d)
  trap 'rm -rf -- "$check_dir"' EXIT
  unzip -q "$PACKAGE_DIR/Sunshine.zip" -d "$check_dir"
  "$TOOLS/check-windows-deps.sh" "$check_dir"
  rm -rf -- "$check_dir"
  trap - EXIT
  if [ "$INSTALLER" = 1 ]; then
    (cd "$BUILD" && cpack -B "$PACKAGE_DIR" -G NSIS)
  fi
fi

if [ -n "$BUNDLE_MANIFEST" ]; then
  python3 -I "$TOOLS/export-native-tests.py" \
    --source-root="$SRC" --test-root="$BUILD/tests" --fixture-manifest="$BUNDLE_MANIFEST" \
    --dll=/ucrt64/bin/zlib1.dll --dependency-checker="$TOOLS/check-windows-deps.sh" \
    --output="$OUT/Sunshine-Windows-AMD64-tests.zip" \
    --source-digest="$SDS_SOURCE_DIGEST" --image-id="$SDS_IMAGE_ID"
fi

if [ -n "$OUT" ] && [ "${#ARTIFACTS[@]}" -gt 0 ]; then
  mkdir -p "$OUT"
  if [ "$PACKAGE" = 1 ]; then
    cp "$PACKAGE_DIR/Sunshine.zip" "$OUT/Sunshine-Windows-AMD64-portable.zip"
  fi
  if [ "$INSTALLER" = 1 ]; then
    install_sources=("$PACKAGE_DIR"/Sunshine*.exe)
    [[ ${#install_sources[@]} -eq 1 && -f ${install_sources[0]} ]] || {
      echo "expected one NSIS installer output" >&2
      exit 2
    }
    cp "${install_sources[0]}" "$OUT/Sunshine-Windows-AMD64-installer.exe"
  fi
  (cd "$OUT" && sha256sum "${ARTIFACTS[@]}" > SHA256SUMS && cat SHA256SUMS)
fi
echo SDS_WINDOWS_BUILD_OK
