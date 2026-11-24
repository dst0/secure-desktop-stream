#!/usr/bin/env bash
# Builds the Linux-hosted x86_64-w64-mingw32 cross binutils + GCC that match the MSYS2 UCRT64
# toolchain (same upstream versions, same configure options and the codegen/path patches MSYS2
# applies). Only the compiler proper is built (all-gcc + lto-plugin); libgcc, libstdc++,
# winpthreads and the CRT are taken prebuilt from the MSYS2 packages, so C++ libraries from
# MSYS2 (boost, Qt, x265 in FFmpeg) link against exactly the runtime they were built with.
#
# Expects the MSYS2 headers at /ucrt64/include (sysroot = /ucrt64, exactly like MSYS2's GCC).
# Installs into /ucrt64 (needed while building GCC) and stages a copy in $DESTDIR_OUT.
set -euo pipefail

: "${BINUTILS_VERSION:?}" "${BINUTILS_SHA256:?}" "${GCC_VERSION:?}" "${GCC_SHA256:?}"
JOBS=${JOBS:-2}
PREFIX=/ucrt64
TARGET=x86_64-w64-mingw32
DESTDIR_OUT=${DESTDIR_OUT:-/cross}
PATCHES=${PATCHES:-/tmp/patches}
WORK=/tmp/toolchain-src

mkdir -p "$WORK" && cd "$WORK"

fetch() {  # url sha256
  local f=${1##*/}
  curl -fsSL --retry 3 -o "$f" "$1"
  echo "$2  $f" | sha256sum -c --quiet -
  tar -xf "$f"
  rm -f "$f"
}

apply_series() {  # srcdir patchdir
  (cd "$PATCHES" && sha256sum -c --quiet SHA256SUMS)
  while read -r patch strip; do
    case $patch in ''|'#'*) continue ;; esac
    echo "applying $patch"
    patch -d "$1" "${strip:--p1}" --forward --batch -i "$2/$patch"
  done < "$2/series"
}

fetch "https://ftp.gnu.org/gnu/binutils/binutils-${BINUTILS_VERSION}.tar.bz2" "$BINUTILS_SHA256"
fetch "https://ftp.gnu.org/gnu/gcc/gcc-${GCC_VERSION}/gcc-${GCC_VERSION}.tar.xz" "$GCC_SHA256"
apply_series "binutils-${BINUTILS_VERSION}" "$PATCHES/binutils"
apply_series "gcc-${GCC_VERSION}" "$PATCHES/gcc"

# binutils: options follow MSYS2 mingw-w64-binutils (minus NLS/libiberty install, host-only bits)
mkdir -p build-binutils && cd build-binutils
"../binutils-${BINUTILS_VERSION}/configure" \
  --prefix="$PREFIX" \
  --target="$TARGET" \
  --with-sysroot="$PREFIX" \
  --enable-64-bit-bfd \
  --disable-multilib \
  --disable-rpath \
  --disable-shared \
  --disable-werror \
  --disable-nls \
  --enable-deterministic-archives \
  --enable-lto \
  --enable-plugins \
  --with-system-zlib \
  --disable-gdb --disable-gdbserver --disable-sim --disable-gprofng --disable-readline --disable-libdecnumber
make -j"$JOBS"
make install
make install DESTDIR="$DESTDIR_OUT"
cd "$WORK"

# gcc: configure options mirror MSYS2 mingw-w64-gcc 16.2.0-7 build() for x86_64/ucrt64.
# --prefix and --with-sysroot are both /ucrt64 like in MSYS2, so the driver finds headers in
# /ucrt64/include, startfiles/libraries in /ucrt64/lib (patch 1000) and libgcc/crtbegin in
# /ucrt64/lib/gcc/x86_64-w64-mingw32/<ver>, i.e. exactly the files the MSYS2 packages install.
mkdir -p build-gcc && cd build-gcc
"../gcc-${GCC_VERSION}/configure" \
  --prefix="$PREFIX" \
  --target="$TARGET" \
  --with-sysroot="$PREFIX" \
  --with-local-prefix=/local \
  --with-native-system-header-dir=/include \
  --with-gxx-include-dir="$PREFIX/include/c++/$GCC_VERSION" \
  --disable-bootstrap \
  --enable-checking=release \
  --with-arch=nocona \
  --with-tune=generic \
  --enable-mingw-wildcard \
  --enable-languages=c,c++,lto \
  --enable-threads=posix \
  --enable-tls \
  --enable-fully-dynamic-string \
  --enable-libstdcxx-time \
  --disable-libstdcxx-pch \
  --enable-libgomp \
  --disable-libssp \
  --disable-multilib \
  --disable-rpath \
  --disable-win32-registry \
  --disable-nls \
  --disable-werror \
  --disable-symvers \
  --with-system-zlib \
  --with-isl \
  --enable-lto \
  --with-pkgversion="sds cross build matching MSYS2 Rev7" \
  --with-bugurl="https://localhost.invalid"
make -j"$JOBS" all-gcc all-lto-plugin
make install-gcc install-lto-plugin DESTDIR="$DESTDIR_OUT"
cd /
rm -rf "$WORK"

# GCC's internal headers and the fixincludes output must be exactly MSYS2's (they come with the
# mingw-w64-ucrt-x86_64-gcc package); drop the copies generated here so nothing can shadow them.
rm -rf "$DESTDIR_OUT$PREFIX/lib/gcc/$TARGET/$GCC_VERSION/include" \
       "$DESTDIR_OUT$PREFIX/lib/gcc/$TARGET/$GCC_VERSION/include-fixed" \
       "$DESTDIR_OUT$PREFIX/lib/gcc/$TARGET/$GCC_VERSION/install-tools"

# strip host binaries in the staged copy
find "$DESTDIR_OUT" -type f -perm -u+x -exec sh -c 'file -b "$1" | grep -q "^ELF" && strip --strip-unneeded "$1"' _ {} \; || true
"$DESTDIR_OUT$PREFIX/bin/$TARGET-gcc" -v 2>&1 | tail -3
