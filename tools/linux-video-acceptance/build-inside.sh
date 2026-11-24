#!/bin/bash
set -euo pipefail
umask 077
test -f /source/moonlight-qt.pro
test -f /source/moonlight-common-c/moonlight-common-c/src/Limelight.h
mkdir -p /build/app /build/home
export HOME=/build/home
cd /build

# Release only, with no host capture, DRM, hardware decode, or Wayland path.
qmake6 -r /source/moonlight-qt.pro \
    CONFIG+=release CONFIG+=disable-prebuilts CONFIG+=disable-wayland \
    CONFIG+=disable-libva CONFIG+=disable-libvdpau CONFIG+=disable-libdrm \
    CONFIG+=disable-libplacebo \
    'QMAKE_CFLAGS_RELEASE_WITH_DEBUGINFO=-O2' \
    'QMAKE_CXXFLAGS_RELEASE_WITH_DEBUGINFO=-O2' \
    'QMAKE_LFLAGS_RELEASE_WITH_DEBUGINFO=' -after 'CONFIG-=force_debug_info'
if grep -rqsE '^(CFLAGS|CXXFLAGS)[[:space:]]*=.*[[:space:]]-g([[:space:]]|$)' \
        --include=Makefile.Release .; then
    echo 'Release configuration unexpectedly contains debug information' >&2
    exit 4
fi
make -j2 release
test -x app/moonlight
sha256sum app/moonlight > Moonlight-executable.sha256
ldd app/moonlight > runtime-dependencies.txt
if grep -q 'not found' runtime-dependencies.txt; then
    echo 'Private Linux client has unresolved runtime dependencies' >&2
    exit 5
fi
