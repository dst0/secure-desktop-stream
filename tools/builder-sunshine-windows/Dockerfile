# sds-sunshine-windows-cross: Linux image that cross-compiles Sunshine for Windows x64 (UCRT)
# with the same toolchain and libraries the upstream MSYS2 UCRT64 Windows CI uses.
#
#   /ucrt64            MSYS2 UCRT64 packages (packages.lock) + Linux-hosted cross binutils/GCC
#   /opt/sds           CMake toolchain file and the in-container build script
#
# Build with ./build-image.sh (uses the classic builder so --cpu-quota/--memory apply).
ARG BASE_IMAGE=ubuntu:26.04@sha256:d66b366dac61b575bee2aef07e9c26e8070096fbe84a3d4d3eb0da069b5d76db

FROM ${BASE_IMAGE} AS base
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl xz-utils bzip2 zstd patch file python3 \
 && rm -rf /var/lib/apt/lists/*

# MSYS2 sysroot: every package is checked against the SHA-256 from the signature-verified repo db.
FROM base AS sysroot
COPY packages.lock fetch-msys2.sh extract-msys2.py /tmp/msys2/
RUN /tmp/msys2/fetch-msys2.sh /tmp/msys2/packages.lock /ucrt64 /tmp/msys2/cache \
 && rm -rf /tmp/msys2 /ucrt64/share/doc /ucrt64/share/man /ucrt64/share/info /ucrt64/qt6-static/doc

# Cross binutils + GCC (compiler proper only), versions and options matching MSYS2.
FROM base AS toolchain
RUN apt-get update \
 && apt-get install -y --no-install-recommends build-essential flex bison texinfo \
      libgmp-dev libmpfr-dev libmpc-dev libisl-dev zlib1g-dev libzstd-dev \
 && rm -rf /var/lib/apt/lists/*
ARG JOBS=2
ARG BINUTILS_VERSION=2.47
ARG BINUTILS_SHA256=3068128c75cda9f898ccb4211d360246e8e195ffcc9dfb655b23ae23a54800e8
ARG GCC_VERSION=16.2.0
ARG GCC_SHA256=e6738e29597f733270731aa90600f37ffdc045079dfc27ec7e8192cc81085c3e
COPY --from=sysroot /ucrt64/include /ucrt64/include
COPY patches /tmp/patches
COPY build-toolchain.sh /tmp/build-toolchain.sh
RUN JOBS=${JOBS} BINUTILS_VERSION=${BINUTILS_VERSION} BINUTILS_SHA256=${BINUTILS_SHA256} \
    GCC_VERSION=${GCC_VERSION} GCC_SHA256=${GCC_SHA256} /tmp/build-toolchain.sh

FROM base AS final
RUN apt-get update \
 && apt-get install -y --no-install-recommends cmake ninja-build pkgconf git python3 make nsis zip unzip \
      gcc libc6-dev qt6-base-dev-tools libgmp10 libmpfr6 libmpc3 libisl23 zlib1g libzstd1 \
 && rm -rf /var/lib/apt/lists/*
# Node.js LTS for the web UI (the Windows CI uses actions/setup-node lts/*).
ARG NODE_VERSION=26.13.1
ARG NODE_SHA256=5c063e46bab0fbc1c17cc445d7ff129cbdcd0471be6ed83b6ab864f8143bc864
RUN curl -fsSL -o /tmp/node.tar.xz "https://nodejs.org/dist/v${NODE_VERSION}/node-v${NODE_VERSION}-linux-x64.tar.xz" \
 && echo "${NODE_SHA256}  /tmp/node.tar.xz" | sha256sum -c --quiet - \
 && mkdir -p /opt/node && tar -xf /tmp/node.tar.xz -C /opt/node --strip-components=1 && rm /tmp/node.tar.xz \
 && ln -s /opt/node/bin/node /opt/node/bin/npm /opt/node/bin/npx /usr/local/bin/
# Cross toolchain first, then the MSYS2 tree on top, so MSYS2's own libgcc/crt files and GCC
# support headers win wherever both provide a file.
COPY --from=toolchain /cross/ucrt64 /ucrt64
COPY --from=sysroot /ucrt64 /ucrt64
COPY toolchain-mingw-ucrt64.cmake qt-host-moc.cmake case-aliases.py build-sunshine-windows.sh check-windows-deps.sh /opt/sds/
COPY export-native-tests.py collect-native-fixtures.py prepare-ffmpeg.py verify-qt-static.sh /opt/sds/
COPY packages.lock /opt/sds/packages.lock
RUN /usr/bin/cc --version | head -1 \
 && /ucrt64/bin/x86_64-w64-mingw32-gcc --version | head -1 \
 && printf '#include <windows.h>\n#include <string>\nint main(){std::string s("ok");return MessageBeep(0)?0:(int)s.size();}\n' > /tmp/t.cpp \
 && /ucrt64/bin/x86_64-w64-mingw32-g++ -O2 -static /tmp/t.cpp -o /tmp/t.exe && file /tmp/t.exe && rm /tmp/t.*
RUN /bin/bash /opt/sds/verify-qt-static.sh
WORKDIR /src
