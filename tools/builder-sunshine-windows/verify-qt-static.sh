#!/usr/bin/env bash
# Consume the actual static Qt targets used by Sunshine, including image plugins.
# Configuration alone misses transitive archive link failures. This never runs PE code.
set -euo pipefail
TOOLS=$(cd "$(dirname "$0")" && pwd)
scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT
cat > "$scratch/CMakeLists.txt" <<'CMAKE'
cmake_minimum_required(VERSION 3.28)
project(SdsQtStaticSmoke LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_FIND_LIBRARY_SUFFIXES ".a")
set(CMAKE_IMPORT_LIBRARY_SUFFIX ".a")
set(PKG_CONFIG_ARGN --static)
set(CMAKE_DISABLE_FIND_PACKAGE_harfbuzz TRUE)
# FindOpenSSL needs this hint to propagate Windows socket/certificate imports.
# This MSYS2 OpenSSL also uses BCryptGenRandom (its openssl.pc declares bcrypt).
set(OPENSSL_USE_STATIC_LIBS TRUE)
find_package(OpenSSL REQUIRED)
set_property(TARGET OpenSSL::Crypto APPEND PROPERTY INTERFACE_LINK_LIBRARIES bcrypt)
find_package(PkgConfig REQUIRED)
pkg_check_modules(STATIC_TIFF REQUIRED IMPORTED_TARGET libtiff-4)
add_library(TIFF::TIFF INTERFACE IMPORTED)
target_link_libraries(TIFF::TIFF INTERFACE PkgConfig::STATIC_TIFF)
find_package(Qt6 REQUIRED COMPONENTS Widgets Svg)
add_executable(qt-static-smoke main.cpp)
target_link_libraries(qt-static-smoke PRIVATE Qt6::Widgets Qt6::Svg)
target_link_options(qt-static-smoke PRIVATE -static)
CMAKE
cat > "$scratch/main.cpp" <<'CPP'
#include <QApplication>
#include <QSystemTrayIcon>
#include <QSvgRenderer>
int main(int argc, char **argv) {
  QApplication app(argc, argv);
  QSystemTrayIcon tray;
  QSvgRenderer svg;
  return tray.isVisible() || svg.isValid();
}
CPP
cmake -S "$scratch" -B "$scratch/build" -G Ninja \
  -DCMAKE_TOOLCHAIN_FILE="$TOOLS/toolchain-mingw-ucrt64.cmake" \
  -DCMAKE_PREFIX_PATH=/ucrt64/qt6-static -DCMAKE_BUILD_TYPE=Release
cmake --build "$scratch/build" --parallel 2
file "$scratch/build/qt-static-smoke.exe"
"$TOOLS/check-windows-deps.sh" "$scratch/build"
