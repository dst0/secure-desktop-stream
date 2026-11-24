# CMake toolchain file: cross-compile for Windows x64 (UCRT) from Linux with the
# sds-sunshine-windows-cross image. The cross compiler and the MSYS2 UCRT64 sysroot both live in
# /ucrt64, the same prefix MSYS2 uses, so .pc files and CMake package configs from MSYS2 resolve
# without any path rewriting.
set(CMAKE_SYSTEM_NAME Windows)
# Sunshine keys MinHook and the FFmpeg archive name (Windows-AMD64-ffmpeg.tar.gz) off this value,
# which is what CMake reports natively on Windows x64.
set(CMAKE_SYSTEM_PROCESSOR AMD64)

set(MINGW_PREFIX /ucrt64)
set(MINGW_TRIPLE x86_64-w64-mingw32)

set(CMAKE_C_COMPILER "${MINGW_PREFIX}/bin/${MINGW_TRIPLE}-gcc")
set(CMAKE_CXX_COMPILER "${MINGW_PREFIX}/bin/${MINGW_TRIPLE}-g++")
set(CMAKE_RC_COMPILER "${MINGW_PREFIX}/bin/${MINGW_TRIPLE}-windres")
set(CMAKE_AR "${MINGW_PREFIX}/bin/${MINGW_TRIPLE}-gcc-ar" CACHE FILEPATH "")
set(CMAKE_RANLIB "${MINGW_PREFIX}/bin/${MINGW_TRIPLE}-gcc-ranlib" CACHE FILEPATH "")
set(CMAKE_STRIP "${MINGW_PREFIX}/bin/${MINGW_TRIPLE}-strip" CACHE FILEPATH "")
set(CMAKE_OBJDUMP "${MINGW_PREFIX}/bin/${MINGW_TRIPLE}-objdump" CACHE FILEPATH "")

set(CMAKE_FIND_ROOT_PATH "${MINGW_PREFIX}")
# FindPkgConfig resolves static archives with find_library(). Admit only the
# explicitly supplied target FFmpeg tree in addition to the MSYS2 sysroot;
# otherwise its relocatable -L paths are re-rooted and degrade to bare -l names.
# The build helper verifies the pinned release before supplying this prefix.
if(DEFINED FFMPEG_PREPARED_BINARIES)
    if(NOT IS_ABSOLUTE "${FFMPEG_PREPARED_BINARIES}" OR
       NOT EXISTS "${FFMPEG_PREPARED_BINARIES}/lib/libavcodec.a")
        message(FATAL_ERROR "FFMPEG_PREPARED_BINARIES must be an existing absolute target prefix")
    endif()
    list(APPEND CMAKE_FIND_ROOT_PATH "${FFMPEG_PREPARED_BINARIES}")
    list(APPEND CMAKE_TRY_COMPILE_PLATFORM_VARIABLES FFMPEG_PREPARED_BINARIES)
endif()
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)

# pkg-config: only the target sysroot (MSYS2 .pc files use prefix=/ucrt64).
set(PKG_CONFIG_EXECUTABLE /usr/bin/pkgconf CACHE FILEPATH "pkg-config for the Windows sysroot")
set(ENV{PKG_CONFIG_LIBDIR} "${MINGW_PREFIX}/lib/pkgconfig:${MINGW_PREFIX}/share/pkgconfig")
unset(ENV{PKG_CONFIG_PATH})
unset(ENV{PKG_CONFIG_SYSROOT_DIR})
