# builder-sunshine-windows

Cross-compiles the Sunshine fork for **Windows x64 (UCRT)** on a Linux build host,
without needing a Windows machine. Output: `sunshine.exe` and tools, the portable ZIP (`cpack -G ZIP`),
and optionally native test bundles (`test_sunshine.exe`).

## Approach

The upstream Windows CI (`.github/workflows/ci-windows.yml`) builds natively in MSYS2 UCRT64 with
MinGW GCC and MSYS2's packages (`boost`, `curl-winssl`, `openssl`, `opus`, `miniupnpc`, `libvpl`, `MinHook`,
`qt6-static`, ...). Mixing MSYS2's C++ libraries with a different compiler is an ABI risk (Ubuntu's
`g++-mingw-w64` is GCC 13, MSYS2 is GCC 16.2), so the image reproduces the MSYS2 toolchain on Linux:

| Piece | Source |
| --- | --- |
| Headers, CRT import libs, winpthreads, `libgcc`/`libstdc++`/`crtbegin`, C++ headers, libraries | MSYS2 UCRT64 binary packages (`packages.lock`), extracted to `/ucrt64` |
| Cross `binutils 2.47` + `GCC 16.2.0` (`all-gcc`, `lto-plugin`) | GNU release tarballs (SHA-256 pinned), MSYS2 codegen/path patches (`patches/`) |
| Static FFmpeg (incl. x264/x265/SVT-AV1) | `LizardByte/build-deps` release `v2026.1017.131201`, `Windows-AMD64-ffmpeg.tar.gz` (SHA-256 pinned) |
| Qt `moc` for tray `AUTOMOC` | Ubuntu `qt6-base-dev-tools` 6.10.2 via `qt-host-moc.cmake` |
| Node.js for Web UI | nodejs.org v26.13.1 LTS (SHA-256 pinned) |
| Installer | Ubuntu `nsis` 3.10 (`makensis`) via CPack |

Trust chain: `lock-packages.sh` verifies `ucrt64.db` with the MSYS2 keyring (signing key must be a
master key or certified by >= 2 master keys and not revoked) and records each package's SHA-256;
`fetch-msys2.sh` verifies every download against `packages.lock`. Vendored GCC/binutils patches are
verified against `patches/SHA256SUMS`.

## Files

| File | Purpose |
| --- | --- |
| `Dockerfile` | Image `sds-sunshine-windows-cross:<date>` (stages: `sysroot`, `toolchain`, `final`) |
| `build-image.sh` | Builds the Docker image on the Linux build host with CPU/memory caps under `flock` |
| `build-toolchain.sh` | Cross `binutils` + `GCC` build (runs inside Dockerfile `toolchain` stage) |
| `packages.in` / `packages.lock` | MSYS2 package roots and pinned closure (filename + SHA-256) |
| `lock-packages.sh`, `msys2-resolve.py` | Regenerate `packages.lock` from the signature-verified repo database |
| `fetch-msys2.sh` | Download, verify, and extract locked packages |
| `extract-msys2.py` | Safe MSYS2 `.pkg.tar.zst` extractor (rejects path traversal, symlinks escaping root, special files) |
| `test_extract_msys2.py` | Extractor regression tests |
| `export-native-tests.py` | Manifest-admitted portable Windows test bundle and payload hashes |
| `test_export_native_tests.py` | Archive completeness, confinement, and launcher regression tests |
| `collect-native-fixtures.py` | SHA-pinned Windows `COPYONLY`/locale completeness collector |
| `test_collect_native_fixtures.py` | Fixture collector regression tests |
| `verify-qt-static.sh` | Static Qt Widgets/Svg PE link and import smoke check |
| `toolchain-mingw-ucrt64.cmake` | CMake toolchain file (`CMAKE_SYSTEM_PROCESSOR=AMD64`) |
| `qt-host-moc.cmake` | `CMAKE_PROJECT_INCLUDE` pointing `AUTOMOC` targets at Linux host `moc` |
| `build-sunshine-windows.sh` | In-container configure/build/package/check script |
| `check-windows-deps.sh` | `objdump -p` DLL import verification |
| `remote-build-windows.sh` | Wrapper to sync a Sunshine checkout to `SDS_BUILD_HOST` and build under `flock` |

## Usage

```bash
# 1. Build the cross-compiler image once on your Linux build host
rsync -a tools/builder-sunshine-windows/ user@linux-builder:build/sds/win-cross/builder/
ssh user@linux-builder 'cd ~/build/sds/win-cross/builder && ./build-image.sh'

# 2. Remote cross-build from macOS/workstation
SDS_BUILD_HOST=user@linux-builder tools/builder-sunshine-windows/remote-build-windows.sh ./sunshine --package
SDS_BUILD_HOST=user@linux-builder tools/builder-sunshine-windows/remote-build-windows.sh ./sunshine --package --tests

# 3. Direct in-container build on Linux
docker run --rm --cpus=2 --memory=5g --user "$(id -u):$(id -g)" -e HOME=/tmp \
  -v "$PWD/sunshine":/src -v "$PWD/out/windows":/out sds-sunshine-windows-cross:latest \
  /opt/sds/build-sunshine-windows.sh --portable-package --out=/out
```

## Tests

```bash
python3 -m unittest discover -s tools/builder-sunshine-windows -p 'test_*.py' -v
```
