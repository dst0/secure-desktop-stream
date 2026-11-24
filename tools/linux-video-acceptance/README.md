# Headless Linux Video Client Acceptance Harness

Containerized build and synthetic decode-oracle harness for verifying Moonlight client protocol negotiation, encrypted `rtspenc://` transport, certificate pinning, and decoded frame color-bar output inside an isolated `Xvfb` environment without touching any live desktop session.

## Components

- `Dockerfile` — builds the pinned Linux client/decode test environment on top of `sds-sunshine-deps:26.04` (Qt6, SDL2, FFmpeg).
- `build-inside.sh` — builds the client and/or decode oracle as an unprivileged user from a read-only source mount (`/source`) into `/build`.
- `run-build.sh` / `run-oracle-build.sh` — host wrappers applying CPU/memory/PIDs caps, read-only rootfs, and `--security-opt=no-new-privileges`.
- `decode-oracle/` — minimal `QCoreApplication` harness (`main.cpp` + `CMakeLists.txt`) exercising `IdentityManager`, `NvPairingManager`, `NvHTTP`, strict certificate pinning, `moonlight-common-c` `rtspenc://` streaming, and FFmpeg frame verification against synthetic test bars.

## Contract

- Containers execute unprivileged with zero network/host home mounts during compilation.
- Runtime verification checks encrypted mode 2 (`ENCFLG_ALL`), `rtspenc://` negotiation, and decoded color-bar integrity without storing pairing PINs, private keys, or raw pixel buffers in receipts.
