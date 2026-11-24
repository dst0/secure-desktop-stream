# Secure Desktop Stream

Post-quantum hardened remote desktop streaming umbrella monorepo combining a security-hardened **Sunshine** host, **Moonlight** desktop client, **moonlight-common-c** protocol core, universal host profiles, and a cross-platform Rust installer, dependency manager, and uninstaller (`sds-installer`).

## Architecture: 1 Controller -> N Managed Hosts

```text
+-----------------------------------+          47984/tcp (PQ mTLS 1.3: X25519MLKEM768)
|      Controller (Client)          | <==============================================> +-----------------------------------+
|  Moonlight Secure Desktop (Qt6)   |  Control, Capabilities, Clipboard, File Xfer     |     Managed Host (Server)         |
|  - Strict TLS cert pinning        |                                                  |     Hardened Sunshine             |
|  - Keychain / OS secret storage   |  48010/tcp (rtspenc://) + 47998-48002/udp        |     - Linux Virtual X11           |
|  - Hardware Metal / YCoCg-R 4:4:4 | <==============================================> |     - Linux Physical X11          |
|  - Mic passthrough (48002/udp)    |  AES-128-GCM Video, Audio, Input, Mic            |     - Windows Host                |
+-----------------------------------+                                                  +-----------------------------------+
                  |                                                                                      ^
                  +------ PQ SSH Tunnel (127.0.0.1:ephemeral -> 127.0.0.1:47990) ------------------------+
                          Web Admin UI stays loopback-only; 47989/tcp closed after pairing
```

## Key Capabilities & Hardening

- **Post-Quantum Transport & Fail-Closed Security:**
  - Enforces **TLS 1.3 with `X25519MLKEM768`** for paired HTTPS (`47984/tcp`), rejecting TLS 1.2 and classical-only key exchange.
  - Fail-closed **`rtspenc://`** control negotiation and mandatory encrypted streams (`ENCFLG_ALL`, `lan_encryption_mode = 2`, `wan_encryption_mode = 2`).
  - Removes STUN/NAT64 probes (`ipv4only.arpa`), disables UPnP and mDNS advertisement, binds the Sunshine Web UI strictly to `127.0.0.1:47990` with CSRF enforcement, and closes `47989/tcp` after pairing.
  - Strict client certificate pinning without plaintext HTTP fallback, UUID/SHA-256 path containment, `0700` staging, and non-synchronizable Keychain secrets on macOS.
- **Memory-Safe Rust HTTP/TLS Layer (`sds-http-rs`) & Rust Installer (`sds-installer`):**
  - Replaces legacy C++ `Simple-Web-Server` with an in-tree `tokio` + `rustls`/`aws-lc-rs` (`X25519MLKEM768`) + `httparse` backend (`sunshine/third-party/sds-http-rs`, see [Branch Sync Guide](docs/SYNCING-BRANCHES.md)).
- **High-Fidelity Streaming & Color:**
  - Supports **hardware-packed `YCoCg-R` 4:4:4 over 10-bit `P010` HEVC Main10** (VAAPI on AMD/Intel Linux -> Apple M4 VideoToolbox + Metal unpack, avoiding 4:2:0 subpixel chroma smear) alongside **host GPU/encoder selection** (`<sdsAdapters>`, `<sdsEncoders>`, `software` 4:4:4 fallback) and **dynamic native host resolution** (`XRandR` + rootless `Xorg + dummy` up to `4096x4096`).
- **Interactive Desktop Features (Opt-In Per Client):**
  - Bidirectional text & PNG clipboard (`CLIPBOARD`), chunked inbox/outbox file transfer, unified lazy file clipboard (`Cmd/Ctrl+C/V`) + X11 `XDND` drag-and-drop, and encrypted UDP microphone passthrough (`48002/udp`).
  - Default paired client permissions are **empty**; grant `clipboard_read`, `clipboard_write`, `file_upload`, `file_download`, and `mic` explicitly per paired client.
- **Hardened Host Profiles (`profiles/`):**
  - **Linux Virtual X11:** Rootless `Xorg + dummy` + Openbox + LXQt (`QuickExec=true`) + private PipeWire/WirePlumber graph. Keeps `NoNewPrivileges=true` on Sunshine & PipeWire services while omitting it on the display service so interactive `sudo` works inside the streamed desktop.
  - **Linux Physical X11:** Captures the active X11 display with `/dev/uinput` udev rules and `picom` configured on `backend = "xrender"` (avoiding `glx` compositor freezes under `x11grab`).
  - **Windows Host:** Protected SDDL DACLs on staging/config directories and `RemoteAddress`-scoped Windows Defender Firewall rules.

## Repository Layout

| Path | Description |
| --- | --- |
| `sunshine/` | Public Sunshine fork submodule (`dst0/Sunshine`) |
| `moonlight-qt/` | Public Moonlight desktop client submodule (`dst0/moonlight-qt`) |
| `moonlight-common-c/` | Public protocol library submodule (`dst0/moonlight-common-c`) |
| `installer/` | Cross-platform pure native Rust GUI (`floem` software renderer) + `ratatui` TUI + CLI installer, dependency checker/auto-installer, PQ probe, SSH fleet deployer, and clean uninstaller |
| `profiles/` | Generic, parameterized configuration & systemd/PowerShell templates for all 3 host profiles |
| `tools/` | Client/host build helpers (macOS, Linux, Docker Linux/Windows Sunshine builders), PII auditor, fork sync helper, and test fixtures |
| `docs/` | Protocol contract ([DESIGN.md](docs/DESIGN.md)), file clipboard spec, transport budget, architecture/profiles guide, and branch sync instructions |
| `tests/` | Automated PII audit regression tests and UDP relay tests |

## Quick Start

> **Note on settings:** Runtime streaming preferences (codec, 4:4:4 mode, GPU adapter, encoder, host resolution matching, bitrate, and per-client permissions) live directly in the **Moonlight client** and **Sunshine Web UI** rather than being duplicated in the installer. The installer handles dependency checking/installation, clean builds or verified archive installs, host profiles, firewall scoping, guided PQ pairing, and uninstallation.

### 1. Option A — Install Prebuilt Release (Recommended)

#### macOS & Linux
```bash
curl -fsSL https://github.com/dst0/secure-desktop-stream/releases/latest/download/get.sh -o get.sh
bash get.sh --release-base=https://github.com/dst0/secure-desktop-stream/releases/latest/download --auto-deps
```

#### Windows (PowerShell 5.1 / 7+)
```powershell
Invoke-WebRequest -Uri https://github.com/dst0/secure-desktop-stream/releases/latest/download/install-windows.ps1 -OutFile install-windows.ps1
powershell -ExecutionPolicy Bypass -File .\install-windows.ps1 -ReleaseBase https://github.com/dst0/secure-desktop-stream/releases/latest/download -AutoDeps -AllowUnsigned
```

### 2. Option B — Build From Source Checkout

```bash
git clone --recursive https://github.com/dst0/secure-desktop-stream.git
cd secure-desktop-stream
bash installer/bootstrap/get.sh --from-source --auto-deps
```

On Windows from a checkout:

```powershell
powershell -ExecutionPolicy Bypass -File installer\bootstrap\install-windows.ps1 -FromSource -AutoDeps -AllowUnsigned
```

Or run the CLI directly after building `sds-installer`:

```bash
cd installer
cargo build --release --locked

# Inspect platform, toolchain & missing dependencies (and optionally auto-install them)
./target/release/sds-installer deps check --role all
./target/release/sds-installer deps install --role client-build --execute-sudo

# Launch the native Rust GUI wizard (RU / EN, tiny-skia software renderer) or headless TUI
./target/release/sds-installer gui
./target/release/sds-installer tui
```

### 3. Clean Uninstall

Every installed artifact (client app, host binaries/systemd units, installer binary, and optionally firewall rules + config/certs with `--purge-config`) can be cleanly removed:

```bash
# Via sds-installer CLI (or Tab 5 in the Native GUI / TUI)
sds-installer uninstall --component all --dry-run
sds-installer uninstall --component all --yes

# Or standalone scripts if sds-installer is already gone (macOS / Linux):
bash installer/bootstrap/uninstall.sh --component all --dry-run
bash installer/bootstrap/uninstall.sh --component all
```

On Windows:
```powershell
powershell -ExecutionPolicy Bypass -File installer\bootstrap\uninstall.ps1 -Component All -DryRun
```

## Verification & Open-Source Hygiene

```bash
# Rust installer fmt, clippy, unit/integration tests, and bootstrap checks
cd installer
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test --locked --all-targets
bash tests/test-bootstraps.sh

# Repository-wide PII, path, IP, and secret audit + Python tests
cd ..
python3 tools/audit-pii.py --strict --check-git-history
python3 -m unittest discover -s tests -v
python3 -m unittest discover -s tools/builder-sunshine-windows -p 'test_*.py' -v
```
