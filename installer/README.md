# Secure Desktop Stream — Native Installer & Orchestrator (`sds-installer`)

A hardened cross-platform **pure native Rust** installer, dependency manager, cryptographic PQ verifier, fleet orchestrator, and uninstaller for **Secure Desktop Stream** (`Client + Host + 1 -> N PQ-SSH Deployment`).

- **Zero HTML / Zero WebView / Zero local HTTP server:**
  - Desktop GUI uses [`floem`](https://github.com/lapce/floem) with CPU software rendering (`FLOEM_FORCE_TINY_SKIA=1`, zero GPU/OpenGL driver requirement).
  - Headless / SSH Linux terminal fallback uses [`ratatui`](https://ratatui.rs) + `crossterm`.
- **Designed explicitly for unsigned / ad-hoc / self-compiled distributions** — no paid Apple Developer ID or Microsoft Authenticode certificates required.
- **Automatic dependency checks & installation (`deps`)** plus **manifest-verified clean uninstallation (`uninstall`)** via both `sds-installer` and standalone `bootstrap/uninstall.sh` / `uninstall.ps1`.

---

## Architecture

1. **CLI Bootstrappers (`bootstrap/`):**
   - `get.sh` — universal macOS/Linux entrypoint. Defaults to `--from-source` inside a repository checkout, or downloads & verifies release manifests/archives (`--release-base=https://...` / `--archive=... --sha256=...`). Supports `--auto-deps`.
   - `install-macos.sh` — builds or verifies `Secure Desktop Stream Installer.app`, enforces symlink/running-process checks, supports optional owner-only local signing config (`~/Library/Application Support/SecureDesktopStream/code-signing.json`), keeps global Gatekeeper enabled (quarantine removal only with explicit `--allow-unnotarized`), swaps atomically with rollback, and launches the native GUI.
   - `install-linux.sh` — POSIX `sh` installer (zero Python/jq required for release verification), checks 6-line `linux-latest.txt`, archive paths/sizes/symlinks, 64-bit ELF architecture (`x86_64` / `aarch64`), `--version` execution, `/proc/[0-9]*/exe` + `cmdline`, atomic swap + `.desktop` entry, and runs `tui` over SSH/headless or `gui` on desktop.
   - `install-windows.ps1` — PowerShell 5.1/7+ installer with pre-extraction zip-slip/entry/size validation via `System.IO.Compression.ZipFile`, Win32 P/Invoke SDDL DACLs, reparse-point checks, PE header validation (`0x8664` / `0xAA64`), immutable `versions\<tag>\` + atomic `current` directory junction swap, Start Menu `.lnk`, and explicit `-AllowUnsigned` `Unblock-File`.
   - `uninstall.sh` & `uninstall.ps1` — standalone uninstallers (delegate to `sds-installer uninstall` if present, or perform allowlisted fallback cleanup cleanly).
2. **Automatic Dependency Engine (`deps`):**
   - Inspects runtime & build dependencies for `client`, `client-build`, `host-virtual`, `host-physical`, `host-windows`, `host-build`, `installer-build`, or `all` (locally or remotely over PQ SSH) using Homebrew (macOS), `apt`/`dnf`/`pacman`/`zypper` (Linux), or `winget`/`choco` (Windows) with strictly allowlisted packages.
3. **Cryptographic Host Probe & Guided Pairing (`probe` / GUI Tab 4):**
   - Probes `47984/tcp` with `rustls` + `aws-lc-rs`: verifies **TLS 1.3 + `X25519MLKEM768`**, verifies classical KEX (`X25519`/`P-256`) and TLS 1.2 are rejected, confirms `47990/tcp` Web UI is closed externally, checks `47989/tcp`, and optionally compares the TLS cert SHA-256 against `cacert.pem` read over PQ SSH (`mlkem768x25519-sha256`).
4. **Hardened Host Profiles (`config_gen`) & Safe Uninstaller (`uninstall`):**
   - `linux-virtual-x11`, `linux-physical-x11`, `windows-host` with `ufw`, `firewalld`, `nftables`, and Windows Firewall setup & teardown rules (`remove_firewall`).
   - Manifest-tracked uninstall with strict allowlist path validation (`is_safe_sds_removal_path`) and optional `--purge-config`.

---

## Quick Usage

```bash
# Launch native GUI (desktop) or TUI (SSH / headless TTY)
bash installer/bootstrap/get.sh

# Check & install dependencies
sds-installer deps check --role all
sds-installer deps install --role client-build --execute-sudo

# Inspect local hardware, PQ SSH, toolchain & existing installs
sds-installer preflight --json

# Probe a host for PQ TLS 1.3 (X25519MLKEM768) & firewall exposure
sds-installer probe --host 192.168.1.50 --ssh user@linux-host

# Generate host configs & firewall commands cleanly
sds-installer gen-config --profile linux-virtual-x11 --controller-ip 192.168.1.10 --out ./out-config

# Dry-run client install from source (auto-checking deps)
sds-installer install-client --from-source --auto-deps --scope user --allow-unnotarized --dry-run

# Dry-run remote PQ-SSH fleet deployment
sds-installer deploy-ssh --ssh user@linux-host --host 192.168.1.50 --controller-ip 192.168.1.10 --profile linux-virtual-x11 --dry-run

# Clean uninstall (with optional config purge)
sds-installer uninstall --component all --dry-run
sds-installer uninstall --component all --yes
```

---

## Build & Test

```bash
cd installer
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test --locked --all-targets
bash tests/test-bootstraps.sh
```
