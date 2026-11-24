# Security Policy & Threat Model

## Cryptographic & Network Invariants

1. **Post-Quantum Transport (`X25519MLKEM768`):**
   - Paired HTTPS (`47984/tcp`) requires **TLS 1.3** with hybrid post-quantum key exchange (`X25519MLKEM768`). TLS 1.2 and classical-only key exchange are rejected.
   - Remote deployment and fingerprint out-of-band checks require PQ SSH (`mlkem768x25519-sha256` by default).
2. **Fail-Closed Media & Control:**
   - RTSP control handshake uses encrypted `rtspenc://` (`48010/tcp`); audio, video, input, and microphone UDP streams (`47998-48000`, `48002`) enforce `ENCFLG_ALL` (`lan_encryption_mode = 2`, `wan_encryption_mode = 2`) with AES-128-GCM.
   - Plain HTTP (`47989/tcp`) returns `404` for all `/sds/v1/*` routes and must be closed in the host firewall once client pairing completes.
3. **Loopback-Only Admin UI & Zero-WebView Native Installer:**
   - Sunshine's Web UI (`47990/tcp`) binds to loopback (`origin_web_ui_allowed = pc`), enforces `X-CSRF-Token`, and is blocked on external interfaces by firewall rules. Access it strictly through a local PQ SSH tunnel (`ssh -N -L 127.0.0.1:47990:127.0.0.1:47990 <host>`).
   - `sds-installer` runs as a **pure native Rust GUI** (`floem` with `tiny-skia` software rendering) or **terminal TUI** (`ratatui`/`crossterm` over SSH), eliminating browser/WebView/localhost HTTP/CSRF/XSS attack surfaces entirely.
4. **Least Privilege & File Containment:**
   - Newly paired clients start with **zero** SDS permissions (`clipboard_read`, `clipboard_write`, `file_upload`, `file_download`, `mic`).
   - Host inbox/outbox and staging paths enforce `0700` / protected Windows SDDL DACLs, `O_NOFOLLOW`, and UUID/SHA-256 containment.
   - **Systemd `NoNewPrivileges` Boundary:** Sunshine and private PipeWire services run with `NoNewPrivileges=true`, `LockPersonality=true`, `RestrictSUIDSGID=true`, and `InaccessiblePaths=-/run/docker.sock`. The Linux virtual display service (`sds-host-display.service`) intentionally omits `NoNewPrivileges` so users inside the authenticated virtual desktop session can run `sudo` normally.

## Unsigned & Self-Compiled Distribution Trust Model

- Paid Apple Developer ID or Windows Authenticode certificates are **not** required.
- All release downloads enforce HTTPS (`--tlsv1.2` minimum), manifest schema validation, exact byte-length bounds, SHA-256 verification, zip-slip/symlink/reparse-point rejection, and ELF/Mach-O/PE header checks before installation.
- Global macOS Gatekeeper and Windows SmartScreen are **never** disabled. Quarantine/MOTW removal (`xattr -dr com.apple.quarantine` or `Unblock-File`) occurs **only** on explicitly verified payloads when opted in via `--allow-unnotarized` / `-AllowUnsigned`.

## Reporting Vulnerabilities

Please inspect [DESIGN.md](docs/DESIGN.md) for protocol security invariants. Do not commit secrets, private keys, personal hostnames, or LAN captures in public issues or pull requests.
