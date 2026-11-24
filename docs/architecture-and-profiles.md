# Architecture, Streaming Enhancements & Host Profiles

This document summarizes the architectural enhancements across the Secure Desktop Stream forks and the three generic host deployment profiles under [`profiles/`](../profiles/).

## 1. Host Profiles

### A. `linux-virtual-x11` (Headless / Isolated Virtual Desktop)
- **Display server:** Rootless `Xorg` with the `dummy` video driver (`VideoRam 262144`, `Virtual 4096 4096`), `Openbox` window manager, `lxqt-panel`, and `pcmanfm-qt` desktop.
  - Uses `QuickExec=true` in `pcmanfm-qt` (`settings.conf`) so `.desktop` launchers open directly without confirmation popups.
  - Because the `dummy` driver owns the display lock inside the rootless X server, **XRandR dynamic resolution switching** up to `4096x4096` works automatically when requested by a Moonlight client.
- **Private Audio Graph:** Isolated per-instance `pipewire`, `wireplumber --profile=sds-private`, and `pipewire-pulse` daemons bound to `%t/<instance>-audio`, creating a dedicated virtual output sink (`<instance>-output`) with `pulse.allow-module-loading = false` and mic priority rules (`priority.session = 3000`).
- **Systemd `NoNewPrivileges` Split:**
  - `sds-host-sunshine.service` and `sds-host-audio.service` enforce `NoNewPrivileges=true`, `LockPersonality=true`, `RestrictSUIDSGID=true`, `SystemCallArchitectures=native`, and `InaccessiblePaths=-/run/docker.sock`.
  - `sds-host-display.service` intentionally **omits** `NoNewPrivileges=true` so interactive `sudo` commands inside terminals on the virtual desktop continue to function.

### B. `linux-physical-x11` (Physical Monitor / EDID Session)
- Attaches Sunshine to an existing X11 session (`DISPLAY` + `XAUTHORITY`), installing `/etc/udev/rules.d/60-sds-uinput.rules` (`MODE="0660", TAG+="uaccess"`) for `/dev/uinput` virtual input.
- **Compositor Stability (`picom`):** If running `picom` on X11 alongside Sunshine `x11grab`, configure `backend = "xrender"` (see [`profiles/linux-physical-x11/picom-xrender.conf`](../profiles/linux-physical-x11/picom-xrender.conf)). Using `backend = "glx"` can trigger X11 frame freezes during fullscreen hardware-accelerated video playback in browsers.

### C. `windows-host`
- Applies `origin_web_ui_allowed = pc`, mandatory LAN/WAN encryption (`2`), UPnP/mDNS disabled, protected SDDL DACLs on `Downloads\Moonlight`, `Outbox`, and config folders, and Windows Defender Firewall rules strictly scoped via `-RemoteAddress <controller_ip>`.

---

## 2. Streaming & Protocol Enhancements

1. **Hardware-Accelerated Packed 4:4:4 (`YCoCg-R` over 10-bit `P010` HEVC Main10):**
   - Many consumer GPUs (including AMD VCN) only expose 4:2:0 (`NV12` / `P010`) hardware encode engines.
   - To deliver crisp 1-pixel colored UI text without 4:2:0 chroma subsampling smear, Sunshine encodes reversible integer **`YCoCg-R`** (`8-bit Y`, `9-bit Co`, `9-bit Cg` padded into 10-bit `P010` `[0..1023]`) inside a CTU-aligned **`1.5W x 2H`** luma-only frame layout (`UV` set to neutral `512` for near-zero chroma bitrate overhead).
   - Apple Silicon clients (`moonlight-qt`) decode `HEVC Main10` hardware frames via VideoToolbox (`kCVPixelBufferMetalCompatibilityKey = true`) and reconstruct crisp full-color RGB in a Metal fragment shader (`65535.0 / 64.0` sample scale + 4-tap RGB interpolation).
2. **Host GPU Adapter & Encoder Selection:**
   - Paired HTTPS `/serverinfo` advertises `<sdsAdapters>`, `<sdsEncoders>` (including `software` 4:4:4 fallback), and `<sdsSoftwareCodecModeSupport>`.
   - Clients can pass per-session overrides (`sdsAdapter`, `sdsEncoder`, `sdsHevc`, `sdsMatchRes`, `sdsRevertRes`) on `/launch` and `/resume`, cleanly reverting host state when the stream ends.
3. **Native Host Resolution Matching & File Clipboard / XDND:**
   - Optional host XRandR mode matching to the client's native/requested display dimensions (with optional revert on disconnect).
   - Unified lazy file & image copy/paste (`Cmd/Ctrl+C/V`) and X11 `XDND` drag-and-drop alongside chunked HTTPS file inbox/outbox.
