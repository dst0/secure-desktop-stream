# Profile: Linux Virtual X11 (`linux-virtual-x11`)

Isolated headless virtual desktop using rootless `Xorg` (`dummy` driver), `Openbox`, `LXQt`, and an isolated `PipeWire` + `WirePlumber` audio graph.

## Highlights

- **Rootless Xorg + `dummy`:** Allows live `XRandR` resolution changes up to `4096x4096` from Moonlight without touching any physical display.
- **No `pcmanfm-qt` Confirmation Popups:** `lxqt/pcmanfm-qt/sds-host/settings.conf` sets `QuickExec=true` so desktop/menu `.desktop` launchers open immediately on double-click, and `lxqt/user-dirs.dirs` isolates the virtual `Desktop` directory (`~/.local/share/sds-host-desktop/Desktop`).
- **Private Audio Drop-In:** Install `systemd/drop-ins/20-private-audio.conf` into **both** `~/.config/systemd/user/sds-host-display.service.d/` and `~/.config/systemd/user/sds-host-sunshine.service.d/` so desktop applications launched inside the virtual desktop and Sunshine share the isolated PipeWire/Pulse sockets.
- **Systemd `NoNewPrivileges` Boundary:**
  - `sds-host-sunshine.service` and `sds-host-audio.service` enforce `NoNewPrivileges=true`, `LockPersonality=true`, `RestrictSUIDSGID=true`, and `InaccessiblePaths=-/run/docker.sock`.
  - `sds-host-display.service` intentionally omits `NoNewPrivileges` so interactive `sudo` works inside terminals launched on the virtual desktop.

## Manual Template Placement Summary

If applying templates manually instead of using `sds-installer gen-config`:
- Privileged scripts & audio config under `/opt/secure-desktop-stream-sds-host/` (`start-display.sh` mode `0755`, `audio/` subtree).
- User units in `~/.config/systemd/user/` (`sds-host-audio.service`, `sds-host-display.service`, `sds-host-sunshine.service`), plus drop-ins under both `sds-host-display.service.d/` and `sds-host-sunshine.service.d/`.
- Private LXQt configs in `~/.config/sds-host-desktop/` (`lxqt/lxqt.conf`, `lxqt/panel.conf`, `pcmanfm-qt/sds-host/settings.conf`, `user-dirs.dirs`) and PipeWire mic priority rule in `~/.config/sds-host-sunshine/config/pipewire/client.conf.d/50-sds-microphone-priority.conf`.

## Generating a Concrete Instance Bundle

```bash
sds-installer gen-config \
  --profile linux-virtual-x11 \
  --controller-ip 192.168.1.10 \
  --instance-name sds-host \
  --display :97 \
  --resolution 1920x1080 \
  --out ./generated-host-bundle
```
