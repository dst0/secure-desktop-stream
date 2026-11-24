# Host Deployment Profiles

Generic, parameterized reference configurations for all supported **Secure Desktop Stream** host setups.

> In normal usage you do **not** need to edit these files manually — run `sds-installer gen-config` (or use the Native GUI / TUI wizard) to render a ready-to-install bundle with your chosen `--instance-name`, `--controller-ip`, `--display`, `--resolution`, `--encoder`, and `--firewall` backend.

## Available Profiles

| Profile | Directory | Use Case |
| --- | --- | --- |
| **Linux Virtual X11** | [`linux-virtual-x11/`](linux-virtual-x11/README.md) | Headless or isolated virtual desktop (`Xorg + dummy` up to `4096x4096` + Openbox + LXQt `QuickExec=true` + private PipeWire/WirePlumber + `NoNewPrivileges` split so `sudo` works inside the virtual desktop). |
| **Linux Physical X11** | [`linux-physical-x11/`](linux-physical-x11/README.md) | Physical X11 session capture with `/dev/uinput` udev rules, mic priority, and `picom` `xrender` compositor stability config (avoiding `glx` freezes). |
| **Windows Host** | [`windows-host/`](windows-host/README.md) | Windows 10/11 host with protected SDDL directory ACLs, `RemoteAddress`-scoped Defender Firewall rules, and clean `-Uninstall` support. |
