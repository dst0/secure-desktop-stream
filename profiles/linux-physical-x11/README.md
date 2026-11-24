# Profile: Linux Physical X11 (`linux-physical-x11`)

Streams an active physical/EDID X11 desktop session with `/dev/uinput` permissions, microphone priority routing, and `picom` `xrender` compositor stability.

## Important Stability Note (`picom`)

If your desktop environment runs `picom`, ensure `backend = "xrender"` (see [`picom-xrender.conf`](picom-xrender.conf)). Using `backend = "glx"` alongside Sunshine `x11grab` and hardware-accelerated fullscreen video playback can trigger X11 frame freezes.

## Generating a Concrete Instance Bundle

```bash
sds-installer gen-config \
  --profile linux-physical-x11 \
  --controller-ip 192.168.1.10 \
  --instance-name sds-host \
  --resolution 1920x1080 \
  --out ./generated-physical-bundle
```
