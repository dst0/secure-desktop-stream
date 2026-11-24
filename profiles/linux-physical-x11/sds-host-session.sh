#!/bin/bash
set -euo pipefail
umask 077

INSTANCE_NAME=${SDS_INSTANCE:-sds-host}
SUNSHINE_UNIT=${SDS_SUNSHINE_UNIT:-${INSTANCE_NAME}-sunshine.service}
TARGET_MODE=${SDS_RESOLUTION:-1920x1080}

[[ ${XDG_SESSION_TYPE:-} == x11 && -n ${XDG_RUNTIME_DIR:-} ]]
[[ ${DISPLAY:-} =~ ^:[0-9]+(\.[0-9]+)?$ ]]
authority=${XAUTHORITY:-$HOME/.Xauthority}
[[ -f "$authority" && -O "$authority" && -r "$authority" ]]
export XAUTHORITY="$authority"

monitors=$(/usr/bin/xrandr --listactivemonitors)
if [[ "$monitors" == 'Monitors: 0' ]]; then
  output=$(/usr/bin/xrandr --query | awk '/ connected/ {print $1; exit}')
  if [[ -n "$output" ]]; then
    /usr/bin/xrandr --output "$output" --mode "$TARGET_MODE" --primary
  fi
fi
monitors=$(/usr/bin/xrandr --listactivemonitors)
grep -Eq '^Monitors: [1-9][0-9]*$' <<<"$monitors"

env_file=$(mktemp "$XDG_RUNTIME_DIR/.${INSTANCE_NAME}-sunshine.XXXXXXXX")
trap 'rm -f -- "$env_file"' EXIT
printf 'DISPLAY=%s\nXAUTHORITY=%s\n' "$DISPLAY" "$XAUTHORITY" >"$env_file"
mv -T -- "$env_file" "$XDG_RUNTIME_DIR/${INSTANCE_NAME}-sunshine.env"
exec /usr/bin/systemctl --user start "$SUNSHINE_UNIT"
