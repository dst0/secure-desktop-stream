#!/usr/bin/env bash
set -euo pipefail
umask 077
: "${RUNTIME_DIRECTORY:?start through systemd display service}"
: "${XAUTHORITY:?set service Xauthority path}"
[[ -d $RUNTIME_DIRECTORY && ! -L $RUNTIME_DIRECTORY && $(stat -c %u:%a "$RUNTIME_DIRECTORY") == "$UID:700" ]]

DISPLAY_TARGET=${SDS_DISPLAY:-:97}
DISPLAY_NUM=${DISPLAY_TARGET#:}
INSTANCE_PROFILE=${SDS_INSTANCE:-sds-host}
INIT_MODE=${SDS_RESOLUTION:-1920x1080}
INIT_W=${INIT_MODE%x*}
INIT_H=${INIT_MODE#*x}

[[ $DISPLAY == "$DISPLAY_TARGET" && $XAUTHORITY == "$RUNTIME_DIRECTORY/Xauthority" ]]
[[ ! -e $XAUTHORITY && ! -L $XAUTHORITY ]]
install -m 0600 /dev/null "$XAUTHORITY"
printf 'add %s MIT-MAGIC-COOKIE-1 %s\n' "$DISPLAY" "$(mcookie)" | xauth -q -f "$XAUTHORITY"

notify_sock=${NOTIFY_SOCKET:-}
unset NOTIFY_SOCKET

pids=()
cleanup() {
    trap - EXIT
    if ((${#pids[@]})); then
        kill "${pids[@]}" 2>/dev/null || true
        wait "${pids[@]}" 2>/dev/null || true
    fi
}
trap cleanup EXIT
trap 'exit 143' TERM INT

xorg_conf="$RUNTIME_DIRECTORY/xorg.conf"
cat > "$xorg_conf" <<EOF
Section "ServerFlags"
    Option "AutoAddDevices" "false"
    Option "AllowEmptyInput" "true"
    Option "DontVTSwitch" "true"
    Option "DontZap" "true"
EndSection
Section "Device"
    Identifier "DummyCard"
    Driver "dummy"
    VideoRam 262144
EndSection
Section "Monitor"
    Identifier "DummyMonitor"
    HorizSync 5.0 - 1000.0
    VertRefresh 5.0 - 240.0
EndSection
Section "Screen"
    Identifier "DummyScreen"
    Device "DummyCard"
    Monitor "DummyMonitor"
    DefaultDepth 24
    SubSection "Display"
        Depth 24
        Virtual 4096 4096
        Modes "$INIT_MODE"
    EndSubSection
EndSection
EOF

/usr/lib/xorg/Xorg "$DISPLAY" -config "$xorg_conf" -logfile "$RUNTIME_DIRECTORY/Xorg.${DISPLAY_NUM}.log" -nolisten tcp -noreset -auth "$XAUTHORITY" &
x_pid=$!
pids+=("$x_pid")
ready=0
for ((attempt=0; attempt<80; attempt++)); do
    if xdpyinfo >/dev/null 2>&1; then
        ready=1
        break
    fi
    kill -0 "$x_pid"
    sleep .1
done
(( ready == 1 ))

[[ -f "/tmp/.X${DISPLAY_NUM}-lock" && ! -L "/tmp/.X${DISPLAY_NUM}-lock" && $(stat -c %u "/tmp/.X${DISPLAY_NUM}-lock") == "$UID" ]]
[[ $(tr -d '[:space:]' < "/tmp/.X${DISPLAY_NUM}-lock") == "$x_pid" ]]
[[ -d /tmp/.X11-unix && ! -L /tmp/.X11-unix ]]
[[ -S "/tmp/.X11-unix/X${DISPLAY_NUM}" && ! -L "/tmp/.X11-unix/X${DISPLAY_NUM}" && $(stat -c %u "/tmp/.X11-unix/X${DISPLAY_NUM}") == "$UID" ]]

xrandr --output DUMMY0 --mode "$INIT_MODE" >/dev/null
xset s off -dpms >/dev/null 2>&1 || true

openbox &
wm_pid=$!
pids+=("$wm_pid")
pcmanfm-qt --desktop --profile "$INSTANCE_PROFILE" &
desktop_pid=$!
pids+=("$desktop_pid")
lxqt-panel &
panel_pid=$!
pids+=("$panel_pid")

mapped_window() {
    local tree=$1 class=$2 geometry=$3 window
    while read -r window; do
        if xwininfo -id "$window" | grep 'Map State: IsViewable' >/dev/null; then
            return 0
        fi
    done < <(awk -v class="$class" -v geometry="$geometry" 'tolower($0) ~ class && $0 ~ geometry && $1 ~ /^0x[[:xdigit:]]+$/ {print $1}' <<<"$tree")
    return 1
}

for ((attempt=0; attempt<160; attempt++)); do
    tree=$(xwininfo -root -tree 2>/dev/null || true)
    if xprop -root _NET_SUPPORTING_WM_CHECK | grep 'window id #' >/dev/null &&
        mapped_window "$tree" '"lxqt-panel"' " ${INIT_W}x[1-9][0-9]+[+-]" &&
        mapped_window "$tree" '"pcmanfm-qt"' " ${INIT_W}x${INIT_H}[+-]"; then
        NOTIFY_SOCKET="$notify_sock" systemd-notify --ready
        wait -n "$x_pid" "$wm_pid" "$desktop_pid" "$panel_pid"
        exit 1
    fi
    kill -0 "$x_pid" "$wm_pid" "$desktop_pid" "$panel_pid"
    sleep .1
done

printf 'Virtual desktop did not become ready\n' >&2
exit 1
