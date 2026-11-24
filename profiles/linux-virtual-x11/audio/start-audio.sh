#!/usr/bin/env bash
set -euo pipefail
umask 077
: "${RUNTIME_DIRECTORY:?start with a dedicated private runtime directory}"
: "${XDG_CONFIG_HOME:?set the dedicated audio config directory}"
: "${XDG_STATE_HOME:?set the dedicated audio state directory}"
[[ -d $RUNTIME_DIRECTORY && ! -L $RUNTIME_DIRECTORY && $(stat -c %u:%a "$RUNTIME_DIRECTORY") == "$UID:700" ]]

OUTPUT_SINK=${SDS_OUTPUT_SINK:-sds-host-output}

export GIO_USE_VFS=local
export XDG_RUNTIME_DIR=$RUNTIME_DIRECTORY
export PIPEWIRE_RUNTIME_DIR=$RUNTIME_DIRECTORY
export PIPEWIRE_REMOTE=pipewire-0
export PULSE_RUNTIME_PATH=$RUNTIME_DIRECTORY/pulse
export PULSE_SERVER=unix:$PULSE_RUNTIME_PATH/native

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

pipewire &
pids+=("$!")
for ((attempt=0; attempt<100; attempt++)); do
    [[ -S $RUNTIME_DIRECTORY/pipewire-0 ]] && break
    kill -0 "${pids[0]}"
    sleep .1
done
[[ -S $RUNTIME_DIRECTORY/pipewire-0 ]]

wireplumber --profile=sds-private &
pids+=("$!")
pipewire-pulse &
pids+=("$!")

for ((attempt=0; attempt<100; attempt++)); do
    if [[ -S $PULSE_RUNTIME_PATH/native ]] &&
        wpctl status -n | grep -F "$OUTPUT_SINK" >/dev/null; then
        NOTIFY_SOCKET="$notify_sock" systemd-notify --ready
        wait -n "${pids[@]}"
        exit 1
    fi
    kill -0 "${pids[@]}"
    sleep .1
done

printf 'Private audio graph failed readiness\n' >&2
exit 1
