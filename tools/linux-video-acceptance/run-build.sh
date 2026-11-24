#!/bin/bash
# Invoke only after the shared heavy-build lock is available.
set -euo pipefail
umask 077
WORK_ROOT=${SDS_WORK_ROOT:-"$HOME/build/sds"}
RUN=$(cd "$(dirname "$0")" && pwd)
case "$RUN" in
    "$WORK_ROOT"/runs/moonlight-linux-video-*) ;;
    *) echo "Refusing a non-task build directory (expected under $WORK_ROOT/runs/moonlight-linux-video-*)" >&2; exit 2 ;;
esac
test ! -e "$RUN/exit-status"
mkdir -p "$WORK_ROOT"
exec 9>"$WORK_ROOT/.build.lock"
if ! flock -n 9; then
    echo 'Shared build slot is busy; wait before launching' >&2
    exit 75
fi

build() {
    local uid gid base image run_id container_name
    uid=$(id -u)
    gid=$(id -g)
    [[ "$uid" -ne 0 ]] || { echo 'Refusing to run container build as root' >&2; exit 2; }
    test "$(df -Pk "$RUN" | awk 'NR==2 {print $4}')" -ge 8388608
    base=${SDS_ACCEPTANCE_IMAGE:-sds-sunshine-deps:26.04}
    image=$(docker image inspect "$base" --format '{{.Id}}')
    [[ -n "$image" ]] || { echo "Missing Docker base image: $base" >&2; exit 2; }
    run_id=$(basename "$RUN")
    run_id=${run_id//[^A-Za-z0-9_.-]/-}
    DOCKER_BUILDKIT=0 docker build --memory=4g --cpu-period=100000 --cpu-quota=200000 \
        --build-arg SDS_BASE_IMAGE="$base" \
        -t "sds-moonlight-linux-video:$run_id" "$RUN"
    image=$(docker image inspect "sds-moonlight-linux-video:$run_id" --format '{{.Id}}')
    printf '%s\n' "$image" > "$RUN/image-id"
    mkdir -p "$RUN/build"
    python3 -I - "$RUN" <<'PY'
import pathlib, secrets, sys
p = pathlib.Path(sys.argv[1]) / 'bind-nonce'
p.write_text(secrets.token_hex(32))
PY
    local probe
    probe=$(docker run --rm --read-only --network=none --cap-drop=ALL \
        --security-opt=no-new-privileges --user="${uid}:${gid}" \
        --mount "type=bind,src=$RUN/bind-nonce,dst=/probe,readonly" \
        --entrypoint=/bin/cat "$image" /probe)
    test "$probe" = "$(cat "$RUN/bind-nonce")"
    container_name="sds-moonlight-build-${run_id}"
    docker run --rm --name "$container_name" --read-only --network=none \
        --cap-drop=ALL --security-opt=no-new-privileges --user="${uid}:${gid}" \
        --cpus=2 --memory=4g --pids-limit=256 \
        --tmpfs /tmp:rw,nosuid,nodev,size=512m \
        --mount "type=bind,src=$RUN/source,dst=/source,readonly" \
        --mount "type=bind,src=$RUN/build,dst=/build" \
        --mount "type=bind,src=$RUN/build-inside.sh,dst=/build-inside.sh,readonly" \
        "$image" /build-inside.sh
    docker run --rm --read-only --network=none --cap-drop=ALL \
        --security-opt=no-new-privileges --entrypoint=dpkg-query "$image" -W \
        > "$RUN/package-versions.txt"
    sha256sum "$RUN/build/app/moonlight" > "$RUN/client-sha256"
}

# Logs are closed before compression; status is published only after log closure.
set +e
(set -e; build) > "$RUN/build.log" 2>&1
status=$?
set -e
if command -v brotli >/dev/null 2>&1; then
    if brotli -q 6 -f "$RUN/build.log"; then
        rm "$RUN/build.log"
    fi
fi
printf '%s\n' "$status" > "$RUN/exit-status.tmp"
mv "$RUN/exit-status.tmp" "$RUN/exit-status"
exit "$status"
