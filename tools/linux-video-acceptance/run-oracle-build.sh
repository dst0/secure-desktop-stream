#!/bin/bash
set -euo pipefail
umask 077
WORK_ROOT=${SDS_WORK_ROOT:-"$HOME/build/sds"}
RUN=$(cd "$(dirname "$0")" && pwd)
case "$RUN" in "$WORK_ROOT"/runs/moonlight-linux-video-*) ;; *) exit 2 ;; esac
test ! -e "$RUN/oracle-build-exit-status"
mkdir -p "$WORK_ROOT"
exec 9>"$WORK_ROOT/.build.lock"
flock -n 9 || exit 75
FFMPEG=${SDS_FFMPEG_DIR:-"$WORK_ROOT/ffmpeg"}
build() {
    local uid gid image run_id container_name
    uid=$(id -u)
    gid=$(id -g)
    [[ "$uid" -ne 0 ]] || { echo 'Refusing to run oracle build as root' >&2; exit 2; }
    [[ -f "$FFMPEG/lib/libavcodec.a" && -f "$FFMPEG/lib/libavutil.a" ]] || {
        echo "Missing FFmpeg static libs under $FFMPEG (set SDS_FFMPEG_DIR)" >&2
        exit 2
    }
    image=${SDS_ACCEPTANCE_IMAGE:-sds-sunshine-deps:26.04}
    image=$(docker image inspect "$image" --format '{{.Id}}')
    [[ -n "$image" ]] || exit 2
    mkdir -p "$RUN/oracle-build"
    python3 -I - "$RUN" <<'PY'
import pathlib, secrets, sys
(pathlib.Path(sys.argv[1]) / 'bind-nonce').write_text(secrets.token_hex(32))
PY
    local probe
    probe=$(docker run --rm --read-only --network=none --cap-drop=ALL --user="${uid}:${gid}" \
        --security-opt=no-new-privileges --mount "type=bind,src=$RUN/bind-nonce,dst=/probe,readonly" \
        --entrypoint=/bin/cat "$image" /probe)
    test "$probe" = "$(cat "$RUN/bind-nonce")"
    run_id=$(basename "$RUN")
    run_id=${run_id//[^A-Za-z0-9_.-]/-}
    container_name="sds-oracle-build-${run_id}"
    docker run --rm --name "$container_name" --read-only --network=none \
        --cap-drop=ALL --security-opt=no-new-privileges --cpus=2 --memory=2g --pids-limit=256 \
        --user="${uid}:${gid}" --tmpfs /tmp:rw,nosuid,nodev,size=256m \
        --tmpfs /state:rw,nosuid,nodev,uid="${uid}",gid="${gid}",mode=700,size=16m \
        --mount "type=bind,src=$RUN/source,dst=/source,readonly" \
        --mount "type=bind,src=$RUN,dst=/oracle,readonly" \
        --mount "type=bind,src=$RUN/oracle-build,dst=/build" \
        --mount "type=bind,src=$FFMPEG,dst=/ffmpeg,readonly" \
        --env HOME=/state --entrypoint=/bin/bash "$image" -c \
        'cmake -S /oracle -B /build -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=OFF && cmake --build /build --target sds-decode-oracle -j2 && /build/sds-decode-oracle --self-test'
    sha256sum "$RUN/oracle-build/sds-decode-oracle" > "$RUN/oracle-client-sha256"
}
set +e
(set -e; build) > "$RUN/oracle-build.log" 2>&1
status=$?
set -e
python3 -I - "$RUN" <<'PY'
import pathlib, sys, brotli
p = pathlib.Path(sys.argv[1]) / 'oracle-build.log'
p.with_suffix('.log.br').write_bytes(brotli.compress(p.read_bytes(), quality=6))
p.unlink()
PY
printf '%s\n' "$status" > "$RUN/oracle-build-exit-status.tmp"
mv "$RUN/oracle-build-exit-status.tmp" "$RUN/oracle-build-exit-status"
exit "$status"
