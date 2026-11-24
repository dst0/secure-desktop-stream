#!/usr/bin/env bash
# Cross-build a Sunshine checkout for Windows x64 on a remote Linux build host
# (set SDS_BUILD_HOST=user@linux-builder) inside the sds-sunshine-windows-cross image.
#
# Usage: SDS_BUILD_HOST=user@linux-builder tools/builder-sunshine-windows/remote-build-windows.sh <sunshine-dir> [options]
#   --package          cpack ZIP + NSIS installer and check DLL imports (default: build only)
#   --tests            also build tests/test_sunshine.exe (runs only on Windows)
#   --reconfigure      rerun the CMake configure step
#   --fetch            copy the packages back to <repo>/out/windows/
#   --image=TAG        image tag (default: newest sds-sunshine-windows-cross tag on the host)
#   --cpus=N           CPU cap (default 2)
set -euo pipefail
if (( $# < 1 )); then
  echo "Usage: SDS_BUILD_HOST=user@linux-builder $0 <sunshine-dir> [--package] [--tests] [--reconfigure] [--fetch] [--image=TAG] [--cpus=N]" >&2
  exit 2
fi
WT=$(cd "$1" && pwd); shift
BUILDER_DIR=$(cd "$(dirname "$0")" && pwd)
HOST=${SDS_BUILD_HOST:-}
if [[ -z "$HOST" ]]; then
  echo "error: SDS_BUILD_HOST is required (e.g. SDS_BUILD_HOST=user@linux-builder)" >&2
  exit 2
fi
CPUS=${CPUS:-2}; MEM=${MEM:-5g}; TAG=""; FETCH=0; ARGS=()
AUTO_DEPS=${SDS_AUTO_INSTALL_DEPS:-1}
for a in "$@"; do
  case $a in
    --package|--portable-package|--tests|--reconfigure) ARGS+=("$a") ;;
    --fetch) FETCH=1 ;;
    --image=*) TAG="${a#--image=}" ;;
    --cpus=*) CPUS="${a#--cpus=}" ;;
    *) echo "unknown arg $a" >&2; exit 2 ;;
  esac
done
NAME=$(basename "$WT")
REMOTE_BASE='build/sds/src'
REMOTE="$REMOTE_BASE/$NAME"
OUT_REMOTE="build/sds/out/windows/$NAME"
BRANCH=$(git -C "$WT" rev-parse --abbrev-ref HEAD)
COMMIT=$(git -C "$WT" rev-parse HEAD)
VERSION=${BUILD_VERSION:-$(git -C "$WT" describe --tags --abbrev=0 2>/dev/null | sed 's/^v//')}

[[ $HOST =~ ^[A-Za-z0-9._-]+(@[A-Za-z0-9._-]+)?$ ]] || { echo "invalid host: $HOST" >&2; exit 2; }
[[ $NAME =~ ^[A-Za-z0-9._-]+$ && $NAME != "." && $NAME != ".." ]] || { echo "invalid worktree name: $NAME" >&2; exit 2; }
[[ $CPUS =~ ^[1-9][0-9]*$ ]] || { echo "invalid cpu count: $CPUS" >&2; exit 2; }
[[ $MEM =~ ^[1-9][0-9]*[kmgKMG]?$ ]] || { echo "invalid memory limit: $MEM" >&2; exit 2; }
[[ $BRANCH =~ ^[A-Za-z0-9._/-]+$ && $BRANCH != *..* ]] || { echo "invalid branch: $BRANCH" >&2; exit 2; }
[[ $COMMIT =~ ^[0-9a-f]{40}$ ]] || { echo "invalid commit: $COMMIT" >&2; exit 2; }
[[ -z $VERSION || $VERSION =~ ^[A-Za-z0-9.+_-]+$ ]] || { echo "invalid build version: $VERSION" >&2; exit 2; }
[[ $AUTO_DEPS == 0 || $AUTO_DEPS == 1 ]] || { echo "invalid SDS_AUTO_INSTALL_DEPS: $AUTO_DEPS" >&2; exit 2; }

SSH_OPTS=(
  -o BatchMode=yes
  -o StrictHostKeyChecking=yes
  -o IdentitiesOnly=yes
  -o ForwardAgent=no
  -o KexAlgorithms=mlkem768x25519-sha256,sntrup761x25519-sha512@openssh.com,sntrup761x25519-sha512
)
printf -v RSH '%s ' ssh "${SSH_OPTS[@]}"

if [ -z "$TAG" ]; then
  TAG=$(ssh "${SSH_OPTS[@]}" -- "$HOST" "docker images sds-sunshine-windows-cross --format '{{.CreatedAt}}\t{{.Tag}}' | LC_ALL=C sort -r | head -1 | cut -f2-")
  if [ -z "$TAG" ]; then
    if [ "$AUTO_DEPS" = 1 ]; then
      ssh "${SSH_OPTS[@]}" -- "$HOST" "mkdir -p ~/build/sds/win-cross/builder-auto"
      rsync -a -e "${RSH% }" "$BUILDER_DIR/" "$HOST:build/sds/win-cross/builder-auto/"
      ssh "${SSH_OPTS[@]}" -- "$HOST" "CPUS='$CPUS' MEM='$MEM' bash ~/build/sds/win-cross/builder-auto/build-image.sh"
      TAG=$(ssh "${SSH_OPTS[@]}" -- "$HOST" "docker images sds-sunshine-windows-cross --format '{{.CreatedAt}}\t{{.Tag}}' | LC_ALL=C sort -r | head -1 | cut -f2-")
    fi
    [ -n "$TAG" ] || { echo "no sds-sunshine-windows-cross image on $HOST; run build-image.sh there first" >&2; exit 1; }
  fi
fi
[[ $TAG =~ ^[A-Za-z0-9._-]+$ ]] || { echo "invalid image tag: $TAG" >&2; exit 2; }

SDS_HELPER_FILES=(
  toolchain-mingw-ucrt64.cmake
  qt-host-moc.cmake
  case-aliases.py
  build-sunshine-windows.sh
  check-windows-deps.sh
  export-native-tests.py
  collect-native-fixtures.py
  prepare-ffmpeg.py
  verify-qt-static.sh
)
LOCAL_HELPERS_SHA=$(cd "$BUILDER_DIR" && cat "${SDS_HELPER_FILES[@]}" | shasum -a 256 | awk '{print $1}')
IMAGE_STATE=$(ssh "${SSH_OPTS[@]}" -- "$HOST" "docker run --rm --entrypoint bash sds-sunshine-windows-cross:$TAG -c 'cc_ok=0; [ -x /usr/bin/cc ] && cc_ok=1; h=\$(cd /opt/sds && cat ${SDS_HELPER_FILES[*]} 2>/dev/null | sha256sum | cut -d\" \" -f1 || true); printf \"%s %s\\n\" \"\$cc_ok\" \"\$h\"'")
IMAGE_CC_OK=${IMAGE_STATE%% *}
IMAGE_SCRIPT_SHA=${IMAGE_STATE#* }
if [ "$IMAGE_CC_OK" != "1" ] || [ "$IMAGE_SCRIPT_SHA" != "$LOCAL_HELPERS_SHA" ]; then
  if [ "$AUTO_DEPS" != 1 ]; then
    echo "image sds-sunshine-windows-cross:$TAG lacks /usr/bin/cc or has stale /opt/sds helpers (SDS_AUTO_INSTALL_DEPS=0)" >&2
    exit 1
  fi
  DERIVED_TAG="${TAG%-rusthost}-rusthost"
  printf -v q_derived_tag '%q' "$DERIVED_TAG"
  ssh "${SSH_OPTS[@]}" -- "$HOST" "mkdir -p ~/build/sds/win-cross/rusthost-ctx"
  (cd "$BUILDER_DIR" && rsync -a -e "${RSH% }" "${SDS_HELPER_FILES[@]}" "$HOST:build/sds/win-cross/rusthost-ctx/")
  ssh "${SSH_OPTS[@]}" -- "$HOST" "set -e
    cd ~/build/sds/win-cross/rusthost-ctx
    cat > Dockerfile <<EOF
FROM sds-sunshine-windows-cross:$TAG
USER root
RUN if [ ! -x /usr/bin/cc ]; then apt-get update && apt-get install -y --no-install-recommends gcc libc6-dev && rm -rf /var/lib/apt/lists/*; fi
COPY ${SDS_HELPER_FILES[*]} /opt/sds/
RUN chmod 0755 /opt/sds/*.sh /opt/sds/*.py
EOF
    flock ~/build/sds/.build.lock env DOCKER_BUILDKIT=0 docker build --force-rm \
      --cpu-period=100000 --cpu-quota=$((CPUS * 100000)) --memory='$MEM' --memory-swap='$MEM' \
      -t sds-sunshine-windows-cross:$q_derived_tag .
  "
  TAG="$DERIVED_TAG"
fi

# Ensure Rust + Windows GNU target exist on $HOST.
ssh "${SSH_OPTS[@]}" -- "$HOST" "set -e
export PATH=\"\$HOME/.cargo/bin:\$PATH\"
if ! command -v cargo >/dev/null 2>&1 || ! command -v rustc >/dev/null 2>&1; then
  if [ '$AUTO_DEPS' = 1 ]; then
    if ! command -v rustup >/dev/null 2>&1; then
      sudo -n apt-get update -qq && sudo -n apt-get install -y --no-install-recommends rustup
    fi
    rustup toolchain install stable --profile minimal --target x86_64-pc-windows-gnu
  else
    echo 'Rust toolchain missing on $HOST and SDS_AUTO_INSTALL_DEPS=0' >&2; exit 1
  fi
elif command -v rustup >/dev/null 2>&1 && ! rustup target list --installed | grep -Fxq x86_64-pc-windows-gnu; then
  if [ '$AUTO_DEPS' = 1 ]; then
    rustup target add x86_64-pc-windows-gnu
  else
    echo 'Rust target x86_64-pc-windows-gnu missing on $HOST and SDS_AUTO_INSTALL_DEPS=0' >&2; exit 1
  fi
fi
"

printf -v q_base '%q' "$REMOTE_BASE"
printf -v q_name '%q' "$NAME"
printf -v q_remote '%q' "$REMOTE"
printf -v q_out_remote '%q' "$OUT_REMOTE"
printf -v q_cpus '%q' "$CPUS"
printf -v q_mem '%q' "$MEM"
printf -v q_version '%q' "$VERSION"
printf -v q_branch '%q' "$BRANCH"
printf -v q_commit '%q' "$COMMIT"
printf -v q_tag '%q' "$TAG"
q_args=""
if ((${#ARGS[@]})); then
  for arg in "${ARGS[@]}"; do
    printf -v q_arg '%q' "$arg"
    q_args+=" $q_arg"
  done
fi

ssh "${SSH_OPTS[@]}" -- "$HOST" "set -e; cd -- \"\$HOME/\"$q_base; if [ ! -d $q_name ]; then mkdir -- $q_name && rsync -a --exclude=/build --exclude=/node_modules --link-dest=\"\$HOME/\"$q_base/sunshine-base/ sunshine-base/ $q_name/; fi"
( cd "$WT" && git ls-files --recurse-submodules -z ) | rsync -a -e "${RSH% }" --from0 --files-from=- -- "$WT"/ "$HOST:$REMOTE/"
stale_prune=()
[[ -e "$WT/src_assets/common/assets/web/Featured.vue" ]] || stale_prune+=("$REMOTE/src_assets/common/assets/web/Featured.vue")
[[ -e "$WT/third-party/Simple-Web-Server" ]] || stale_prune+=("$REMOTE/third-party/Simple-Web-Server")
if ((${#stale_prune[@]})); then
  printf -v q_prune '%q ' "${stale_prune[@]}"
  ssh "${SSH_OPTS[@]}" -- "$HOST" "rm -rf -- $q_prune"
fi

ssh "${SSH_OPTS[@]}" -- "$HOST" "mkdir -p -- \"\$HOME/\"$q_out_remote ~/build/sds/win-cross/cache/npm && cd ~/build/sds && {
  RUST_ARGS=()
  if [ -d \"\$HOME/.rustup\" ] && [ -d \"\$HOME/.cargo\" ]; then
    RUST_ARGS+=(-e RUSTUP_HOME=/rustup -e CARGO_HOME=/cargo -v \"\$HOME/.rustup:/rustup:ro\" -v \"\$HOME/.cargo:/cargo\")
  fi
  flock .build.lock \
    docker run --rm --user \"\$(id -u):\$(id -g)\" --cap-drop=ALL --security-opt=no-new-privileges --cpus=$q_cpus --memory=$q_mem --pids-limit=512 --cpu-shares=256 \
      -e HOME=/tmp -e npm_config_cache=/cache/npm \
      -e BUILD_VERSION=$q_version -e BRANCH=$q_branch -e COMMIT=$q_commit \
      \"\${RUST_ARGS[@]}\" \
      -v \"\$HOME/\"$q_remote:/src -v \"\$HOME/\"$q_out_remote:/out -v \"\$HOME/build/sds/win-cross/cache/npm:/cache/npm\" \
      sds-sunshine-windows-cross:$q_tag \
      /opt/sds/build-sunshine-windows.sh --jobs=$q_cpus --out=/out$q_args
}"

echo "artifacts on $HOST:~/$OUT_REMOTE"
ssh "${SSH_OPTS[@]}" -- "$HOST" "ls -la -- \"\$HOME/\"$q_out_remote"
if [ "$FETCH" = 1 ]; then
  OUT="$(cd "$(dirname "$0")/../.." && pwd)/out/windows"; mkdir -p "$OUT"
  scp "${SSH_OPTS[@]}" -q -- "$HOST:$OUT_REMOTE/Sunshine-Windows-AMD64-*" "$HOST:$OUT_REMOTE/SHA256SUMS" "$OUT/"
  (cd "$OUT" && shasum -a 256 -c SHA256SUMS)
  ls -la "$OUT"
fi
