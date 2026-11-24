#!/usr/bin/env bash
# Runs ON the Linux build host. Builds Sunshine + .deb inside the
# sds-sunshine-deps:26.04 image with a CPU cap so other host services stay responsive.
# Usage: builder-sunshine-linux.sh <src-dir> <cpus> [extra linux_build.sh args...]
set -euo pipefail
if (( $# < 2 )); then
  echo "Usage: $0 <src-dir> <cpus> [extra linux_build.sh args...]" >&2
  exit 2
fi
SRC=${1:?source dir}; CPUS=${2:?cpus}; shift 2
[[ -d $SRC ]] || { echo "missing source dir: $SRC" >&2; exit 2; }
SRC=$(cd "$SRC" && pwd -P)
[[ $CPUS =~ ^[1-9][0-9]*$ ]] || { echo "invalid cpu count: $CPUS" >&2; exit 2; }
MEM=${MEM:-6g}
[[ $MEM =~ ^[1-9][0-9]*[kmgKMG]?$ ]] || { echo "invalid memory limit: $MEM" >&2; exit 2; }
VERSION=${BUILD_VERSION:-}
BRANCH=${BRANCH:-main}
COMMIT=${COMMIT:-}
[[ -z $VERSION || $VERSION =~ ^[A-Za-z0-9.+_-]+$ ]] || { echo "invalid build version: $VERSION" >&2; exit 2; }
[[ $BRANCH =~ ^[A-Za-z0-9._/-]+$ && $BRANCH != *..* ]] || { echo "invalid branch: $BRANCH" >&2; exit 2; }
[[ -z $COMMIT || $COMMIT =~ ^[0-9a-f]{7,64}$ ]] || { echo "invalid commit: $COMMIT" >&2; exit 2; }

NAME=${NAME:-sds-build-sunshine}
[[ $NAME =~ ^[A-Za-z0-9._-]+$ ]] || { echo "invalid container name: $NAME" >&2; exit 2; }
AUTO_DEPS=${SDS_AUTO_INSTALL_DEPS:-1}
[[ $AUTO_DEPS == 0 || $AUTO_DEPS == 1 ]] || { echo "invalid SDS_AUTO_INSTALL_DEPS: $AUTO_DEPS" >&2; exit 2; }
export PATH="$HOME/.cargo/bin:$PATH"
if ! command -v cargo >/dev/null 2>&1 || ! command -v rustc >/dev/null 2>&1; then
  if docker run --rm --entrypoint bash sds-sunshine-deps:26.04 -c 'command -v cargo >/dev/null 2>&1 && command -v rustc >/dev/null 2>&1'; then
    :
  elif [[ $AUTO_DEPS == 1 ]]; then
    if ! command -v rustup >/dev/null 2>&1; then
      sudo -n apt-get update -qq && sudo -n apt-get install -y --no-install-recommends rustup
    fi
    rustup toolchain install stable --profile minimal --target x86_64-unknown-linux-gnu
  else
    echo "Rust toolchain (cargo/rustc) is missing and SDS_AUTO_INSTALL_DEPS=0" >&2
    exit 1
  fi
fi
docker rm -f "$NAME" >/dev/null 2>&1 || true
RUST_DOCKER_ARGS=()
if [[ -d ${HOME:-}/.rustup && -d ${HOME:-}/.cargo ]]; then
  RUST_DOCKER_ARGS+=(
    -v "$HOME/.rustup:/rustup:ro"
    -v "$HOME/.cargo:/cargo"
    -e RUSTUP_HOME=/rustup
    -e CARGO_HOME=/cargo
  )
fi
docker run -d --name "$NAME" --user "$(id -u):$(id -g)" --cap-drop=ALL --security-opt=no-new-privileges \
  --cpus="$CPUS" --memory="$MEM" --pids-limit=512 --cpu-shares=256 \
  -e HOME=/tmp -e BUILD_VERSION="$VERSION" -e BRANCH="$BRANCH" -e COMMIT="$COMMIT" \
  -e DEBIAN_PACKAGE_RELEASE="1+sds+ubuntu26.04" -e SDS_CPUS="$CPUS" \
  "${RUST_DOCKER_ARGS[@]}" \
  -v "$SRC":/src -w /src sds-sunshine-deps:26.04 bash -c '
    set -e
    export PATH="/cargo/bin:$PATH"
    for s in cmake build package; do
      ./scripts/linux_build.sh --step="$s" --skip-cuda --sudo-off --num-processors="$SDS_CPUS" \
        --publisher-name="secure-desktop-stream fork" --publisher-website="https://localhost.invalid" \
        --publisher-issue-url="https://localhost.invalid" "$@"
    done
    echo SDS_BUILD_OK' _ "$@"
echo "started container $NAME"
