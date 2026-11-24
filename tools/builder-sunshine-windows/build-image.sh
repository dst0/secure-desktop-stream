#!/usr/bin/env bash
# Runs on a Linux build host. Builds sds-sunshine-windows-cross:<tag> (default: today's
# date). Uses the classic builder because BuildKit ignores --cpu-quota/--memory; with the classic
# builder every RUN step is capped (default 2 CPUs, 5 GB). Serialized with other SDS builds.
# Usage: build-image.sh [tag]
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
TAG=${1:-$(date +%Y%m%d)}
CPUS=${CPUS:-2}
MEM=${MEM:-5g}
LOCK=${LOCK:-$HOME/build/sds/.build.lock}
echo "building sds-sunshine-windows-cross:$TAG (cpus=$CPUS mem=$MEM), waiting for $LOCK"
exec flock "$LOCK" env DOCKER_BUILDKIT=0 docker build --force-rm \
  --cpu-period=100000 --cpu-quota=$((CPUS * 100000)) --memory="$MEM" --memory-swap="$MEM" \
  --build-arg JOBS="$CPUS" \
  -t "sds-sunshine-windows-cross:$TAG" "$HERE"
