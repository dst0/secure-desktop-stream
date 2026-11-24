#!/usr/bin/env bash
# Build a Sunshine checkout on a remote Linux build host (set SDS_BUILD_HOST=user@linux-builder)
# inside the sds-sunshine-deps:26.04 container. Incremental: each worktree gets its own source
# copy and build dir on the host, serialized with flock and CPU/memory capped.
#
# Usage: SDS_BUILD_HOST=user@linux-builder tools/remote-build-sunshine.sh <sunshine-dir> [--tests[=FILTER]] [--web-tests] [--package] [--reconfigure] [--cpus=N]
set -euo pipefail
if (( $# < 1 )); then
  echo "Usage: SDS_BUILD_HOST=user@linux-builder $0 <sunshine-dir> [--tests[=FILTER]] [--web-tests] [--package] [--reconfigure] [--cpus=N]" >&2
  exit 2
fi
WT=$(cd "$1" && pwd); shift
HOST=${SDS_BUILD_HOST:-}
if [[ -z "$HOST" ]]; then
  echo "error: SDS_BUILD_HOST is required (e.g. SDS_BUILD_HOST=user@linux-builder)" >&2
  exit 2
fi
CPUS=${CPUS:-2}; MEM=${MEM:-6g}; TESTS=""; WEB_TESTS=0; PACKAGE=0; RECONF=0
AUTO_DEPS=${SDS_AUTO_INSTALL_DEPS:-1}
VERSION=${BUILD_VERSION:-2026.1120.205658}
BRANCH=${BRANCH:-main}
for a in "$@"; do
  case $a in
    --tests) TESTS="*" ;;
    --tests=*) TESTS="${a#--tests=}" ;;
    --web-tests) WEB_TESTS=1 ;;
    --package) PACKAGE=1 ;;
    --reconfigure) RECONF=1 ;;
    --cpus=*) CPUS="${a#--cpus=}" ;;
    *) echo "unknown arg $a" >&2; exit 2 ;;
  esac
done
NAME=$(basename "$WT")
[[ $HOST =~ ^[A-Za-z0-9._-]+(@[A-Za-z0-9._-]+)?$ ]] || { echo "invalid host: $HOST" >&2; exit 2; }
[[ $NAME =~ ^[A-Za-z0-9._-]+$ && $NAME != "." && $NAME != ".." ]] || { echo "invalid worktree name: $NAME" >&2; exit 2; }
[[ $CPUS =~ ^[1-9][0-9]*$ ]] || { echo "invalid cpu count: $CPUS" >&2; exit 2; }
[[ $MEM =~ ^[1-9][0-9]*[kmgKMG]?$ ]] || { echo "invalid memory limit: $MEM" >&2; exit 2; }
[[ -z $TESTS || $TESTS =~ ^[A-Za-z0-9_.*?:/=,-]+$ ]] || { echo "invalid gtest filter: $TESTS" >&2; exit 2; }
[[ $VERSION =~ ^[A-Za-z0-9.+_-]+$ ]] || { echo "invalid build version: $VERSION" >&2; exit 2; }
[[ $BRANCH =~ ^[A-Za-z0-9._/-]+$ && $BRANCH != *..* ]] || { echo "invalid branch: $BRANCH" >&2; exit 2; }
[[ $AUTO_DEPS == 0 || $AUTO_DEPS == 1 ]] || { echo "invalid SDS_AUTO_INSTALL_DEPS: $AUTO_DEPS" >&2; exit 2; }

SSH_OPTS=(
  -o BatchMode=yes
  -o StrictHostKeyChecking=yes
  -o IdentitiesOnly=yes
  -o ForwardAgent=no
  -o KexAlgorithms=mlkem768x25519-sha256,sntrup761x25519-sha512@openssh.com,sntrup761x25519-sha512
)
printf -v RSH '%s ' ssh "${SSH_OPTS[@]}"

REMOTE_BASE='build/sds/src'
REMOTE="$REMOTE_BASE/$NAME"
printf -v q_base '%q' "$REMOTE_BASE"
printf -v q_name '%q' "$NAME"
printf -v q_remote '%q' "$REMOTE"
printf -v q_cpus '%q' "$CPUS"
printf -v q_mem '%q' "$MEM"
printf -v q_tests '%q' "$TESTS"
printf -v q_reconf '%q' "$RECONF"
printf -v q_web_tests '%q' "$WEB_TESTS"
printf -v q_package '%q' "$PACKAGE"
printf -v q_version '%q' "$VERSION"
printf -v q_branch '%q' "$BRANCH"

ssh "${SSH_OPTS[@]}" -- "$HOST" "set -e
export PATH=\"\$HOME/.cargo/bin:\$PATH\"
command -v docker >/dev/null 2>&1 || { echo 'docker is missing on $HOST' >&2; exit 1; }
docker image inspect sds-sunshine-deps:26.04 >/dev/null 2>&1 || { echo 'sds-sunshine-deps:26.04 image is missing on $HOST' >&2; exit 1; }
if command -v cargo >/dev/null 2>&1 && command -v rustc >/dev/null 2>&1; then
  if command -v rustup >/dev/null 2>&1 && ! rustup target list --installed | grep -Fxq x86_64-unknown-linux-gnu; then
    if [ '$AUTO_DEPS' = 1 ]; then
      rustup target add x86_64-unknown-linux-gnu
    else
      echo 'missing Rust target x86_64-unknown-linux-gnu on $HOST' >&2; exit 1
    fi
  fi
elif docker run --rm --entrypoint bash sds-sunshine-deps:26.04 -c 'command -v cargo >/dev/null 2>&1 && command -v rustc >/dev/null 2>&1'; then
  :
elif [ '$AUTO_DEPS' = 1 ]; then
  if ! command -v rustup >/dev/null 2>&1; then
    sudo -n apt-get update -qq && sudo -n apt-get install -y --no-install-recommends rustup
  fi
  rustup toolchain install stable --profile minimal --target x86_64-unknown-linux-gnu
else
  echo 'Rust toolchain (cargo/rustc) is missing on $HOST and SDS_AUTO_INSTALL_DEPS=0' >&2; exit 1
fi
cd -- \"\$HOME/\"$q_base
if [ ! -d $q_name ]; then
  mkdir -- $q_name && rsync -a --exclude=/build --exclude=/node_modules --link-dest=\"\$HOME/\"$q_base/sunshine-base/ sunshine-base/ $q_name/
fi"

( cd "$WT" && git ls-files --recurse-submodules -z ) | \
  rsync -a -e "${RSH% }" --from0 --files-from=- -- "$WT"/ "$HOST:$REMOTE/"
stale_prune=()
[[ -e "$WT/src_assets/common/assets/web/Featured.vue" ]] || stale_prune+=("$REMOTE/src_assets/common/assets/web/Featured.vue")
[[ -e "$WT/third-party/Simple-Web-Server" ]] || stale_prune+=("$REMOTE/third-party/Simple-Web-Server")
if ((${#stale_prune[@]})); then
  printf -v q_prune '%q ' "${stale_prune[@]}"
  ssh "${SSH_OPTS[@]}" -- "$HOST" "rm -rf -- $q_prune"
fi

if [ "$WEB_TESTS" = 1 ]; then
  ssh "${SSH_OPTS[@]}" -- "$HOST" "set -e; cd -- \"\$HOME/\"$q_base; if [ ! -f $q_name/node_modules/.package-lock.json ]; then cmp -s sunshine-base/package-lock.json $q_name/package-lock.json || { echo 'package-lock.json differs from sunshine-base; cannot reuse node_modules' >&2; exit 1; }; rm -rf -- $q_name/node_modules.tmp; cp -a sunshine-base/node_modules $q_name/node_modules.tmp; rm -rf -- $q_name/node_modules; mv -T -- $q_name/node_modules.tmp $q_name/node_modules; fi"
fi

inner_script='
  set -e
  export PATH="/cargo/bin:$PATH"
  if [ "$SDS_RECONF" = 1 ] || [ ! -f build/build.ninja ]; then
    ./scripts/linux_build.sh --step=cmake --skip-cuda --sudo-off --num-processors="$SDS_CPUS" \
      --publisher-name=secure-desktop-stream --publisher-website=https://localhost.invalid --publisher-issue-url=https://localhost.invalid >/tmp/cmake.log 2>&1 || { tail -50 /tmp/cmake.log; exit 1; }
  fi
  ninja -C build -j"$SDS_CPUS" sunshine 2>&1 | grep -E "error|warning: unused|FAILED|^ninja: build stopped" -A5 | head -150; test ${PIPESTATUS[0]} -eq 0
  if [ -n "$SDS_TESTS" ]; then
    ninja -C build -j"$SDS_CPUS" test_sunshine 2>&1 | grep -E "error|FAILED" -A5 | head -100; test ${PIPESTATUS[0]} -eq 0
    cd build/tests && xvfb-run -a ./test_sunshine --gtest_filter="$SDS_TESTS" --gtest_brief=1 2>&1 | tail -60; test ${PIPESTATUS[0]} -eq 0; cd /src
  fi
  if [ "$SDS_WEB_TESTS" = 1 ]; then
    npx vitest run 2>&1 | tail -60; test ${PIPESTATUS[0]} -eq 0
    npm run build >/tmp/webui-build.log 2>&1 || { tail -40 /tmp/webui-build.log; exit 1; }
    if grep -lE "(^|[^A-Za-z0-9_.\$])Function\\(" build/assets/web/assets/*.js; then echo "web bundle contains a Function constructor (needs unsafe-eval)"; exit 1; fi
    if grep -iE "<script[^>]*>[^<]+</script>" build/assets/web/index.html; then echo "web bundle has inline scripts"; exit 1; fi
    echo SDS_WEB_TESTS_OK
  fi
  if [ "$SDS_PACKAGE" = 1 ]; then
    ./scripts/linux_build.sh --step=package --skip-cuda --sudo-off >/tmp/pkg.log 2>&1 || { tail -40 /tmp/pkg.log; exit 1; }
    ls -la build/cpack_artifacts/*.deb
  fi
  echo SDS_REMOTE_BUILD_OK
'
printf -v q_inner '%q' "$inner_script"

ssh "${SSH_OPTS[@]}" -- "$HOST" "cd ~/build/sds && {
  RUST_ARGS=()
  if [ -d \"\$HOME/.rustup\" ] && [ -d \"\$HOME/.cargo\" ]; then
    RUST_ARGS+=(-e RUSTUP_HOME=/rustup -e CARGO_HOME=/cargo -v \"\$HOME/.rustup:/rustup:ro\" -v \"\$HOME/.cargo:/cargo\")
  fi
  flock .build.lock docker run --rm --user \"\$(id -u):\$(id -g)\" --cap-drop=ALL --security-opt=no-new-privileges --cpus=$q_cpus --memory=$q_mem --pids-limit=512 --cpu-shares=256 \
    -e HOME=/tmp -e BUILD_VERSION=$q_version -e BRANCH=$q_branch -e DEBIAN_PACKAGE_RELEASE=1+sds+ubuntu26.04 \
    -e SDS_CPUS=$q_cpus -e SDS_RECONF=$q_reconf -e SDS_TESTS=$q_tests -e SDS_WEB_TESTS=$q_web_tests -e SDS_PACKAGE=$q_package \
    \"\${RUST_ARGS[@]}\" \
    -v \"\$HOME/\"$q_remote:/src -w /src sds-sunshine-deps:26.04 bash -c $q_inner
}"
if [ "$PACKAGE" = 1 ]; then
  OUT="$(cd "$(dirname "$0")/.." && pwd)/out/$NAME"; mkdir -p "$OUT"
  scp "${SSH_OPTS[@]}" -q -- "$HOST:$REMOTE/build/cpack_artifacts/*.deb" "$OUT/"; ls -la "$OUT"
fi
