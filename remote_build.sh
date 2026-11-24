#!/usr/bin/env bash
# sync the project to a build host, then build and run unit tests there.
# usage: ./remote_build.sh [--tests-only | --build-only]
set -euo pipefail

HOST="${BASALT_HOST:?set BASALT_HOST=user@host}"
DIR="${BASALT_DIR:-basalt}"
MODE="${1:-all}"
cd "$(dirname "$0")"

rsync -az --delete --exclude /build --exclude graphify-out --exclude .git ./ "$HOST:$DIR/"

ssh "$HOST" "MODE='$MODE' bash -s" "$DIR" <<'EOF'
set -euo pipefail
cd "$1"
mkdir -p build
if [ "$MODE" != "--tests-only" ]; then
  bash build.sh
fi
if [ "$MODE" != "--build-only" ]; then
  make -j"$(nproc)" build/basalt_tests
  ./build/basalt_tests --gtest_brief=1
fi
EOF
