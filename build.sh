#!/usr/bin/env bash
# parallel incremental build (see Makefile)
set -euo pipefail
cd "$(dirname "$0")"
make -j"$(nproc)" build/basalt
echo "Built: build/basalt"
