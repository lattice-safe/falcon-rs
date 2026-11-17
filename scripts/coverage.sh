#!/usr/bin/env bash
# Line/region/function coverage, merged over both floating-point backends.
#
# Usage:   ./scripts/coverage.sh           # enforce 100% (same as gate.sh)
#          ./scripts/coverage.sh --html    # HTML report in target/llvm-cov/html
# Needs:   cargo install cargo-llvm-cov  (and rustup component add llvm-tools-preview)
set -euo pipefail
cd "$(dirname "$0")/.."

if [[ "${1:-}" != "--html" ]]; then
    exec ./scripts/c-fn-dsa/gate.sh
fi
IGNORE='tests/|benches/|examples/|fuzz/'
cargo llvm-cov clean --workspace
cargo llvm-cov --no-report --features serde
cargo llvm-cov --no-report --all-features
cargo llvm-cov report --ignore-filename-regex "$IGNORE" --html
echo "HTML report: target/llvm-cov/html/index.html"
