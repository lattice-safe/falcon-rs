#!/usr/bin/env bash
# Line-coverage report for falcon-rs (target: >= 90%).
#
# Usage:   ./scripts/coverage.sh [--html]
# Needs:   cargo install cargo-llvm-cov  (and rustup component add llvm-tools-preview)
set -euo pipefail
cd "$(dirname "$0")/.."

if ! cargo llvm-cov --version >/dev/null 2>&1; then
    echo "cargo-llvm-cov not found. Install with:"
    echo "  rustup component add llvm-tools-preview && cargo install cargo-llvm-cov"
    exit 1
fi

ARGS=(--all-features --ignore-filename-regex 'tests/|benches/|examples/|fuzz/')
if [[ "${1:-}" == "--html" ]]; then
    cargo llvm-cov "${ARGS[@]}" --html
    echo "HTML report: target/llvm-cov/html/index.html"
else
    cargo llvm-cov "${ARGS[@]}" --summary-only --fail-under-lines 90
fi
