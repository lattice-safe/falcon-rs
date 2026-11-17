#!/usr/bin/env bash
# Verify that this port is bit-exact with the C reference, c-fn-dsa, at the
# revision pinned in scripts/c-fn-dsa/UPSTREAM. Three links:
#
#   1. the reference, compiled here, passes its own test suite (test_fndsa);
#   2. the fixtures under tests/fixtures/c-fn-dsa/ are exactly what that
#      reference produces: they are regenerated from it and must not change
#      (its own test vectors, plus the API vectors from its public API);
#   3. this crate reproduces every fixture, on both floating-point backends.
#
# Usage: ./scripts/verify_c_parity.sh [checkout-dir]
set -euo pipefail
cd "$(dirname "$0")/.."

echo "1+2. Building the reference, running its suite, regenerating fixtures"
./scripts/c-fn-dsa/extract_vectors.sh "${1:-}" >/dev/null
if ! git diff --quiet -- tests/fixtures/c-fn-dsa \
    || [[ -n "$(git ls-files --others --exclude-standard tests/fixtures/c-fn-dsa)" ]]; then
    echo "   FAIL: the regenerated fixtures differ from the committed ones"
    git status --short tests/fixtures/c-fn-dsa
    exit 1
fi
echo "   reference suite passed; fixtures reproduced exactly"

echo
echo "3. Rust against the fixtures"
for features in "" "--features fpemu"; do
    # shellcheck disable=SC2086
    cargo test --release $features --test c_fn_dsa_vectors --test api_vectors -q
    echo "   ok (${features:-native backend})"
done

echo
echo "PASS: bit-exact with c-fn-dsa @ $(sed -n 's/^commit=//p' scripts/c-fn-dsa/UPSTREAM)"
