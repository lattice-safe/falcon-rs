#!/usr/bin/env bash
# Verify that this port is bit-exact with the C reference implementation.
#
# The crate's strongest external claim is that it reproduces the reference's
# NIST KAT transcript digests. Those two SHA-1 values are not ours: they are
# published in the reference's own `test_falcon.c`, as the expected results of
# its `test_nist_KAT` self-test. This script closes the loop by checking all
# three links:
#
#   1. the digests `tests/nist_kat.rs` expects are the ones the reference's
#      `test_falcon.c` expects;
#   2. the reference, compiled and run here, actually produces them;
#   3. our Rust test produces them too.
#
# Usage:
#   ./scripts/verify_c_parity.sh [path-to-reference-source]
#
# With no argument it downloads the official round-3 package from
# falcon-sign.info. Note that the round-3 package predates a reference fix:
# its `falcon.c` omits `shake256_flip` in the two PRNG-init helpers, which the
# 2021-11-01 release added and which this port follows. That difference does
# not affect the KAT.
set -euo pipefail
cd "$(dirname "$0")/.."
REPO="$PWD"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

if [[ $# -ge 1 ]]; then
    SRC="$1"
    echo "Using reference source at $SRC"
else
    echo "Downloading the official round-3 package..."
    curl -fsSL --max-time 120 -o "$WORK/ref.zip" https://falcon-sign.info/falcon-round3.zip
    unzip -oq "$WORK/ref.zip" -d "$WORK/ref"
    SRC="$WORK/ref/falcon-round3/Extra/c"
fi
[[ -f "$SRC/test_falcon.c" ]] || { echo "no test_falcon.c under $SRC"; exit 1; }

# --- 1. the expected digests must agree -------------------------------------
echo
echo "1. Comparing expected digests"
ref_digests=$(grep -oE 'test_nist_KAT\([0-9]+, "[0-9a-f]{40}"' "$SRC/test_falcon.c" |
              grep -oE '[0-9a-f]{40}' | sort)
our_digests=$(grep -oE '[0-9a-f]{40}' "$REPO/tests/nist_kat.rs" | sort -u)
if [[ -z "$ref_digests" ]]; then echo "   could not find digests in the reference"; exit 1; fi
for d in $ref_digests; do
    if grep -q "$d" <<<"$our_digests"; then
        echo "   $d  present in both"
    else
        echo "   $d  MISSING from tests/nist_kat.rs"; exit 1
    fi
done

# --- 2. the reference must reproduce them ----------------------------------
echo
echo "2. Building and running the reference's own KAT self-test"
mkdir -p "$WORK/build"
cp "$SRC"/*.c "$SRC"/*.h "$WORK/build/"
rm -f "$WORK/build/speed.c"   # a second main()
( cd "$WORK/build" && cc -O2 -o test_falcon_ref ./*.c )
ref_out="$("$WORK/build/test_falcon_ref" 2>&1 | grep -i "NIST KAT" || true)"
echo "$ref_out" | sed 's/^/   /'
for d in $ref_digests; do
    grep -q "$d" <<<"$ref_out" || { echo "   the reference did not print $d"; exit 1; }
done

# --- 3. our port must reproduce them ---------------------------------------
echo
echo "3. Running our own KAT test"
cargo test --release --test nist_kat 2>&1 | grep -E "^test result" | sed 's/^/   /'

echo
echo "OK: the digests are the reference's own, the reference reproduces them,"
echo "    and this port matches. Parity with the C implementation is verified."
