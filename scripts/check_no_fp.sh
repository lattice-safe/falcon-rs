#!/usr/bin/env bash
# Verify that the `fpemu` build contains no floating-point instructions.
#
# The `fpemu` backend claims that no hardware floating-point unit is used,
# which is what removes the floating-point timing side channel. This script
# checks that claim against the actual machine code: it disassembles the
# compiled crate and fails if any floating-point arithmetic, comparison or
# conversion instruction appears.
#
# Bit-moves between the general-purpose and FP/SIMD register files (aarch64
# `fmov x0, d0`, x86 `movsd`/`movq`) are allowed: the compiler emits them to
# shuffle 64-bit integers around, they do not interpret the operand as a
# float, and their timing is fixed on every implementation.
#
# Usage:   ./scripts/check_no_fp.sh [--native]
#          --native  scan the default backend instead. That build *does* use
#                    floating point, so the check is expected to fail —
#                    which is how we know the check works.
set -euo pipefail
cd "$(dirname "$0")/.."

FEATURES=(--features fpemu)
LABEL="fpemu"
if [[ "${1:-}" == "--native" ]]; then
    FEATURES=()
    LABEL="native"
fi

# A dedicated target directory per backend: the uplifted `target/release`
# artifact is shared between feature sets and can be stale.
export CARGO_TARGET_DIR="target/fpcheck-$LABEL"
# bash 3.2 (macOS) needs this form to expand a possibly-empty array under `set -u`.
cargo build --release ${FEATURES[@]+"${FEATURES[@]}"} >/dev/null
RLIB="$CARGO_TARGET_DIR/release/libfalcon.rlib"
[[ -f "$RLIB" ]] || { echo "missing $RLIB"; exit 1; }

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
( cd "$WORK" && ar x "$OLDPWD/$RLIB" )
OBJS=("$WORK"/*.rcgu.o)
[[ -e "${OBJS[0]}" ]] || { echo "no object files extracted from $RLIB"; exit 1; }

if command -v objdump >/dev/null 2>&1; then
    DISASM=(objdump -d)
elif command -v otool >/dev/null 2>&1; then
    DISASM=(otool -tvV)
else
    echo "no disassembler found (need objdump or otool)"; exit 1
fi

TEXT="$("${DISASM[@]}" "${OBJS[@]}" 2>/dev/null)"
[[ -n "$TEXT" ]] || { echo "disassembly produced no output"; exit 1; }

# Floating-point arithmetic / compare / convert, aarch64 and x86_64.
MNEM='fadd|fsub|fmul|fdiv|fsqrt|fmadd|fmsub|fnmadd|fnmsub|fabs|fneg|fcmpe?|fccmpe?'
MNEM="$MNEM"'|fcsel|fmaxn?m?|fminn?m?|frint[a-z]*|fcvt[a-z]*|scvtf|ucvtf'
MNEM="$MNEM"'|v?(add|sub|mul|div|sqrt|max|min|round)(sd|ss|pd|ps)|v?u?comis[sd]'
MNEM="$MNEM"'|v?cvt(si2|tt?|dq2|ps2|pd2|sd2|ss2)[a-z0-9]*'
MNEM="$MNEM"'|f(add|sub|mul|div|sqrt|ld|st|stp|prem|patan|yl2x)[a-z]*'

# Every disassembler (otool, GNU objdump, llvm-objdump) prints the mnemonic
# immediately after a tab, so match on that rather than on a column index —
# the column differs between them.
TAB=$'\t'
FOUND="$(printf '%s\n' "$TEXT" \
    | grep -oE "${TAB}(${MNEM})([[:space:]]|\$)" \
    | tr -d "${TAB} " | sort | uniq -c | sort -rn || true)"

if [[ -n "$FOUND" ]]; then
    echo "FAIL [$LABEL]: floating-point instructions present:"
    echo "$FOUND"
    exit 1
fi

echo "OK [$LABEL]: no floating-point arithmetic, compare or convert instructions"
