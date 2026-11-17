#!/usr/bin/env bash
# Migration gate for the v0.4 (c-fn-dsa) branch. Two rules:
#
#  1. Pure Rust: the crate builds with no C, no build script, no FFI and no
#     -sys / cc / bindgen dependency. The C reference is only ever compiled by
#     the dev scripts in this directory, never by `cargo build`.
#  2. 100% coverage: every file listed in PORTED has 100% line, region and
#     function coverage under the full test suite, merged over the native
#     and the `fpemu` floating-point backends.
#
# Usage: scripts/c-fn-dsa/gate.sh
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
cd "$HERE/../.."

echo "1. Pure Rust"
fail=0
if [[ -e build.rs ]] || grep -qE '^\s*(build|links)\s*=' Cargo.toml; then
    echo "   build script or links key present"; fail=1
fi
if grep -rnE 'extern\s+"C"|#\[link|global_asm!|asm!' src/ >/dev/null; then
    echo "   FFI or assembly in src/:"; grep -rnE 'extern\s+"C"|#\[link|global_asm!|asm!' src/; fail=1
fi
bad=$(cargo tree --all-features -e normal,build --prefix none --format '{p}' 2>/dev/null |
      awk '{print $1}' | sort -u | grep -E '(-sys$|^cc$|^bindgen$|^cmake$|^pkg-config$)' || true)
if [[ -n "$bad" ]]; then
    echo "   native-code dependencies: $bad"; fail=1
fi
[[ $fail -eq 0 ]] && echo "   ok" || exit 1

echo "2. 100% coverage of ported files"
JSON="$(mktemp)"
trap 'rm -f "$JSON"' EXIT
# The two floating-point backends are mutually exclusive (`fpemu` selects
# the integer one), so coverage is the union of a run with each.
IGNORE='tests/|benches/|examples/|fuzz/'
cargo llvm-cov clean --workspace >/dev/null 2>&1
cargo llvm-cov --no-report --features serde >/dev/null 2>&1
cargo llvm-cov --no-report --all-features >/dev/null 2>&1
cargo llvm-cov report --ignore-filename-regex "$IGNORE" \
    --json --summary-only --output-path "$JSON" >/dev/null 2>&1
python3 -I - "$JSON" "$HERE/PORTED" "$PWD" <<'PY'
import json, sys
data = json.load(open(sys.argv[1]))["data"][0]["files"]
root = sys.argv[3].rstrip("/") + "/"
by_name = {f["filename"].removeprefix(root): f["summary"] for f in data}
ported = [l.strip() for l in open(sys.argv[2]) if l.strip() and not l.startswith("#")]
bad = 0
for p in ported:
    s = by_name.get(p)
    if s is None:
        print(f"   {p}: no coverage data"); bad = 1; continue
    gaps = {k: s[k]["count"] - s[k]["covered"] for k in ("lines", "regions", "functions")}
    if any(gaps.values()):
        print(f"   {p}: missed {gaps}"); bad = 1
    else:
        print(f"   {p}: 100%")
sys.exit(bad)
PY
