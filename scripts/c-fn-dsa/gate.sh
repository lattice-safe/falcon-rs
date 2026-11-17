#!/usr/bin/env bash
# Migration gate for the v0.4 (c-fn-dsa) branch. Two rules:
#
#  1. Pure Rust: the crate builds with no C, no build script, no FFI and no
#     -sys / cc / bindgen dependency. The C reference is only ever compiled by
#     the dev scripts in this directory, never by `cargo build`.
#  2. 100% coverage: every source file under src/ has 100% line, region and
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

echo "2. 100% coverage of every file under src/"
JSON="$(mktemp)"
trap 'rm -f "$JSON"' EXIT
# The two floating-point backends are mutually exclusive (`fpemu` selects
# the integer one), so coverage is the union of a run with each.
IGNORE='tests/|benches/|examples/|fuzz/'
cargo llvm-cov clean --workspace >/dev/null 2>&1
cargo llvm-cov --no-report --features serde >/dev/null 2>&1
cargo llvm-cov --no-report --all-features >/dev/null 2>&1
cargo llvm-cov report --ignore-filename-regex "$IGNORE" \
    --json --output-path "$JSON" >/dev/null 2>&1
python3 -I - "$JSON" "$PWD" <<'PY'
import json, os, sys
from collections import defaultdict

# Coverage is counted per *source* region, line and function: an item is
# covered if any compiled copy of it ran. The library is compiled twice
# under test (with cfg(test) for its unit tests, and as a dependency of
# the integration tests), and generic code once per instantiation;
# llvm-cov's per-file summary counts those copies separately, so a path
# that only a unit test can reach would look uncovered in the other copy.
data = json.load(open(sys.argv[1]))["data"][0]
root = sys.argv[2].rstrip("/") + "/"
regions = defaultdict(lambda: defaultdict(int))   # file -> region -> count
funcs = defaultdict(lambda: defaultdict(int))     # file -> fn start -> count
for fn in data["functions"]:
    for r in fn["regions"]:
        l1, c1, l2, c2, count, fid, _, kind = r[:8]
        if kind != 0:          # code regions only (not gap/skipped/branch)
            continue
        f = fn["filenames"][fid].removeprefix(root)
        regions[f][(l1, c1, l2, c2)] += count
    first = fn["regions"][0]
    f0 = fn["filenames"][first[5]].removeprefix(root)
    funcs[f0][(first[0], first[1])] += fn["count"]
lines = {}
for fdata in data["files"]:
    f = fdata["filename"].removeprefix(root)
    by_line = defaultdict(int)
    seen = set()
    for seg in fdata["segments"]:
        line, _, count, has_count = seg[:4]
        if has_count:
            seen.add(line)
            by_line[line] = max(by_line[line], count)
    lines[f] = (len(seen), sum(1 for l in seen if by_line[l] > 0))

files = sorted(
    os.path.join(d, f).removeprefix(root)
    for d, _, fs in os.walk(root + "src") for f in fs if f.endswith(".rs")
)
bad = 0
for p in files:
    if p not in regions and p not in lines:
        if "fn " in open(root + p).read():
            print(f"   {p}: no coverage data"); bad = 1
        else:
            print(f"   {p}: no executable code")
        continue
    gaps = {
        "lines": lines.get(p, (0, 0))[0] - lines.get(p, (0, 0))[1],
        "regions": sum(1 for c in regions[p].values() if c == 0),
        "functions": sum(1 for c in funcs[p].values() if c == 0),
    }
    if any(gaps.values()):
        print(f"   {p}: missed {gaps}"); bad = 1
    else:
        print(f"   {p}: 100%")
sys.exit(bad)
PY
