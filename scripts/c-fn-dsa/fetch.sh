#!/usr/bin/env bash
# Fetch c-fn-dsa at the pinned revision, build its test suite and run it.
#
# Usage: scripts/c-fn-dsa/fetch.sh [checkout-dir]
#   default checkout-dir: target/c-fn-dsa (inside the gitignored target/)
#
# Prints the checkout directory on the last line of stdout.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$HERE/../.." && pwd)"
# shellcheck disable=SC1091
repo=$(sed -n 's/^repo=//p' "$HERE/UPSTREAM")
commit=$(sed -n 's/^commit=//p' "$HERE/UPSTREAM")
DIR="${1:-$REPO_ROOT/target/c-fn-dsa}"

if [[ ! -d "$DIR/.git" ]]; then
    echo "Cloning $repo into $DIR" >&2
    git clone -q "$repo" "$DIR"
fi
git -C "$DIR" fetch -q origin "$commit" 2>/dev/null || git -C "$DIR" fetch -q origin
git -C "$DIR" -c advice.detachedHead=false checkout -q "$commit"
actual=$(git -C "$DIR" rev-parse HEAD)
if [[ "$actual" != "$commit" ]]; then
    echo "checked out $actual, expected $commit" >&2
    exit 1
fi
echo "c-fn-dsa at $commit" >&2

CC="${CC:-cc}"
echo "Building test_fndsa with $CC" >&2
make -s -C "$DIR" CC="$CC" LD="$CC" test_fndsa >&2

echo "Running the reference's own test suite" >&2
(cd "$DIR" && ./test_fndsa) >&2

echo "$DIR"
