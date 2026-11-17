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
# A reused checkout must come from the pinned repository and be pristine:
# no local edits and no stray files that a build glob could pick up.
origin_url=$(git -C "$DIR" config --get remote.origin.url)
if [[ "$origin_url" != "$repo" ]]; then
    echo "checkout origin is $origin_url, expected $repo" >&2
    exit 1
fi
make -s -C "$DIR" clean >/dev/null 2>&1 || true
if [[ -n "$(git -C "$DIR" status --porcelain --ignored)" ]]; then
    echo "checkout at $DIR is not pristine:" >&2
    git -C "$DIR" status --short --ignored >&2
    exit 1
fi
# GitHub serves any object of the fork network through the parent's URL, so
# the pinned commit must also be on upstream's own default branch.
git -C "$DIR" fetch -q origin HEAD
if ! git -C "$DIR" merge-base --is-ancestor "$commit" FETCH_HEAD; then
    echo "$commit is not on $repo's default branch" >&2
    exit 1
fi
echo "c-fn-dsa at $commit" >&2

CC="${CC:-cc}"
echo "Building test_fndsa with $CC" >&2
make -s -C "$DIR" CC="$CC" LD="$CC" test_fndsa >&2

echo "Running the reference's own test suite" >&2
(cd "$DIR" && ./test_fndsa) >&2

echo "$DIR"
