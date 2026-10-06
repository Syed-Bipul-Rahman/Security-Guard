#!/usr/bin/env bash
# Checks the goldens in cli/tests/golden still describe the Python build on
# this OS, then that the guard binary matches them. Run from the repo root
# with guard.py's dependencies installed (requirements-dev.txt and ./core).
#
# A golden that only holds on other OSes gets a per-OS override; any written
# here are printed (base64) and fail the run, so they can be committed.
set -euo pipefail
cd "$(dirname "$0")/../.."
before=$(git status --porcelain -- cli/tests/golden)
GUARD_GOLDEN=record-os GUARD_REFERENCE="$PWD/guard.py" \
  cargo test --locked --manifest-path cli/Cargo.toml --tests -q
after=$(git status --porcelain -- cli/tests/golden)
if [ "$before" != "$after" ]; then
  echo "The Python build's output on this OS differs from the shared goldens."
  echo "Commit these per-OS goldens:"
  git status --porcelain -- cli/tests/golden | while read -r st path; do
    echo "=== $st $path"
    [ -f "$path" ] && cat "$path"
  done
  exit 1
fi
cargo test --locked --manifest-path cli/Cargo.toml --tests -q
