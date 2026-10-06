#!/usr/bin/env bash
# Checks the goldens in cli/tests/golden still describe the Python build on
# this OS, then that the guard binary matches them. Run from the repo root
# with guard.py's dependencies installed (requirements-dev.txt and ./core).
#
# A golden that only holds on other OSes gets a per-OS override; any written
# here are printed (a base64 tar.gz) and fail the run, so they can be committed.
#
# On Windows the overrides are recorded from the binary instead: Python there
# writes text files with CRLF and has no symlinks, so its output differs from
# the binary's for reasons that aren't behaviour. The Python side-by-side
# tests (tests/test_rust_*.py) already compare the two builds on Windows.
set -euo pipefail
cd "$(dirname "$0")/../.."
before=$(git status --porcelain -- cli/tests/golden)
rc=0
case "$(uname -s)" in
  MINGW* | MSYS* | CYGWIN*) ref=() ;;
  *) ref=(GUARD_REFERENCE="$PWD/guard.py") ;;
esac
env GUARD_GOLDEN=record-os "${ref[@]}" \
  cargo test --locked --manifest-path cli/Cargo.toml --tests -q --no-fail-fast || rc=$?
after=$(git status --porcelain -- cli/tests/golden)
if [ "$before" != "$after" ]; then
  echo "The output on this OS differs from the shared goldens."
  echo "Commit these per-OS goldens:"
  git status --porcelain -- cli/tests/golden
  echo "=== BEGIN GOLDENS (base64 tar.gz)"
  git ls-files -o -m --exclude-standard -- cli/tests/golden | tar czf - -T - | base64
  echo "=== END GOLDENS"
  exit 1
fi
[ "$rc" = 0 ] || exit "$rc"
cargo test --locked --manifest-path cli/Cargo.toml --tests -q --no-fail-fast
