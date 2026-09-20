#!/bin/sh
# guard-scan-hook.sh — shared Guard hook body, symlinked/copied to the git hook
# names below. Runs a Guard scan on the repo right after a clone/pull/checkout,
# BEFORE the developer opens the folder in an editor.
#
# Installed as a global git hook (core.hooksPath) so it fires for EVERY repo,
# including freshly cloned ones. Detect + report only; it never edits your repo.
#
# Wired to: post-checkout, post-merge, post-rewrite  (git has no post-clone, but
# a clone runs a post-checkout, so clones are covered).
#
# Exit status is intentionally 0 (never blocks the git operation); the guard
# raises alerts through the agent + a visible warning, not by failing git.

set -u

# Locate the Guard install (overridable via env)
GUARD_HOME="${GUARD_HOME:-$HOME/.guard}"
GUARD_APP="${GUARD_APP:-$GUARD_HOME/app}"        # where scanner.py etc. live
PYTHON="${GUARD_PYTHON:-python3}"

# The repo the hook is running in
REPO_ROOT=$(git rev-parse --show-toplevel 2>/dev/null) || exit 0

# Skip if Guard isn't installed (don't break git for anyone)
[ -f "$GUARD_APP/scanner.py" ] || exit 0

hook_name=$(basename "$0")
log="$GUARD_HOME/hook.log"
mkdir -p "$GUARD_HOME" 2>/dev/null || true
echo "$(date -u +%FT%TZ)  $hook_name  $REPO_ROOT" >> "$log" 2>/dev/null || true

# 1) Highest-priority: is it safe to open in VS Code?
if ! "$PYTHON" "$GUARD_APP/scanner.py" guard-open "$REPO_ROOT" >/dev/null 2>>"$log"; then
    printf '\n\033[31m[GUARD] WARNING: %s contains a VS Code auto-run task (folderOpen dropper).\n' "$REPO_ROOT" >&2
    printf '[GUARD] DO NOT OPEN THIS FOLDER IN VS CODE. Details: %s\033[0m\n\n' "$log" >&2
fi

# 2) Full tree scan (records alerts to the agent; prints a short notice on hit)
if ! "$PYTHON" "$GUARD_APP/scanner.py" scan-tree "$REPO_ROOT" >/dev/null 2>>"$log"; then
    printf '\033[31m[GUARD] Supply-chain signatures detected in %s — see %s\033[0m\n' "$REPO_ROOT" "$log" >&2
fi

exit 0
