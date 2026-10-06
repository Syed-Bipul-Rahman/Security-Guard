#!/bin/sh
# GUARD_SCAN_HOOK
# guard-scan-hook.sh — shared Guard hook body. install.sh copies it to the git
# hook names below. POSIX sh, so Git for Windows (which runs hooks with sh) can
# execute it. No bashisms.
#
#   post-checkout, post-merge, post-rewrite
#       Detect + report only. Exit 0 so a pull/checkout is never blocked.
#   pre-push
#       Scan the commits being pushed (not the dirty worktree). Exit non-zero
#       when a critical finding is present so git push aborts.
#
# Bypass the Guard check and still run any chained user hook:
#   GUARD_HOOK_BYPASS=1 git push
# Skip every hook, including user hooks (git itself):
#   git push --no-verify
#
# Chaining: repo-local .git/hooks/<name> and a preserved <name>.guard-user next
# to this script are run after a clean Guard check. This script does not replace
# core.hooksPath when one is already set; install.sh writes these copies into
# that directory instead.

set -u

GUARD_HOME="${GUARD_HOME:-$HOME/.guard}"
GUARD_APP="${GUARD_APP:-$GUARD_HOME/app}"
PYTHON="${GUARD_PYTHON:-python3}"

mkdir -p "$GUARD_HOME" 2>/dev/null || true
stdin_file=$(mktemp 2>/dev/null || printf '%s' "$GUARD_HOME/hook-stdin.$$")
cat > "$stdin_file" || true
trap 'rm -f "$stdin_file"' EXIT INT TERM

hook_name=$(basename "$0")
log="$GUARD_HOME/hook.log"

run_chained_hooks() {
    git_dir=$(git rev-parse --git-dir 2>/dev/null) || return 0
    script_dir=$(CDPATH= cd "$(dirname "$0")" && pwd) || return 0
    user_hook="$script_dir/$hook_name.guard-user"
    repo_hook="$git_dir/hooks/$hook_name"
    for candidate in "$user_hook" "$repo_hook"; do
        [ -f "$candidate" ] || continue
        [ -x "$candidate" ] || continue
        if [ "$candidate" -ef "$0" ]; then
            continue
        fi
        # A copy of this script must not call itself.
        if grep -q GUARD_SCAN_HOOK "$candidate" 2>/dev/null; then
            continue
        fi
        "$candidate" "$@" < "$stdin_file"
        rc=$?
        if [ "$rc" -ne 0 ]; then
            return "$rc"
        fi
    done
    return 0
}

REPO_ROOT=$(git rev-parse --show-toplevel 2>/dev/null) || exit 0
echo "$(date -u +%FT%TZ)  $hook_name  $REPO_ROOT" >> "$log" 2>/dev/null || true

if [ "${GUARD_HOOK_BYPASS:-}" = "1" ] || [ ! -f "$GUARD_APP/scanner.py" ]; then
    run_chained_hooks "$@"
    exit $?
fi

if [ "$hook_name" = "pre-push" ]; then
    if ! "$PYTHON" "$GUARD_APP/scanner.py" scan-push "$REPO_ROOT" --stdin-file "$stdin_file"; then
        printf '\n\033[31m[GUARD] Push blocked. Critical supply-chain findings in the commits being pushed.\033[0m\n' >&2
        printf '[GUARD] Nothing was rewritten. Bypass Guard for one command: GUARD_HOOK_BYPASS=1 git push\n' >&2
        printf '[GUARD] Skip every hook, including your own: git push --no-verify\n\n' >&2
        exit 1
    fi
else
    if ! "$PYTHON" "$GUARD_APP/scanner.py" guard-open "$REPO_ROOT" >/dev/null 2>>"$log"; then
        printf '\n\033[31m[GUARD] WARNING: %s contains a VS Code auto-run task (folderOpen dropper).\n' "$REPO_ROOT" >&2
        printf '[GUARD] DO NOT OPEN THIS FOLDER IN VS CODE. Details: %s\033[0m\n\n' "$log" >&2
    fi
    if ! "$PYTHON" "$GUARD_APP/scanner.py" scan-tree "$REPO_ROOT" >/dev/null 2>>"$log"; then
        printf '\033[31m[GUARD] Supply-chain signatures detected in %s — see %s\033[0m\n' "$REPO_ROOT" "$log" >&2
    fi
fi

run_chained_hooks "$@"
exit $?
