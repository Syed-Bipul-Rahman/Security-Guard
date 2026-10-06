#!/usr/bin/env bash
# install.sh — deploy Guard on a macOS/Linux workstation.
#
#   * copies the scanner app into $GUARD_HOME/app
#   * installs GLOBAL git hooks (post-checkout/merge/rewrite/pre-push) so every
#     clone/pull is scanned, and a push with a critical finding is refused
#   * installs + starts the always-on watcher service (launchd / systemd)
#
# Run this ON EACH developer machine. It is idempotent.
# pre-push blocks a critical finding. The other hooks detect and report only.
# Uninstall with:  ./install.sh --uninstall
#
# This does NOT need root for the per-user install (recommended). A machine-wide
# install (--system) needs sudo.

set -euo pipefail

GUARD_HOME="${GUARD_HOME:-$HOME/.guard}"
GUARD_APP="$GUARD_HOME/app"
HOOKS_DIR="$GUARD_HOME/githooks"
PYTHON="${GUARD_PYTHON:-python3}"
SRC_DIR="$(cd "$(dirname "$0")" && pwd)"
OS="$(uname -s)"
HOOK_NAMES="post-checkout post-merge post-rewrite pre-push"

install_hook_scripts() {
    dest="$1"
    mkdir -p "$dest"
    for hook in $HOOK_NAMES; do
        cp "$SRC_DIR/hooks/guard-scan-hook.sh" "$dest/$hook"
        chmod +x "$dest/$hook"
    done
}

# If we previously chained into someone else's hooks directory, put their
# scripts back and remove the copies we added.
restore_chained_hooks() {
    record="$GUARD_HOME/chained-hooks-path"
    [ -f "$record" ] || return 0
    dir=$(head -n 1 "$record")
    if [ -d "$dir" ]; then
        for hook in $HOOK_NAMES; do
            if [ -f "$dir/$hook.guard-user" ]; then
                mv "$dir/$hook.guard-user" "$dir/$hook"
            elif [ -f "$dir/$hook" ] && grep -q GUARD_SCAN_HOOK "$dir/$hook" 2>/dev/null; then
                rm -f "$dir/$hook"
            fi
        done
    fi
    rm -f "$record"
}

# watcher.py imports snapshot_store and memguard at startup. Leave either out and
# the service crash-loops (ModuleNotFoundError) the moment launchd/systemd runs it.
# remediator.py is imported when a finding is cleaned. Leave it out and auto-clean
# fails the first time the watcher tries to quarantine a payload.
APP_FILES="scanner.py magic_bytes.py vscode_guard.py fingerprint_matcher.py workflow_baseline.py snapshot_store.py memguard.py remediator.py watcher.py signatures.json signatures.yaml"

uninstall() {
    echo "Uninstalling Guard..."
    case "$OS" in
        Darwin)
            launchctl bootout "gui/$(id -u)/me.syedbipul.guard" 2>/dev/null || \
              launchctl unload "$HOME/Library/LaunchAgents/me.syedbipul.guard.plist" 2>/dev/null || true
            rm -f "$HOME/Library/LaunchAgents/me.syedbipul.guard.plist"
            ;;
        Linux)
            systemctl --user disable --now guard.service 2>/dev/null || true
            rm -f "$HOME/.config/systemd/user/guard.service"
            systemctl --user daemon-reload 2>/dev/null || true
            ;;
    esac
    # restore previous global hooksPath only if it points at ours
    if [ "$(git config --global --get core.hooksPath || true)" = "$HOOKS_DIR" ]; then
        git config --global --unset core.hooksPath || true
    fi
    restore_chained_hooks
    echo "Removed service + global hook wiring. App/config left in $GUARD_HOME (delete manually if desired)."
    exit 0
}

[ "${1:-}" = "--uninstall" ] && uninstall

echo "==> Installing Guard to $GUARD_HOME"
mkdir -p "$GUARD_APP" "$HOOKS_DIR"

# 1. Copy app
for f in $APP_FILES; do
    cp "$SRC_DIR/$f" "$GUARD_APP/$f"
done
echo "    app -> $GUARD_APP"

# 2. Global git hooks. Never replace a core.hooksPath that already points somewhere
# else: chain by installing into that directory and keeping the previous script
# as <hook>.guard-user. Repo-local .git/hooks still run from the hook itself.
install_hook_scripts "$HOOKS_DIR"
existing="$(git config --global --get core.hooksPath || true)"
if [ -z "$existing" ] || [ "$existing" = "$HOOKS_DIR" ]; then
    # A previous install may have chained into someone else's directory and
    # recorded it. Deleting that record without restoring their scripts leaves
    # Guard's copies in place and uninstall can no longer put theirs back.
    restore_chained_hooks
    git config --global core.hooksPath "$HOOKS_DIR"
    echo "    global git hooks -> $HOOKS_DIR (post-checkout/merge/rewrite/pre-push)"
elif [ -d "$existing" ]; then
    printf '%s\n' "$existing" > "$GUARD_HOME/chained-hooks-path"
    for hook in $HOOK_NAMES; do
        target="$existing/$hook"
        if [ -e "$target" ] && ! grep -q GUARD_SCAN_HOOK "$target" 2>/dev/null; then
            if [ ! -e "$existing/$hook.guard-user" ]; then
                mv "$target" "$existing/$hook.guard-user"
            fi
        fi
    done
    install_hook_scripts "$existing"
    echo "    chained Guard into existing core.hooksPath=$existing (config left unchanged)"
else
    echo "    NOTE: core.hooksPath=$existing is not a directory; left unchanged."
    echo "    Guard hooks were written to $HOOKS_DIR. Point core.hooksPath there to enable them."
fi

# 3. Default watcher config (only if absent — don't clobber local edits)
if [ ! -f "$GUARD_HOME/watcher.config.json" ]; then
    GUARD_HOME="$GUARD_HOME" "$PYTHON" "$GUARD_APP/watcher.py" --print-default-config \
        > "$GUARD_HOME/watcher.config.json"
    echo "    default config -> $GUARD_HOME/watcher.config.json (edit watch_roots as needed)"
fi

# 4. Service
if [ "${GUARD_INSTALL_SKIP_SERVICE:-}" = "1" ]; then
    echo "    service install skipped"
else
case "$OS" in
    Darwin)
        plist="$HOME/Library/LaunchAgents/me.syedbipul.guard.plist"
        mkdir -p "$HOME/Library/LaunchAgents"
        sed -e "s|__PYTHON__|$(command -v "$PYTHON")|g" \
            -e "s|__GUARD_APP__|$GUARD_APP|g" \
            -e "s|__GUARD_HOME__|$GUARD_HOME|g" \
            "$SRC_DIR/service/macos/me.syedbipul.guard.plist" > "$plist"
        launchctl bootout "gui/$(id -u)/me.syedbipul.guard" 2>/dev/null || true
        launchctl bootstrap "gui/$(id -u)" "$plist"
        launchctl enable "gui/$(id -u)/me.syedbipul.guard" 2>/dev/null || true
        echo "    launchd agent installed + started (RunAtLoad, KeepAlive)"
        ;;
    Linux)
        unit="$HOME/.config/systemd/user/guard.service"
        mkdir -p "$HOME/.config/systemd/user"
        sed -e "s|__PYTHON__|$(command -v "$PYTHON")|g" \
            -e "s|__GUARD_APP__|$GUARD_APP|g" \
            -e "s|__GUARD_HOME__|$GUARD_HOME|g" \
            "$SRC_DIR/service/linux/guard.service" > "$unit"
        systemctl --user daemon-reload
        systemctl --user enable --now guard.service
        loginctl enable-linger "$USER" 2>/dev/null || true
        echo "    systemd user service enabled + started (Restart=always, linger on)"
        ;;
    *)
        echo "    Unsupported OS for auto service install: $OS (see service/windows for Windows)"
        ;;
esac
fi

echo "==> Done. Logs: $GUARD_HOME/watcher.log  Alerts: $GUARD_HOME/alerts.jsonl"
echo "    Verify: tail -f $GUARD_HOME/watcher.log"
