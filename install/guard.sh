#!/usr/bin/env bash
# guard.sh - one-command Guard installer (Linux/macOS).
#   curl -fsSL https://security.syedbipul.me/guard.sh | sudo bash
#
# Thin bootstrap (carries no product logic): detects platform, downloads the single
# `guard` binary, verifies its SHA-256, installs it to /usr/local/bin, then runs
# `guard install` to set up the always-on service. Windows uses guard.ps1.
#
# IMPORTANT: serve this over HTTPS only. Piping a script to a root shell over plain
# HTTP lets any network attacker run code as root. Use https://.
set -euo pipefail

BASE_URL="${GUARD_BASE_URL:-https://security.syedbipul.me/guard}"   # dir with binaries + manifest
INSTALL_DIR="${GUARD_INSTALL_DIR:-/usr/local/bin}"
BIN="$INSTALL_DIR/guard"

# --- downloader ---
if command -v curl >/dev/null 2>&1; then DL="curl -fsSL -o"; DLO="curl -fsSL";
elif command -v wget >/dev/null 2>&1; then DL="wget -qO"; DLO="wget -qO-";
else echo "need curl or wget" >&2; exit 1; fi

# --- detect platform ---
case "$(uname -s)" in
  Linux)  os=linux ;;
  Darwin) os=darwin ;;
  *) echo "unsupported OS $(uname -s); Windows: use guard.ps1" >&2; exit 1 ;;
esac
case "$(uname -m)" in
  x86_64|amd64) arch=x64 ;;
  arm64|aarch64) arch=arm64 ;;
  *) echo "unsupported arch $(uname -m)" >&2; exit 1 ;;
esac
# musl vs glibc on Linux
if [ "$os" = linux ] && { [ -f /lib/libc.musl-x86_64.so.1 ] || ldd /bin/ls 2>&1 | grep -q musl; }; then
  platform="linux-${arch}-musl"
else
  platform="${os}-${arch}"
fi

echo "Guard installer: platform=$platform"
[ "$(id -u)" -eq 0 ] || echo "note: not root; installing a system service needs sudo (re-run with sudo if this fails)."

tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
echo "Downloading guard ($platform)..."
$DL "$tmp/guard" "$BASE_URL/$platform/guard"

# verify checksum from the published manifest (fail closed)
if sums="$($DLO "$BASE_URL/$platform/guard.sha256" 2>/dev/null)"; then
  want="$(printf '%s' "$sums" | awk '{print $1}')"
  if command -v sha256sum >/dev/null 2>&1; then have="$(sha256sum "$tmp/guard" | awk '{print $1}')";
  else have="$(shasum -a 256 "$tmp/guard" | awk '{print $1}')"; fi
  if [ -n "$want" ] && [ "$want" != "$have" ]; then
    echo "CHECKSUM MISMATCH (want $want, got $have) - aborting." >&2; exit 1
  fi
  echo "checksum OK"
else
  echo "WARNING: no checksum manifest found - proceeding without verification is unsafe." >&2
fi

chmod +x "$tmp/guard"
mkdir -p "$INSTALL_DIR"
mv "$tmp/guard" "$BIN"
echo "installed: $BIN"

echo "Setting up the Guard service..."
"$BIN" install

echo ""
echo "Guard installed. Try:  guard version   |   guard scan .   |   guard triage"
