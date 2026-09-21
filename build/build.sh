#!/usr/bin/env bash
# build.sh - produce the single `guard` binary for THIS OS/arch.
# PyInstaller does not cross-compile: run this once on each target
# (Linux x64, Linux arm64, macOS arm64/x64, Windows x64) in CI or on a VM.
#
#   bash build/build.sh
#   -> build/dist/guard   (guard.exe on Windows)   + build/dist/guard.sha256
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

python3 -m pip install --quiet --upgrade pyinstaller certifi

# refresh the bundled blocklist snapshot so `guard deps check` works out of the box
if [ ! -f malware-feed/malware-blocklist.json ]; then
  echo "note: no malware-blocklist.json to bundle; run 'guard deps update' after install, or"
  echo "      python3 malware-feed/collect_malware_advisories.py --out malware-feed --ecosystem npm"
fi

rm -rf build/dist build/work
pyinstaller build/guard.spec --distpath build/dist --workpath build/work --clean --noconfirm

BIN="build/dist/guard"
[ -f "$BIN.exe" ] && BIN="$BIN.exe"
if command -v sha256sum >/dev/null 2>&1; then sha256sum "$BIN" > "$BIN.sha256"
else shasum -a 256 "$BIN" > "$BIN.sha256"; fi

echo "built: $BIN"
cat "$BIN.sha256"
echo "smoke test:"
"$BIN" version
