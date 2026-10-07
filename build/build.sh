#!/usr/bin/env bash
# build.sh - produce the single static `guard` binary for THIS OS/arch.
# Needs a Rust toolchain (https://rustup.rs). On Linux it builds against musl, so
# the binary runs on any distro (glibc or musl) with no shared libraries; install
# musl-tools (Debian/Ubuntu) first. Release CI builds every platform the same way.
#
#   bash build/build.sh
#   -> build/dist/guard   (guard.exe on Windows)   + build/dist/guard.sha256
#
# GUARD_VERSION, GUARD_UPDATE_PUBKEY and GUARD_UPDATE_URL, when set, are
# compiled in (CI sets them for releases).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

command -v cargo >/dev/null 2>&1 || { echo "cargo not found: install Rust from https://rustup.rs" >&2; exit 1; }

case "$(uname -s)-$(uname -m)" in
  Linux-x86_64)            t=x86_64-unknown-linux-musl ;;
  Linux-aarch64|Linux-arm64) t=aarch64-unknown-linux-musl ;;
  Darwin-arm64)            t=aarch64-apple-darwin ;;
  Darwin-x86_64)           t=x86_64-apple-darwin ;;
  MINGW*-x86_64|MSYS*-x86_64|CYGWIN*-x86_64) t=x86_64-pc-windows-msvc ;;
  MINGW*-aarch64|MSYS*-aarch64|CYGWIN*-aarch64) t=aarch64-pc-windows-msvc ;;
  *) echo "unsupported platform $(uname -s)-$(uname -m)" >&2; exit 1 ;;
esac
case "$t" in
  *-linux-musl)
    command -v musl-gcc >/dev/null 2>&1 || { echo "musl-gcc not found: install musl-tools" >&2; exit 1; }
    export "CC_${t//-/_}=musl-gcc" ;;
  *-windows-msvc)
    export RUSTFLAGS="-C target-feature=+crt-static" ;;   # no VC++ runtime needed
esac
rustup target add "$t" >/dev/null 2>&1 || true
cargo build --release --locked --manifest-path cli/Cargo.toml --target "$t"

exe=""; case "$t" in *windows*) exe=.exe ;; esac
mkdir -p build/dist
BIN="build/dist/guard$exe"
cp "cli/target/$t/release/guard$exe" "$BIN"
if command -v sha256sum >/dev/null 2>&1; then sha256sum "$BIN" > "$BIN.sha256"
else shasum -a 256 "$BIN" > "$BIN.sha256"; fi

echo "built: $BIN"
cat "$BIN.sha256"
echo "smoke test:"
"$BIN" version
