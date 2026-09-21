#!/usr/bin/env python3
"""
updater.py - OTA self-update for the Guard agent (signed, fail-closed).

The running service checks a SIGNED manifest on the update server every N hours and,
if a newer version is offered AND its signature verifies against the EMBEDDED public
key, updates the blocklist (frequent) and/or the binary (staged, then restart).

SECURITY MODEL (a self-updating root agent is a supply-chain target - treat it so):
  * HTTPS only.
  * Ed25519 signature over the manifest, verified with a key baked into the binary.
    A bad/absent signature => NO update (fail closed). This is the gate that stops a
    compromised server/CDN/CI from pushing malicious code to the fleet.
  * SHA-256 verify of every downloaded artifact.
  * Downgrade protection: never apply a version <= current.
  * Atomic swap + keep previous binary (.bak) for rollback.

Manifest (JSON) served at $GUARD_UPDATE_URL/manifest.json, with its detached
signature (base64 of 64-byte Ed25519 sig) at manifest.json.sig:
  {
    "version": "1.1.0",
    "min_version": "1.0.0",
    "blocklist": { "sha256": "...", "url": ".../malware-blocklist.json" },
    "binary": {
      "linux-x64":    { "sha256": "...", "url": ".../1.1.0/linux-x64/guard" },
      "darwin-arm64": { "sha256": "...", "url": ".../1.1.0/darwin-arm64/guard" }
    }
  }
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import sys
import tempfile
import urllib.request
from pathlib import Path

import ed25519_pure

# --- release identity: REPLACE with your real public key before shipping ---
# (generate with release/sign_manifest.py keygen; keep the SECRET key offline)
PUBKEY_HEX = os.environ.get("GUARD_UPDATE_PUBKEY", "b42962000f5fd0e3f3ab68eaee6ab946623f50313c8b6d3b644421daf9279bb0")  # empty in source; set at build/release
BASE_URL = os.environ.get("GUARD_UPDATE_URL", "https://security.syedbipul.me/guard")
CURRENT_VERSION = "1.0.0"   # kept in sync with guard.VERSION at build time


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _semver(v: str):
    parts = []
    for p in str(v).split("."):
        num = "".join(ch for ch in p if ch.isdigit())
        parts.append(int(num) if num else 0)
    while len(parts) < 3:
        parts.append(0)
    return tuple(parts[:3])


def _fetch(url: str, timeout: int = 30) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "guard-updater"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()


def platform_key() -> str:
    import platform
    m = platform.machine().lower()
    arch = "arm64" if m in ("arm64", "aarch64") else ("x64" if m in ("x86_64", "amd64") else m)
    if sys.platform.startswith("linux"):
        return f"linux-{arch}"
    if sys.platform == "darwin":
        return f"darwin-{arch}"
    if sys.platform.startswith("win"):
        return f"windows-{arch}"
    return f"{sys.platform}-{arch}"


class Updater:
    def __init__(self, base_url: str = BASE_URL, pubkey_hex: str = PUBKEY_HEX,
                 current_version: str = CURRENT_VERSION, guard_home: Path | None = None,
                 log=print):
        self.base = base_url.rstrip("/")
        self.pubkey = bytes.fromhex(pubkey_hex) if pubkey_hex else b""
        self.current = current_version
        self.home = guard_home or Path(os.environ.get("GUARD_HOME", str(Path.home() / ".guard")))
        self.log = log

    # -- the signature gate --
    def _load_verified_manifest(self) -> dict | None:
        if not self.pubkey:
            self.log("updater: NO public key embedded -> refusing all updates (fail closed)")
            return None
        try:
            raw = _fetch(f"{self.base}/manifest.json")
            sig_b64 = _fetch(f"{self.base}/manifest.json.sig").strip()
        except Exception as e:
            self.log(f"updater: manifest fetch failed ({e}); staying on current version")
            return None
        import base64
        try:
            sig = base64.b64decode(sig_b64)
        except Exception:
            self.log("updater: malformed signature -> refusing")
            return None
        if not ed25519_pure.verify(sig, raw, self.pubkey):
            self.log("updater: SIGNATURE INVALID -> refusing update (possible tampering)")
            return None
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            self.log("updater: manifest not valid JSON -> refusing")
            return None

    def _download_verified(self, url: str, want_sha: str, dest: Path) -> bool:
        try:
            data = _fetch(url)
        except Exception as e:
            self.log(f"updater: download failed {url} ({e})")
            return False
        if _sha256_bytes(data) != want_sha:
            self.log(f"updater: SHA-256 MISMATCH for {url} -> discarding")
            return False
        dest.write_bytes(data)
        return True

    def _update_blocklist(self, m: dict) -> bool:
        bl = m.get("blocklist") or {}
        url, want = bl.get("url"), bl.get("sha256")
        if not (url and want):
            return False
        feed = self.home / "feed"
        feed.mkdir(parents=True, exist_ok=True)
        local = feed / "malware-blocklist.json"
        if local.exists() and _sha256_file(local) == want:
            return False  # already current
        tmp = feed / "malware-blocklist.json.new"
        if self._download_verified(url, want, tmp):
            os.replace(tmp, local)   # atomic
            self.log(f"updater: blocklist updated ({want[:12]}...)")
            return True
        return False

    def _update_binary(self, m: dict) -> bool:
        if not getattr(sys, "frozen", False):
            return False  # only self-update the packaged binary, not dev runs
        newver = m.get("version", "0")
        minver = m.get("min_version", "0")
        if _semver(newver) <= _semver(self.current):
            return False  # downgrade protection / already current
        if _semver(self.current) < _semver(minver):
            self.log(f"updater: current {self.current} below min_version {minver}; forced upgrade")
        entry = (m.get("binary") or {}).get(platform_key())
        if not entry:
            self.log(f"updater: no binary for platform {platform_key()} in manifest")
            return False
        target = Path(sys.executable)      # the running binary
        # Only the root service can replace a binary in a system dir. If this process
        # can't write there (e.g. a manual non-root `guard watch`), skip cleanly — the
        # service handles binary updates; don't download or error.
        if not os.access(str(target.parent), os.W_OK):
            self.log(f"updater: {newver} available; binary self-update skipped "
                     f"({target.parent} not writable — the root service applies it). Blocklist is current.")
            return False
        tmp = target.with_suffix(".new")
        if not self._download_verified(entry["url"], entry["sha256"], tmp):
            return False
        try:
            tmp.chmod(target.stat().st_mode)
            if sys.platform.startswith("win"):
                # can't replace a running .exe; stage it - a bootstrap swaps on next start
                pending = target.with_suffix(".pending.exe")
                os.replace(tmp, pending)
                self.log(f"updater: staged {newver} at {pending}; will apply on next restart")
                return True
            shutil.copy2(target, target.with_suffix(".bak"))  # rollback copy
            os.replace(tmp, target)                            # atomic swap (Unix)
            self.log(f"updater: binary updated {self.current} -> {newver}; restart to run it")
            return True
        except Exception as e:
            self.log(f"updater: swap failed ({e}); keeping current binary")
            try: tmp.unlink()
            except OSError: pass
            return False

    def check_and_apply(self) -> dict:
        m = self._load_verified_manifest()
        if not m:
            return {"status": "no-op"}
        bl_changed = self._update_blocklist(m)
        bin_changed = self._update_binary(m)
        return {"status": "updated" if (bl_changed or bin_changed) else "current",
                "blocklist_updated": bl_changed, "binary_updated": bin_changed,
                "offered_version": m.get("version")}


if __name__ == "__main__":
    up = Updater()
    print(up.check_and_apply())
