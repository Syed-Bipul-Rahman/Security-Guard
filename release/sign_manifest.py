#!/usr/bin/env python3
"""
sign_manifest.py - release-side signing for Guard OTA updates.

Run this in your release pipeline (offline / CI secret). It NEVER ships in the
binary - only the PUBLIC key does (baked into updater.PUBKEY_HEX).

  keygen                       -> print a new secret seed + public key; save seed to a file
  sign  MANIFEST.json          -> write MANIFEST.json.sig (base64 Ed25519 sig)
  build-and-sign ...           -> assemble a manifest from files + sign it (convenience)

Usage:
  python3 release/sign_manifest.py keygen --out guard-update.key
  python3 release/sign_manifest.py sign manifest.json --key guard-update.key
  python3 release/sign_manifest.py build-and-sign \\
      --version 1.1.0 --key guard-update.key \\
      --base-url https://security.syedbipul.me/guard \\
      --blocklist malware-feed/malware-blocklist.json \\
      --binary linux-x64=build/dist/guard \\
      --binary darwin-arm64=build/dist/guard \\
      --out manifest.json

SECURITY: guard-update.key is the master key to the whole fleet's root agent.
Keep it in a CI secret / HSM / offline vault. Rotate = re-bake a new public key
into the binary and re-sign.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import ed25519_pure


def sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as f:
        for c in iter(lambda: f.read(65536), b""):
            h.update(c)
    return h.hexdigest()


def cmd_keygen(args):
    seed = os.urandom(32)
    pk = ed25519_pure.publickey(seed)
    out = Path(args.out)
    out.write_bytes(seed)
    try:
        out.chmod(0o600)
    except OSError:
        pass
    print(f"secret seed  -> {out}  (KEEP OFFLINE / in a CI secret)")
    print(f"PUBLIC key   -> bake this into updater.PUBKEY_HEX and rebuild the binary:")
    print(f"  {pk.hex()}")


def _load_seed(path: str) -> tuple[bytes, bytes]:
    seed = Path(path).read_bytes()
    if len(seed) != 32:
        raise SystemExit("key file must be a 32-byte seed (from `keygen`)")
    return seed, ed25519_pure.publickey(seed)


def _sign_bytes(raw: bytes, seed: bytes, pk: bytes) -> str:
    return base64.b64encode(ed25519_pure.sign(raw, seed, pk)).decode()


def cmd_sign(args):
    seed, pk = _load_seed(args.key)
    raw = Path(args.manifest).read_bytes()
    sig = _sign_bytes(raw, seed, pk)
    Path(args.manifest + ".sig").write_text(sig)
    print(f"signed: {args.manifest} -> {args.manifest}.sig")
    print(f"verify: {ed25519_pure.verify(base64.b64decode(sig), raw, pk)}")


def cmd_build_and_sign(args):
    seed, pk = _load_seed(args.key)
    base = args.base_url.rstrip("/")
    # URLs are flat: {base}/{filename}, matching GitHub Release asset names.
    manifest = {"version": args.version, "min_version": args.min_version}
    if args.blocklist:
        bl = Path(args.blocklist)
        manifest["blocklist"] = {"sha256": sha256_file(bl), "url": f"{base}/{bl.name}"}
    binaries = {}
    for spec in args.binary or []:
        plat, path = spec.split("=", 1)
        p = Path(path)
        binaries[plat] = {"sha256": sha256_file(p), "url": f"{base}/{p.name}"}
    if binaries:
        manifest["binary"] = binaries
    raw = json.dumps(manifest, indent=2, sort_keys=True).encode()
    Path(args.out).write_bytes(raw)
    Path(args.out + ".sig").write_text(_sign_bytes(raw, seed, pk))
    print(f"wrote {args.out} (+ .sig) for version {args.version}")
    print(json.dumps(manifest, indent=2))


def main():
    ap = argparse.ArgumentParser(description="Guard OTA manifest signer")
    sub = ap.add_subparsers(dest="cmd", required=True)
    k = sub.add_parser("keygen"); k.add_argument("--out", default="guard-update.key"); k.set_defaults(fn=cmd_keygen)
    s = sub.add_parser("sign"); s.add_argument("manifest"); s.add_argument("--key", required=True); s.set_defaults(fn=cmd_sign)
    b = sub.add_parser("build-and-sign")
    b.add_argument("--version", required=True)
    b.add_argument("--min-version", default="0.0.0")
    b.add_argument("--key", required=True)
    b.add_argument("--base-url", required=True)
    b.add_argument("--blocklist")
    b.add_argument("--binary", action="append", help="plat=path (repeatable)")
    b.add_argument("--out", default="manifest.json")
    b.set_defaults(fn=cmd_build_and_sign)
    args = ap.parse_args()
    args.fn(args)


if __name__ == "__main__":
    main()
