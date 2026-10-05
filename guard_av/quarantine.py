"""
quarantine.py - a reversible, NEUTERED quarantine vault.

Quarantined files are stored XOR-encrypted with a per-item random key, so the
vault never holds a runnable or re-detectable copy of the malware (other AV
products won't fire on it, and double-clicking it does nothing). Each item has
a JSON record with the original path, hashes, threat name and timestamp, and
restore() verifies the SHA-256 before writing the file back.

Layout:  <vault>/<id>.bin  (neutered bytes)   <vault>/<id>.json  (record)
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
from datetime import datetime, timezone
from pathlib import Path

_ID = re.compile(r"^[0-9a-f]{32}$")


class QuarantineError(Exception):
    pass


def _keystream_xor(data: bytes, key: bytes) -> bytes:
    """XOR with a SHA-256 counter-mode keystream (symmetric: apply twice = identity)."""
    out = bytearray(len(data))
    block = 0
    for start in range(0, len(data), 32):
        ks = hashlib.sha256(key + block.to_bytes(8, "big")).digest()
        chunk = data[start:start + 32]
        for i, b in enumerate(chunk):
            out[start + i] = b ^ ks[i]
        block += 1
    return bytes(out)


class QuarantineVault:
    def __init__(self, root: str | Path) -> None:
        self.root = Path(root)

    def _ensure(self) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self.root, 0o700)
        except OSError:  # e.g. a filesystem without POSIX modes
            pass

    def _paths(self, item_id: str) -> tuple[Path, Path]:
        if not _ID.match(item_id or ""):
            raise QuarantineError(f"invalid quarantine id: {item_id!r}")
        return self.root / f"{item_id}.bin", self.root / f"{item_id}.json"

    def quarantine(self, path: str | Path, threat: str = "", remove_original: bool = True) -> dict:
        src = Path(path)
        try:
            data = src.read_bytes()
        except OSError as exc:
            raise QuarantineError(f"cannot read {src}: {exc}") from None
        self._ensure()
        item_id = secrets.token_hex(16)
        key = secrets.token_bytes(32)
        bin_path, meta_path = self._paths(item_id)
        bin_path.write_bytes(_keystream_xor(data, key))
        record = {
            "id": item_id,
            "original_path": str(src.resolve()),
            "sha256": hashlib.sha256(data).hexdigest(),
            "size": len(data),
            "threat": threat,
            "quarantined_at": datetime.now(timezone.utc).isoformat(),
            "key": key.hex(),
        }
        meta_path.write_text(json.dumps(record, indent=2), encoding="utf-8")
        if remove_original:
            try:
                src.unlink()
            except OSError as exc:
                record["note"] = f"original not removed: {exc}"
                meta_path.write_text(json.dumps(record, indent=2), encoding="utf-8")
        return {k: v for k, v in record.items() if k != "key"}

    def list(self) -> list[dict]:
        if not self.root.is_dir():
            return []
        out = []
        for meta in sorted(self.root.glob("*.json")):
            try:
                rec = json.loads(meta.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            rec.pop("key", None)
            out.append(rec)
        out.sort(key=lambda r: r.get("quarantined_at", ""))
        return out

    def _load(self, item_id: str) -> tuple[dict, Path, Path]:
        bin_path, meta_path = self._paths(item_id)
        if not meta_path.exists() or not bin_path.exists():
            raise QuarantineError(f"no quarantined item {item_id}")
        return json.loads(meta_path.read_text(encoding="utf-8")), bin_path, meta_path

    def restore(self, item_id: str, dest: str | Path | None = None, overwrite: bool = False) -> Path:
        rec, bin_path, meta_path = self._load(item_id)
        data = _keystream_xor(bin_path.read_bytes(), bytes.fromhex(rec["key"]))
        if hashlib.sha256(data).hexdigest() != rec["sha256"]:
            raise QuarantineError(f"integrity check failed for {item_id}; not restored")
        target = Path(dest) if dest else Path(rec["original_path"])
        if target.exists() and not overwrite:
            raise QuarantineError(f"{target} exists (pass overwrite=True to replace it)")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        bin_path.unlink()
        meta_path.unlink()
        return target

    def delete(self, item_id: str) -> None:
        _rec, bin_path, meta_path = self._load(item_id)
        bin_path.unlink()
        meta_path.unlink()
