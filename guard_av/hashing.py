"""hashing.py - single-pass multi-hashing and Shannon entropy."""

from __future__ import annotations

import hashlib
import math
from collections import Counter
from pathlib import Path

from . import _native

CHUNK = 1024 * 1024


def hash_bytes(data: bytes) -> dict[str, str]:
    return {
        "md5": hashlib.md5(data, usedforsecurity=False).hexdigest(),
        "sha1": hashlib.sha1(data, usedforsecurity=False).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def hash_file(path: str | Path) -> dict[str, str]:
    """MD5/SHA-1/SHA-256 of a file in one streaming pass (constant memory)."""
    md5 = hashlib.md5(usedforsecurity=False)
    sha1 = hashlib.sha1(usedforsecurity=False)
    sha256 = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(CHUNK), b""):
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)
    return {"md5": md5.hexdigest(), "sha1": sha1.hexdigest(), "sha256": sha256.hexdigest()}


def shannon_entropy(data: bytes) -> float:
    """Bits per byte, 0.0 (constant) .. 8.0 (uniformly random)."""
    if _native.NATIVE is not None:
        return _native.NATIVE.shannon_entropy(data)
    if not data:
        return 0.0
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in Counter(data).values())
