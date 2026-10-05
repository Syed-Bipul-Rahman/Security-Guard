"""
_native.py - optional Rust acceleration (the `guard_core` extension, see core/).

When guard_core is importable, rule matching and content heuristics run in
Rust; otherwise the pure-Python implementations are used. Results are
identical either way (the test suite runs every engine test on both).
Set GUARD_AV_BACKEND=python to force the Python implementation.
"""

from __future__ import annotations

import os


def load():
    if os.environ.get("GUARD_AV_BACKEND", "").strip().lower() == "python":
        return None
    try:
        import guard_core
    except ImportError:
        return None
    return guard_core


NATIVE = load()


def backend() -> str:
    return "rust" if NATIVE is not None else "python"
