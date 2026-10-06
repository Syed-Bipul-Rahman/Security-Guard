"""Shared helpers for the tests that run the Rust `guard` binary (cli/) against
the Python code it replaces.

The binary comes from $GUARD_RS_BIN, else cli/target/{release,debug}/guard. The
tests skip without one locally, and fail without one in CI.
"""

from __future__ import annotations

import functools
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
EXE = ".exe" if sys.platform.startswith("win") else ""
WINDOWS = sys.platform.startswith("win")


@pytest.fixture(scope="session")
def rust_guard() -> Path:
    env = os.environ.get("GUARD_RS_BIN")
    candidates = [Path(env)] if env else [ROOT / "cli" / "target" / t / f"guard{EXE}" for t in ("release", "debug")]
    for c in candidates:
        if c.is_file():
            return c.resolve()
    msg = f"Rust guard binary not built (looked at {', '.join(map(str, candidates))}); cargo build --manifest-path cli/Cargo.toml"
    if os.environ.get("CI"):
        pytest.fail(msg)
    pytest.skip(msg)


def clean_env(env: dict | None = None) -> dict:
    """The current environment without proxies, plus `env`."""
    full = {k: v for k, v in os.environ.items() if "proxy" not in k.lower()}
    full.update(env or {})
    return full


def run_rust(exe: Path, *args: str, env: dict | None = None, cwd=None) -> subprocess.CompletedProcess:
    return subprocess.run([str(exe), *args], capture_output=True, env=clean_env(env), timeout=120, cwd=cwd)


def run_python(*args: str, env: dict | None = None, cwd=None) -> subprocess.CompletedProcess:
    """guard.py, the reference implementation the binary is compared against."""
    return subprocess.run([sys.executable, str(ROOT / "guard.py"), *args], capture_output=True,
                          env=clean_env(env), timeout=120, cwd=cwd)


@functools.lru_cache(maxsize=None)
def binary_version(exe: Path) -> str:
    """The version the binary runs as (release builds bake GUARD_VERSION in)."""
    r = run_rust(exe, "version")
    assert r.returncode == 0
    return r.stdout.decode().strip().removeprefix("guard ")
