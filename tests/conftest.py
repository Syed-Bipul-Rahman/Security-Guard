"""Shared fixtures and synthetic-binary builders for the test suite."""

from __future__ import annotations

import gzip
import io
import random
import struct
import sys
import tarfile
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
TESTS = Path(__file__).resolve().parent
for p in (str(ROOT), str(TESTS)):
    if p not in sys.path:
        sys.path.insert(0, p)

from guard_av.engine import EngineConfig, ScanEngine  # noqa: E402

EXEC, WRITE, READ, CODE = 0x20000000, 0x80000000, 0x40000000, 0x00000020


def random_bytes(n: int, seed: int = 7) -> bytes:
    return random.Random(seed).randbytes(n)


def build_pe(sections=None, entry: int = 0x1000, extra: bytes = b"", opt_magic: int = 0x10B,
             dll: bool = False) -> bytes:
    """A minimal, structurally valid PE32 image.

    sections: list of (name: bytes, flags: int, body: bytes); virtual addresses
    are assigned 0x1000, 0x2000, ... in order.
    """
    if sections is None:
        sections = [(b".text", EXEC | READ | CODE, b"\x90" * 512),
                    (b".data", READ | WRITE, b"\x00" * 512)]
    opt_size = 0xE0
    headers = 0x40 + 4 + 20 + opt_size + 40 * len(sections)
    raw = (headers + 0x1FF) & ~0x1FF
    dos = bytearray(0x40)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x40)
    coff = struct.pack("<HHIIIHH", 0x14C, len(sections), 0, 0, 0, opt_size, 0x2000 if dll else 0x0102)
    opt = bytearray(opt_size)
    struct.pack_into("<H", opt, 0, opt_magic)
    struct.pack_into("<I", opt, 16, entry)
    table, bodies = b"", b""
    ptr = raw
    for i, (name, flags, body) in enumerate(sections):
        table += struct.pack("<8sIIIIIIHHI", name, len(body), 0x1000 * (i + 1), len(body), ptr,
                             0, 0, 0, 0, flags)
        bodies += body
        ptr += len(body)
    head = bytes(dos) + b"PE\0\0" + coff + bytes(opt) + table
    return head + b"\0" * (raw - len(head)) + bodies + extra


def build_elf(body: bytes = b"") -> bytes:
    return b"\x7fELF\x02\x01\x01" + b"\0" * 9 + body


def make_zip(files: dict[str, bytes], encrypt_flag: set[str] | None = None) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in files.items():
            zf.writestr(name, data)
    raw = bytearray(buf.getvalue())
    for name in encrypt_flag or ():
        # flip the "encrypted" general-purpose bit in both headers for this member
        enc = name.encode()
        for sig, off in ((b"PK\x03\x04", 6), (b"PK\x01\x02", 8)):
            i = 0
            while True:
                i = raw.find(sig, i)
                if i < 0:
                    break
                name_off = i + (30 if sig == b"PK\x03\x04" else 46)
                if raw[name_off:name_off + len(enc)] == enc:
                    raw[i + off] |= 0x1
                i += 4
    return bytes(raw)


def make_tar(files: dict[str, bytes], mode: str = "w") -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode=mode) as tf:
        for name, data in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
        d = tarfile.TarInfo("adir")
        d.type = tarfile.DIRTYPE
        tf.addfile(d)
    return buf.getvalue()


def gz(data: bytes) -> bytes:
    return gzip.compress(data)


@pytest.fixture(scope="session")
def engine() -> ScanEngine:
    return ScanEngine.default()


@pytest.fixture
def fresh_engine() -> ScanEngine:
    return ScanEngine.default(EngineConfig())


@pytest.fixture(autouse=True)
def _isolated_home(tmp_path, monkeypatch):
    """Never let a test touch the real ~/.guard."""
    monkeypatch.setenv("GUARD_HOME", str(tmp_path / "guard_home"))
    monkeypatch.delenv("GUARD_DEP_BLOCKLIST", raising=False)
    yield


def write(path: Path, data: bytes | str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(data, str):
        data = data.encode()
    path.write_bytes(data)
    return path

