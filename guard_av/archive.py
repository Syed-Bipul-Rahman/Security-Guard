"""
archive.py - bounded extraction of zip / tar / gzip members for scanning.

Everything happens in memory and nothing is ever written to disk. Hard limits
keep a hostile archive (zip bomb, million-entry tar, path tricks) from costing
more than a bounded amount of CPU and RAM:

  max_members        members examined per archive
  max_member_size    bytes read from a single member
  max_total_size     bytes read across one archive
  max_ratio          compression ratio that marks a member as a likely bomb
"""

from __future__ import annotations

import bz2
import gzip
import io
import lzma
import tarfile
import zipfile
import zlib
from dataclasses import dataclass, field


@dataclass
class ArchiveLimits:
    max_members: int = 1000
    max_member_size: int = 32 * 1024 * 1024
    max_total_size: int = 256 * 1024 * 1024
    max_ratio: int = 200


@dataclass
class Member:
    name: str
    data: bytes


@dataclass
class Extraction:
    members: list[Member] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)   # limits hit, errors
    bomb: bool = False
    encrypted: bool = False


def _read_capped(fh, cap: int) -> tuple[bytes, bool]:
    data = fh.read(cap + 1)
    return data[:cap], len(data) > cap


def extract_zip(data: bytes, lim: ArchiveLimits) -> Extraction:
    ex = Extraction()
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except (zipfile.BadZipFile, ValueError) as exc:
        ex.notes.append(f"bad zip: {exc}")
        return ex
    total = 0
    with zf:
        infos = [i for i in zf.infolist() if not i.is_dir()]
        if len(infos) > lim.max_members:
            ex.notes.append(f"{len(infos)} members; scanned first {lim.max_members}")
            infos = infos[:lim.max_members]
        for info in infos:
            if info.flag_bits & 0x1:
                ex.encrypted = True
                ex.notes.append(f"encrypted member skipped: {info.filename}")
                continue
            if info.compress_size and info.file_size / info.compress_size > lim.max_ratio \
                    and info.file_size > 1024 * 1024:
                ex.bomb = True
                ex.notes.append(f"compression ratio {info.file_size // info.compress_size}:1 "
                                f"on {info.filename}; not extracted")
                continue
            budget = min(lim.max_member_size, lim.max_total_size - total)
            if budget <= 0:
                ex.notes.append("total size budget exhausted")
                break
            try:
                with zf.open(info) as fh:
                    body, truncated = _read_capped(fh, budget)
            except (zipfile.BadZipFile, NotImplementedError, RuntimeError, OSError, EOFError,
                    zlib.error) as exc:
                ex.notes.append(f"cannot read {info.filename}: {exc}")
                continue
            if truncated:
                ex.notes.append(f"{info.filename} truncated at {budget} bytes")
            total += len(body)
            ex.members.append(Member(info.filename, body))
    return ex


def extract_tar(data: bytes, lim: ArchiveLimits) -> Extraction:
    ex = Extraction()
    try:
        tf = tarfile.open(fileobj=io.BytesIO(data), mode="r:*")
    except (tarfile.TarError, EOFError, OSError, lzma.LZMAError) as exc:
        ex.notes.append(f"bad tar: {exc}")
        return ex
    total = 0
    seen = 0
    with tf:
        try:
            for info in tf:
                if not info.isfile():
                    continue
                seen += 1
                if seen > lim.max_members:
                    ex.notes.append(f"more than {lim.max_members} members; rest skipped")
                    break
                budget = min(lim.max_member_size, lim.max_total_size - total)
                if budget <= 0:
                    ex.notes.append("total size budget exhausted")
                    break
                fh = tf.extractfile(info)
                body, truncated = _read_capped(fh, budget)
                if truncated:
                    ex.notes.append(f"{info.name} truncated at {budget} bytes")
                total += len(body)
                ex.members.append(Member(info.name, body))
        except (tarfile.TarError, EOFError, OSError, lzma.LZMAError) as exc:
            ex.notes.append(f"tar read error: {exc}")
    return ex


def _decompress_stream(opener, data: bytes, name: str, lim: ArchiveLimits) -> Extraction:
    ex = Extraction()
    try:
        with opener(io.BytesIO(data)) as fh:
            body, truncated = _read_capped(fh, lim.max_member_size)
    except (OSError, EOFError, lzma.LZMAError, ValueError) as exc:
        ex.notes.append(f"bad stream: {exc}")
        return ex
    if truncated and len(data) and len(body) / len(data) > lim.max_ratio:
        ex.bomb = True
        ex.notes.append(f"decompresses beyond {lim.max_member_size} bytes at >{lim.max_ratio}:1")
    elif truncated:
        ex.notes.append(f"stream truncated at {lim.max_member_size} bytes")
    ex.members.append(Member(name, body))
    return ex


def _strip(name: str, *exts: str) -> str:
    low = name.lower()
    for e in exts:
        if low.endswith(e):
            return name[: -len(e)] or "payload"
    return name + ".out"


def extract(data: bytes, tag: str, name: str, lim: ArchiveLimits | None = None) -> Extraction:
    """Dispatch on the content type tag from filetype.identify()."""
    lim = lim or ArchiveLimits()
    if tag == "zip":
        return extract_zip(data, lim)
    if tag == "tar":
        return extract_tar(data, lim)
    if tag in ("gzip", "bzip2", "xz"):
        # a compressed tarball is a tar; otherwise it's a single compressed stream
        tar = extract_tar(data, lim)
        if tar.members:
            return tar
        opener = {"gzip": gzip.GzipFile, "bzip2": bz2.BZ2File, "xz": lzma.LZMAFile}[tag]
        return _decompress_stream(lambda f: opener(fileobj=f) if tag == "gzip" else opener(f),
                                  data, _strip(name, ".gz", ".bz2", ".xz", ".tgz"), lim)
    ex = Extraction()
    ex.notes.append(f"{tag} archives are not unpacked (no stdlib decoder)")
    return ex
