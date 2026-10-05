"""
engine.py - the scan pipeline.

For every object (a file, or a member unpacked from an archive):

  1. hash (MD5/SHA-1/SHA-256, one pass) and identify the real type by content
  2. allowlist  -> known-good hash or trusted path: stop, CLEAN
  3. hash DB    -> exact match: MALICIOUS (zero-FP signature)
  4. rules      -> YARA rules (*.yar, via yara-x) and the JSON rule format:
                   MALICIOUS or SUSPICIOUS
  5. heuristics -> weighted static indicators, escalated only when they stack
  6. archives   -> recurse into members (bounded depth / size / count)

Results are cached by (sha256, filename) so re-scanning unchanged content is
free. The engine is read-only: it never modifies or deletes anything.
"""

from __future__ import annotations

import os
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from pathlib import Path

from . import filetype as ft
from .allowlist import Allowlist
from .archive import ArchiveLimits, extract
from .hashdb import HashDatabase
from .hashing import hash_bytes, hash_file
from .heuristics import STRONG, analyze
from .model import Detection, ScanResult, Verdict
from .rules import RuleSet
from .yara_rules import YARA_SUFFIXES, YaraRuleSet

DATA_DIR = Path(__file__).resolve().parent / "data"


@dataclass
class EngineConfig:
    max_scan_bytes: int = 64 * 1024 * 1024     # content examined per file (hashes always cover all)
    scan_archives: bool = True
    max_archive_depth: int = 3
    archive_limits: ArchiveLimits = field(default_factory=ArchiveLimits)
    heuristics: bool = True
    suspicious_threshold: int = 70
    malicious_threshold: int = 150
    malicious_min_strong: int = 3              # independent strong indicators needed for MALICIOUS
    skip_dirs: frozenset = frozenset({".git", ".hg", ".svn"})
    cache_size: int = 4096


@dataclass
class ScanSummary:
    scanned: int = 0
    malicious: int = 0
    suspicious: int = 0
    errors: int = 0
    elapsed: float = 0.0
    results: list[ScanResult] = field(default_factory=list)   # non-clean + errored only

    def to_dict(self) -> dict:
        return {
            "scanned": self.scanned, "malicious": self.malicious, "suspicious": self.suspicious,
            "errors": self.errors, "elapsed_sec": round(self.elapsed, 3),
            "results": [r.to_dict() for r in self.results],
        }


def action_hint(result: ScanResult) -> str:
    """'quarantine' when the whole file is the threat, 'review' when malicious code
    may sit inside a legitimate file, '' when there is nothing to do."""
    if result.verdict is not Verdict.MALICIOUS:
        return ""
    if any(d.whole_file for d in result.detections if d.verdict is Verdict.MALICIOUS):
        return "quarantine"
    if ft.is_executable(result.filetype) or ft.is_archive(result.filetype):
        return "quarantine"
    return "review"


class ScanEngine:
    def __init__(self, config: EngineConfig | None = None, rules: RuleSet | None = None,
                 hashdb: HashDatabase | None = None, allowlist: Allowlist | None = None) -> None:
        self.config = config or EngineConfig()
        self.rules = rules if rules is not None else RuleSet()
        self.hashdb = hashdb if hashdb is not None else HashDatabase()
        self.allowlist = allowlist if allowlist is not None else Allowlist()
        self.yara = YaraRuleSet()
        self._cache: OrderedDict[tuple[str, str], ScanResult] = OrderedDict()

    # ------------------------------------------------------------- factory
    @classmethod
    def default(cls, config: EngineConfig | None = None, extra_dirs: list[str | Path] | None = None,
                data_dir: str | Path | None = None) -> "ScanEngine":
        """Bundled signatures + any user-supplied rules/hashes/allowlist.

        A signature database necessarily contains the strings it hunts for, so
        every database file the engine loads is allowlisted by hash: Guard must
        never flag its own definitions.
        """
        engine = cls(config)
        dirs = [Path(data_dir) if data_dir else DATA_DIR] + [Path(d) for d in (extra_dirs or [])]
        for d in dirs:
            engine.load_dir(d)
        return engine

    def load_dir(self, d: str | Path) -> None:
        d = Path(d)
        for f in sorted(d.glob("rules*.json")):
            self.rules.load(f)
            self.allowlist.add_hash(hash_file(f)["sha256"])
        yara_files = sorted(f for f in d.iterdir() if f.suffix.lower() in YARA_SUFFIXES and f.is_file())
        for f in yara_files:
            self.yara.load(f)
            self.allowlist.add_hash(hash_file(f)["sha256"])
        if yara_files:
            self.yara.compile()      # fail here, naming the file, not mid-scan
        for f in sorted(d.glob("hashes*.json")) + sorted(d.glob("hashes*.txt")):
            self.hashdb.load(f)
            self.allowlist.add_hash(hash_file(f)["sha256"])
        for f in sorted(d.glob("allowlist*.json")):
            self.allowlist.merge(Allowlist.load(f))

    # ---------------------------------------------------------------- cache
    def _cache_get(self, key: tuple[str, str]) -> ScanResult | None:
        hit = self._cache.get(key)
        if hit is not None:
            self._cache.move_to_end(key)
        return hit

    def _cache_put(self, key: tuple[str, str], res: ScanResult) -> None:
        if self.config.cache_size <= 0:
            return
        self._cache[key] = res
        if len(self._cache) > self.config.cache_size:
            self._cache.popitem(last=False)

    # ------------------------------------------------------------------ scan
    def scan_bytes(self, data: bytes, name: str = "<buffer>", hashes: dict | None = None,
                   size: int | None = None, depth: int = 0) -> ScanResult:
        hashes = hashes or hash_bytes(data)
        size = len(data) if size is None else size
        tag = ft.identify(data[:4096], name)
        res = ScanResult(path=name, size=size, filetype=tag, **hashes)

        reason = self.allowlist.file_reason(name, hashes["sha256"])
        if reason:
            res.allowlisted = reason
            return res

        key = (hashes["sha256"], Path(name.split("!")[-1]).name)
        cached = self._cache_get(key)
        if cached is not None:
            return self._rebase(cached, name)

        hit = self.hashdb.lookup(hashes)
        if hit is not None:
            algo, entry = hit
            res.detections.append(Detection(
                engine="hash", name=entry.name, verdict=entry.verdict, whole_file=True,
                description=f"{algo} matches a known-malware signature",
                evidence=f"{algo}:{hashes[algo]}"))

        for det in self.rules.scan(data, name, tag, size) + self.yara.scan(data):
            if not self.allowlist.suppresses(det):
                res.detections.append(det)

        if self.config.heuristics:
            self._heuristics(res, data, name, tag)

        if self.config.scan_archives and ft.is_archive(tag) and depth < self.config.max_archive_depth:
            self._scan_archive(res, data, name, tag, depth)

        res.finalize()
        self._cache_put(key, res)
        return res

    def _heuristics(self, res: ScanResult, data: bytes, name: str, tag: str) -> None:
        indicators = analyze(data, name, tag)
        res.heuristic_score = sum(i.score for i in indicators)
        if res.heuristic_score < self.config.suspicious_threshold:
            return
        strong = [i for i in indicators if i.score >= STRONG]
        malicious = (res.heuristic_score >= self.config.malicious_threshold
                     and len(strong) >= self.config.malicious_min_strong)
        top = max(indicators, key=lambda i: i.score)
        det = Detection(
            engine="heuristic",
            name=f"Heur.{'Malware' if malicious else 'Suspicious'}.{top.id}",
            verdict=Verdict.MALICIOUS if malicious else Verdict.SUSPICIOUS,
            description="; ".join(i.description for i in indicators),
            evidence=", ".join(str(i) for i in indicators),
            score=res.heuristic_score,
            whole_file=ft.is_executable(tag),
        )
        if not self.allowlist.suppresses(det):
            res.detections.append(det)

    def _scan_archive(self, res: ScanResult, data: bytes, name: str, tag: str, depth: int) -> None:
        ex = extract(data, tag, name, self.config.archive_limits)
        if ex.bomb:
            det = Detection(engine="archive", name="Archive.Bomb", verdict=Verdict.SUSPICIOUS,
                            description="decompression bomb (extreme compression ratio)",
                            evidence="; ".join(ex.notes), whole_file=True)
            if not self.allowlist.suppresses(det):
                res.detections.append(det)
        for m in ex.members:
            child = self.scan_bytes(m.data, f"{name}!{m.name}", depth=depth + 1)
            if child.verdict is not Verdict.CLEAN:
                res.children.append(child)

    @staticmethod
    def _rebase(cached: ScanResult, name: str) -> ScanResult:
        """Copy a cached result onto a new path (same content, same filename)."""
        clone = ScanResult(**{**cached.__dict__, "path": name,
                              "detections": list(cached.detections),
                              "children": list(cached.children)})
        return clone

    def scan_file(self, path: str | Path) -> ScanResult:
        p = Path(path)
        try:
            size = p.stat().st_size
            with p.open("rb") as fh:
                data = fh.read(self.config.max_scan_bytes)
            hashes = hash_bytes(data) if size <= len(data) else hash_file(p)
        except OSError as exc:
            return ScanResult(path=str(p), error=f"{type(exc).__name__}: {exc}")
        return self.scan_bytes(data, str(p), hashes=hashes, size=size)

    def iter_files(self, target: str | Path):
        t = Path(target)
        if t.is_file():
            yield t
            return
        for dirpath, dirnames, filenames in os.walk(t):
            dirnames[:] = sorted(d for d in dirnames if d not in self.config.skip_dirs)
            for fn in sorted(filenames):
                p = Path(dirpath) / fn
                if p.is_symlink() or not p.is_file():
                    continue   # never follow links out of the tree; skip fifos/sockets
                yield p

    def scan_path(self, target: str | Path, on_result=None) -> ScanSummary:
        start = time.monotonic()
        summary = ScanSummary()
        for p in self.iter_files(target):
            r = self.scan_file(p)
            summary.scanned += 1
            if r.error:
                summary.errors += 1
            elif r.verdict is Verdict.MALICIOUS:
                summary.malicious += 1
            elif r.verdict is Verdict.SUSPICIOUS:
                summary.suspicious += 1
            if r.error or r.verdict is not Verdict.CLEAN:
                summary.results.append(r)
            if on_result is not None:
                on_result(r)
        summary.elapsed = time.monotonic() - start
        return summary
