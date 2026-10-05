"""
hashdb.py - exact-match hash signatures (zero false-positive by construction).

Database file format (JSON):
    {"version": 1,
     "entries": [{"sha256": "...", "name": "Threat.Name", "verdict": "malicious"},
                 {"md5": "...", "name": "..."}]}
Each entry carries at least one of md5 / sha1 / sha256. Plain-text lists
(`<hash> <name>` per line, `#` comments) can be imported with load_text().
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path

from .model import Verdict

_ALGOS = {32: "md5", 40: "sha1", 64: "sha256"}
_HEX = re.compile(r"^[0-9a-fA-F]+$")


@dataclass(frozen=True)
class HashEntry:
    name: str
    verdict: Verdict = Verdict.MALICIOUS


def algo_for(digest: str) -> str | None:
    """Infer the algorithm from a hex digest's length (None if not a digest)."""
    if not _HEX.match(digest or ""):
        return None
    return _ALGOS.get(len(digest))


class HashDatabase:
    def __init__(self) -> None:
        self._db: dict[str, dict[str, HashEntry]] = {a: {} for a in _ALGOS.values()}

    def __len__(self) -> int:
        return sum(len(v) for v in self._db.values())

    def add(self, digest: str, name: str, verdict: Verdict | str = Verdict.MALICIOUS) -> None:
        algo = algo_for(digest)
        if algo is None:
            raise ValueError(f"not a md5/sha1/sha256 hex digest: {digest!r}")
        self._db[algo][digest.lower()] = HashEntry(name, Verdict.parse(verdict))

    def lookup(self, hashes: dict[str, str]) -> tuple[str, HashEntry] | None:
        """Return (algo, entry) for the first algorithm that matches."""
        for algo in ("sha256", "sha1", "md5"):
            h = hashes.get(algo)
            if h and h.lower() in self._db[algo]:
                return algo, self._db[algo][h.lower()]
        return None

    # ------------------------------------------------------------------ io
    def load_json(self, path: str | Path) -> int:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        n = 0
        for e in data.get("entries", []):
            name = e.get("name") or "Unnamed"
            verdict = e.get("verdict", "malicious")
            for algo in ("md5", "sha1", "sha256"):
                if e.get(algo):
                    self.add(e[algo], name, verdict)
                    n += 1
        return n

    def load_text(self, path: str | Path, verdict: Verdict | str = Verdict.MALICIOUS) -> int:
        n = 0
        for line in Path(path).read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.split("#", 1)[0].strip()
            if not line:
                continue
            parts = line.split(None, 1)
            if algo_for(parts[0]) is None:
                continue
            self.add(parts[0], parts[1].strip() if len(parts) > 1 else "Hash.Blocklisted", verdict)
            n += 1
        return n

    def load(self, path: str | Path) -> int:
        p = Path(path)
        return self.load_json(p) if p.suffix.lower() == ".json" else self.load_text(p)

    def to_json(self) -> dict:
        entries = []
        for algo, table in self._db.items():
            for digest, entry in sorted(table.items()):
                entries.append({algo: digest, "name": entry.name, "verdict": entry.verdict.label})
        return {"version": 1, "entries": entries}
