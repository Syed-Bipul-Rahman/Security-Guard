"""
allowlist.py - false-positive suppression.

A file is allowlisted when ANY of these match:
  * its SHA-256 is a known-good hash (vendor binaries, the engine's own DBs)
  * its path matches a glob (fnmatch, '/'-normalised; '**' allowed)
  * the detection's rule id / threat name is disabled globally

JSON format:
    {"sha256": ["<hex>", ...],
     "paths": ["*/vendor/trusted/*", ...],
     "rules": ["rule.id.or.Threat.Name", ...]}
"""

from __future__ import annotations

import fnmatch
import json
from pathlib import Path

from .model import Detection


class Allowlist:
    def __init__(self, sha256: list[str] | None = None, paths: list[str] | None = None,
                 rules: list[str] | None = None) -> None:
        self.sha256: set[str] = {h.lower() for h in (sha256 or [])}
        self.paths: list[str] = [p.replace("\\", "/") for p in (paths or [])]
        self.rules: set[str] = set(rules or [])

    @classmethod
    def load(cls, path: str | Path) -> "Allowlist":
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        return cls(data.get("sha256"), data.get("paths"), data.get("rules"))

    def merge(self, other: "Allowlist") -> "Allowlist":
        self.sha256 |= other.sha256
        self.paths += [p for p in other.paths if p not in self.paths]
        self.rules |= other.rules
        return self

    def add_hash(self, sha256: str) -> None:
        self.sha256.add(sha256.lower())

    def file_reason(self, path: str, sha256: str = "") -> str:
        """Why this whole file is trusted ('' if it isn't)."""
        if sha256 and sha256.lower() in self.sha256:
            return f"known-good hash {sha256[:16]}"
        norm = path.replace("\\", "/")
        for pat in self.paths:
            if fnmatch.fnmatch(norm, pat):
                return f"path matches {pat}"
        return ""

    def suppresses(self, det: Detection) -> bool:
        return bool(det.rule_id and det.rule_id in self.rules) or det.name in self.rules

    def to_json(self) -> dict:
        return {"sha256": sorted(self.sha256), "paths": list(self.paths), "rules": sorted(self.rules)}
