#!/usr/bin/env python3
"""
dep_blocklist.py - check dependency manifests against the GitHub malware blocklist.

Reusable by the Guard scanner/watcher. Loads malware-blocklist.json (produced by
malware-feed/collect_malware_advisories.py) and, given a manifest file's path +
content, returns any dependency whose name GitHub flagged as malware.

Blocklist path resolution (first that exists):
  $GUARD_DEP_BLOCKLIST  ->  <this dir>/malware-feed/malware-blocklist.json  ->  <this dir>/malware-blocklist.json
Loads lazily; if absent, checks are no-ops (feature simply off).
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from pathlib import Path


def _parse_ver(v: str):
    """Extract a comparable (major, minor, patch) tuple from a version string/spec."""
    m = re.search(r"(\d+)\.(\d+)\.(\d+)", v or "")
    if m:
        return tuple(int(x) for x in m.groups())
    m = re.search(r"(\d+)\.(\d+)", v or "")
    if m:
        return (int(m.group(1)), int(m.group(2)), 0)
    m = re.search(r"(\d+)", v or "")
    return (int(m.group(1)), 0, 0) if m else None


def _in_range(installed: str, range_str: str) -> bool:
    """Does `installed` satisfy one GitHub vulnerable_version_range (commas = AND)?"""
    import operator
    rs = (range_str or "").strip()
    if rs in (">= 0", ">=0", "*", ""):
        return True  # whole package is malicious (typosquat / fully bad)
    iv = _parse_ver(installed)
    if iv is None:
        return False  # unknown installed version -> don't claim a match (avoid false positives)
    ops = {">=": operator.ge, "<=": operator.le, "==": operator.eq,
           "=": operator.eq, ">": operator.gt, "<": operator.lt}
    for clause in rs.split(","):
        m = re.match(r"\s*(>=|<=|==|=|>|<)\s*(.+)", clause.strip())
        if not m:
            return False
        tv = _parse_ver(m.group(2))
        if tv is None or not ops[m.group(1)](iv, tv):
            return False
    return True


def _version_flagged(installed: str, ranges: list[str]) -> bool:
    """True if the installed version matches ANY flagged range (OR across advisories)."""
    return any(_in_range(installed, r) for r in ranges)


@dataclass
class DepFinding:
    ecosystem: str
    name: str
    version: str
    malicious_ranges: str
    where: str
    severity: str = "critical"
    sig_id: str = "dep.malware"
    category: str = "malicious-dependency"

    @property
    def desc(self) -> str:
        return f"malicious dependency '{self.name}' ({self.ecosystem}); GitHub-flagged range: {self.malicious_ranges}"


def _default_paths() -> list[Path]:
    here = Path(__file__).resolve().parent
    envp = os.environ.get("GUARD_DEP_BLOCKLIST")
    paths = []
    if envp:
        paths.append(Path(envp))
    paths += [here / "malware-feed" / "malware-blocklist.json", here / "malware-blocklist.json"]
    return paths


class DepBlocklist:
    # manifest basename -> ecosystem
    NPM_FILES = {"package.json", "package-lock.json", "npm-shrinkwrap.json"}
    PIP_FILES = {"requirements.txt", "Pipfile.lock"}

    def __init__(self, blocklist_path: str | Path | None = None):
        self.blocklist: dict[str, dict] = {}
        self.loaded_from: str | None = None
        candidates = [Path(blocklist_path)] if blocklist_path else _default_paths()
        for p in candidates:
            try:
                if p.exists():
                    self.blocklist = json.loads(p.read_text(encoding="utf-8"))
                    self.loaded_from = str(p)
                    break
            except (OSError, json.JSONDecodeError):
                continue

    @property
    def available(self) -> bool:
        return bool(self.blocklist)

    def count(self) -> int:
        return sum(len(v) for v in self.blocklist.values())

    def is_manifest(self, rel_or_name: str) -> bool:
        base = os.path.basename(rel_or_name)
        return (base in self.NPM_FILES or base in self.PIP_FILES
                or bool(re.match(r"requirements.*\.txt$", base)))

    def _ecosystem(self, base: str) -> str | None:
        if base in self.NPM_FILES:
            return "npm"
        if base in self.PIP_FILES or re.match(r"requirements.*\.txt$", base):
            return "pip"
        return None

    def _names(self, base: str, content: str):
        """Yield (name, version) from a manifest's content."""
        if base == "package.json":
            try:
                data = json.loads(content)
            except json.JSONDecodeError:
                return
            for key in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
                for n, v in (data.get(key) or {}).items():
                    yield n, str(v)
        elif base in ("package-lock.json", "npm-shrinkwrap.json"):
            try:
                data = json.loads(content)
            except json.JSONDecodeError:
                return
            for pkgpath, meta in (data.get("packages") or {}).items():
                if pkgpath:
                    yield pkgpath.split("node_modules/")[-1], (meta or {}).get("version", "")
            def walk(deps):
                for n, meta in (deps or {}).items():
                    yield n, (meta or {}).get("version", "")
                    yield from walk((meta or {}).get("dependencies"))
            yield from walk(data.get("dependencies"))
        elif base == "Pipfile.lock":
            try:
                data = json.loads(content)
            except json.JSONDecodeError:
                return
            for sect in ("default", "develop"):
                for n, meta in (data.get(sect) or {}).items():
                    yield n, (meta or {}).get("version", "").lstrip("=")
        else:  # requirements*.txt
            for line in content.splitlines():
                line = line.strip()
                if not line or line.startswith(("#", "-")):
                    continue
                m = re.match(r"^([A-Za-z0-9._-]+)\s*(?:==\s*([^\s;]+))?", line)
                if m:
                    yield m.group(1), (m.group(2) or "")

    def check_manifest(self, rel_path: str, content: str) -> list[DepFinding]:
        if not self.available:
            return []
        base = os.path.basename(rel_path)
        eco = self._ecosystem(base)
        if not eco:
            return []
        eco_bl = self.blocklist.get(eco) or {}
        if not eco_bl:
            return []
        out = []
        seen = set()
        for name, ver in self._names(base, content):
            if name not in eco_bl or (name, ver) in seen:
                continue
            ranges = eco_bl[name]
            # Only flag if the INSTALLED version matches a flagged range — a name
            # match alone false-positives on legit packages (chalk, axios, ...) that
            # only had specific compromised versions.
            if not _version_flagged(ver, ranges):
                continue
            seen.add((name, ver))
            out.append(DepFinding(eco, name, ver or "?", ", ".join(ranges), rel_path))
        return out


if __name__ == "__main__":
    import sys
    bl = DepBlocklist()
    print(f"blocklist: {'loaded from ' + bl.loaded_from if bl.available else 'NOT FOUND'} "
          f"({bl.count()} names)" if bl.available else "blocklist NOT FOUND")
    if len(sys.argv) > 1 and bl.available:
        p = Path(sys.argv[1])
        for f in bl.check_manifest(p.name, p.read_text(encoding="utf-8", errors="replace")):
            print(f"[{f.severity}] {f.where}: {f.desc} (your version: {f.version})")
