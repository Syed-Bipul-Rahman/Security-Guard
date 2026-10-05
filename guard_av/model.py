"""model.py - verdicts, detections and per-file scan results."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import IntEnum


class Verdict(IntEnum):
    """Ordered so max() of several verdicts gives the worst one."""

    CLEAN = 0
    SUSPICIOUS = 1
    MALICIOUS = 2

    @classmethod
    def parse(cls, value: "str | Verdict") -> "Verdict":
        if isinstance(value, Verdict):
            return value
        try:
            return cls[str(value).strip().upper()]
        except KeyError:
            raise ValueError(f"unknown verdict: {value!r}") from None

    @property
    def label(self) -> str:
        return self.name.lower()


@dataclass
class Detection:
    """One reason a file was flagged."""

    engine: str                 # "hash" | "rule" | "yara" | "heuristic" | "archive"
    name: str                   # threat / indicator name, e.g. "Webshell.PHP.SuperglobalExec"
    verdict: Verdict
    description: str = ""
    rule_id: str = ""
    evidence: str = ""
    score: int = 0              # heuristic weight (0 for signature hits)
    whole_file: bool = False    # True when the entire file is the threat (safe to quarantine)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["verdict"] = self.verdict.label
        return d


@dataclass
class ScanResult:
    """Result for one scanned object (a file, or an archive member)."""

    path: str
    size: int = 0
    sha256: str = ""
    md5: str = ""
    sha1: str = ""
    filetype: str = "unknown"
    verdict: Verdict = Verdict.CLEAN
    detections: list[Detection] = field(default_factory=list)
    children: list["ScanResult"] = field(default_factory=list)
    allowlisted: str = ""       # reason, when an allowlist entry suppressed detections
    error: str = ""
    heuristic_score: int = 0

    @property
    def infected(self) -> bool:
        return self.verdict is Verdict.MALICIOUS

    @property
    def threat_name(self) -> str:
        """Name of the most severe detection (own or nested), '' when clean."""
        best: Detection | None = None
        for d in self.iter_detections():
            if best is None or d.verdict > best.verdict:
                best = d
        return best.name if best else ""

    def iter_detections(self):
        yield from self.detections
        for c in self.children:
            yield from c.iter_detections()

    def finalize(self) -> "ScanResult":
        """Recompute the verdict from own detections and children."""
        v = Verdict.CLEAN
        for d in self.detections:
            v = max(v, d.verdict)
        for c in self.children:
            v = max(v, c.verdict)
        self.verdict = v
        return self

    def to_dict(self) -> dict:
        return {
            "path": self.path,
            "size": self.size,
            "sha256": self.sha256,
            "md5": self.md5,
            "sha1": self.sha1,
            "filetype": self.filetype,
            "verdict": self.verdict.label,
            "threat": self.threat_name,
            "heuristic_score": self.heuristic_score,
            "allowlisted": self.allowlisted,
            "error": self.error,
            "detections": [d.to_dict() for d in self.detections],
            "children": [c.to_dict() for c in self.children],
        }
