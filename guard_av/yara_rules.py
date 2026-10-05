"""
yara_rules.py - real YARA rules, compiled and matched by yara-x in guard_core.

Any *.yar / *.yara file in a signature directory is loaded; each file is its own
namespace (the file stem), so community rule sets with clashing rule names can
sit side by side. The JSON rules in rules.py keep working unchanged next to them.

Guard reads three optional metadata keys:

    meta:
        verdict = "malicious"      // or "suspicious" (the default)
        whole_file = true          // the whole file is the threat (quarantine it)
        description = "..."

Rules without a verdict report SUSPICIOUS: third-party rules vary in precision,
and Guard's policy is that only high-confidence signatures say MALICIOUS. A hit's
rule id is "yara:<namespace>.<rule>", which the allowlist can disable.

YARA needs the Rust core. Without it the sources are still read (and reported by
`unavailable`), but nothing is matched.
"""

from __future__ import annotations

import json
from pathlib import Path

from . import _native
from .model import Detection, Verdict
from .rules import MAX_MATCHES_PER_STRING, RuleError, _evidence

YARA_SUFFIXES = (".yar", ".yara")
SCAN_TIMEOUT_SEC = 10.0


class YaraRuleSet:
    def __init__(self) -> None:
        self.sources: list[tuple[str, str, str]] = []   # (namespace, origin, source)
        self._compiled = None
        self._dirty = False
        self.timeouts = 0                               # scans abandoned at SCAN_TIMEOUT_SEC

    def __len__(self) -> int:
        compiled = self.compile()
        return len(compiled) if compiled is not None else 0

    @property
    def unavailable(self) -> bool:
        """True when rules were loaded but there is no engine to run them."""
        return bool(self.sources) and _native.NATIVE is None

    @property
    def warnings(self) -> list[str]:
        compiled = self.compile()
        return list(compiled.warnings) if compiled is not None else []

    def add_source(self, source: str, origin: str = "<string>", namespace: str = "default") -> None:
        self.sources.append((namespace, origin, source))
        self._dirty = True

    def load(self, path: str | Path) -> None:
        p = Path(path)
        self.add_source(p.read_text(encoding="utf-8", errors="surrogateescape"), str(p), p.stem)

    def compile(self):
        """The compiled rules (None without sources or without the Rust core).
        Raises RuleError naming the file and line when a source doesn't compile."""
        nat = _native.NATIVE
        if nat is None or not self.sources:
            return None
        if self._dirty or self._compiled is None:
            try:
                self._compiled = nat.YaraRules(self.sources)
            except ValueError as exc:
                raise RuleError(str(exc)) from None
            self._dirty = False
        return self._compiled

    def scan(self, data: bytes) -> list[Detection]:
        compiled = self.compile()
        if compiled is None:
            return []
        try:
            hits = compiled.scan(data, SCAN_TIMEOUT_SEC, MAX_MATCHES_PER_STRING)
        except TimeoutError:
            self.timeouts += 1
            return []
        out: list[Detection] = []
        for namespace, rule, tags, meta_json, first in hits:
            meta = json.loads(meta_json)
            try:
                verdict = Verdict.parse(meta.get("verdict", "suspicious"))
            except ValueError:
                verdict = Verdict.SUSPICIOUS
            evidence = _evidence(data, {first[0]: [first[1]]}) if first else ""
            out.append(Detection(
                engine="yara", name=rule, verdict=max(verdict, Verdict.SUSPICIOUS),
                rule_id=f"yara:{namespace}.{rule}",
                description=str(meta.get("description", "")) or " ".join(tags),
                evidence=evidence, whole_file=meta.get("whole_file") is True,
            ))
        return out
