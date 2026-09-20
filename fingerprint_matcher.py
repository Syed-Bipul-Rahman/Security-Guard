#!/usr/bin/env python3
"""
fingerprint_matcher.py — match source content against the incident signature set.

Covers CATEGORIES 1-6 from the signature database:
  1. .env malicious AUTH_API_KEY (base64 C2 URL)
  2. malicious/attack-added GitHub workflows
  3. eval(proxyInfo) IIFE injection (literal combo + structural regex)
  4. obfuscated C2 payload fingerprints
  5. VS Code auto-run dropper markers (also handled structurally in vscode_guard.py)
  6. dropper command strings

Matches both working-tree file CONTENT and git DIFF text (added lines only, so
payloads that exist only in history are caught even when HEAD looks clean).

Severity model: any 'critical' hit => file/commit is INFECTED.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class Finding:
    where: str          # file path or "diff"
    sig_id: str
    severity: str
    category: str
    desc: str
    evidence: str = ""

    def __str__(self) -> str:
        ev = f"  <<{self.evidence}>>" if self.evidence else ""
        return f"[{self.severity.upper()}] {self.where}: {self.sig_id} ({self.category}) — {self.desc}{ev}"


_FLAG_MAP = {"DOTALL": re.DOTALL, "IGNORECASE": re.IGNORECASE, "MULTILINE": re.MULTILINE}


def _snippet(text: str, needle: str, span: int = 40) -> str:
    i = text.find(needle)
    if i < 0:
        return ""
    start, end = max(0, i - span), min(len(text), i + len(needle) + span)
    return text[start:end].replace("\n", "\\n")


class FingerprintMatcher:
    def __init__(self, sig: dict) -> None:
        self.sig = sig
        self.literals = sig.get("literals", [])
        self.combo_rules = sig.get("combo_rules", [])
        self.network_iocs = sig.get("network_iocs", [])
        self.scan_exts = set(sig.get("scan_extensions", [".ts", ".js", ".mjs", ".cjs"]))
        self.skip_prefixes = tuple(sig.get("skip_path_prefixes", []))
        self.dropper_names = set(sig.get("known_dropper_filenames", []))
        self.suspicious_workflows = set(sig.get("suspicious_workflow_names", []))

        # Precompile regexes
        self.regexes = []
        for r in sig.get("regexes", []):
            flags = 0
            for f in str(r.get("flags", "")).split("|"):
                flags |= _FLAG_MAP.get(f.strip().upper(), 0)
            self.regexes.append((r, re.compile(r["pattern"], flags)))

    # ------------------------------------------------------------------ utils
    def _skip(self, path: str) -> bool:
        return any(path.startswith(p) for p in self.skip_prefixes)

    def _applies(self, lit: dict, path: str) -> bool:
        applies_to = lit.get("applies_to")
        if not applies_to:
            return True
        base = Path(path).name
        return any(path.endswith(a) or base == a.lstrip("./").split("/")[-1] or path.endswith(a.lstrip(".")) for a in applies_to)

    # ---------------------------------------------------------------- content
    def scan_content(self, path: str, content: str) -> list[Finding]:
        findings: list[Finding] = []
        if self._skip(path):
            return findings
        base = Path(path).name
        ext = Path(path).suffix.lower()

        # Known dropper filename (independent of content)
        if base in self.dropper_names:
            findings.append(Finding(path, "drop.file.name", "critical", "dropper-file",
                                    "known dropper filename", base))

        # Workflow filename signal
        norm = path.replace("\\", "/")
        for wf in self.suspicious_workflows:
            if norm.endswith(wf) or norm == wf:
                findings.append(Finding(path, "wf.name", "high", "workflow",
                                        "attack-associated workflow filename (confirm via baseline diff)", wf))

        # Literal signatures
        for lit in self.literals:
            if not self._applies(lit, path):
                continue
            val = lit["value"]
            # For .ts/.js payload fingerprints, honor extension scoping when category says so
            if lit.get("category") == "obfuscated-c2" and lit.get("applies_to") is None and ext and ext not in self.scan_exts and ext not in (".env",):
                # obfuscated payload is only meaningful in scannable source or config; still allow config exts
                pass
            if val in content:
                findings.append(Finding(path, lit["id"], lit["severity"], lit.get("category", "?"),
                                        lit["desc"], _snippet(content, val)))

        # Combo rules (all_of substrings present)
        for combo in self.combo_rules:
            if all(s in content for s in combo["all_of"]):
                findings.append(Finding(path, combo["id"], combo["severity"], combo.get("category", "?"),
                                        combo["desc"], " + ".join(combo["all_of"])))

        # Structural regexes
        for r, rx in self.regexes:
            m = rx.search(content)
            if m:
                ev = m.group(0)[:80].replace("\n", "\\n")
                findings.append(Finding(path, r["id"], r["severity"], r.get("category", "?"),
                                        r["desc"], ev))

        # Network IOCs anywhere
        for ioc in self.network_iocs:
            if ioc["value"] in content:
                findings.append(Finding(path, ioc["id"], ioc["severity"], "network-ioc",
                                        ioc["desc"], ioc["value"]))
        return findings

    def scan_file(self, path: str | Path) -> list[Finding]:
        p = Path(path)
        try:
            content = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return []
        return self.scan_content(str(p), content)

    # ------------------------------------------------------------------- diff
    def scan_diff(self, diff_text: str) -> list[Finding]:
        """Scan a unified git diff, considering only ADDED lines (+, not +++)."""
        added = "\n".join(
            line[1:] for line in diff_text.splitlines()
            if line.startswith("+") and not line.startswith("+++")
        )
        findings = self.scan_content("diff", added)

        # Added workflow files from diff headers
        for line in diff_text.splitlines():
            if line.startswith("+++ b/.github/workflows/"):
                findings.append(Finding("diff", "wf.added", "high", "workflow",
                                        "workflow file added by this diff", line[6:]))
        return findings

    # --------------------------------------------------------------- verdicts
    @staticmethod
    def is_infected(findings: list[Finding]) -> bool:
        return any(f.severity == "critical" for f in findings)


if __name__ == "__main__":
    import json
    import sys

    sig_path = Path(__file__).with_name("signatures.json")
    matcher = FingerprintMatcher(json.loads(sig_path.read_text(encoding="utf-8")))

    if len(sys.argv) < 2:
        print("usage: fingerprint_matcher.py <file> [file ...]   |   --diff < patch")
        raise SystemExit(2)

    all_findings: list[Finding] = []
    if sys.argv[1] == "--diff":
        all_findings = matcher.scan_diff(sys.stdin.read())
    else:
        for arg in sys.argv[1:]:
            all_findings.extend(matcher.scan_file(arg))

    for f in all_findings:
        print(f)
    raise SystemExit(1 if matcher.is_infected(all_findings) else 0)
