#!/usr/bin/env python3
"""
workflow_baseline.py — turn workflow-filename SIGNALS into confirmed VERDICTS.

Problem: filenames like deploy.yml / ci.yml / node.js.yml are used both by the
attack AND by legitimate repos, so a name match alone is only 'high' signal.

Solution: keep a per-repo baseline of known-good workflow files (by content hash,
approved by a human once). Then any workflow that is ADDED or MODIFIED relative
to the baseline is a confirmed change requiring review — and if its content also
matches the incident signatures, it is CRITICAL.

Baseline storage: JSON at <guard_home>/baselines/<repo-key>.json
  { "repo": "...", "approved_at": "...", "workflows": { "<path>": "<sha256>" } }

Verdicts:
  added     -> workflow not in baseline            (high; critical if signatures hit)
  modified  -> hash differs from baseline          (high; critical if signatures hit)
  removed   -> in baseline, gone now               (info; not an attack indicator)
  unchanged -> matches baseline                    (ok)
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import dataclass
from pathlib import Path


WORKFLOW_DIR = ".github/workflows"
WORKFLOW_EXTS = (".yml", ".yaml")


def guard_home() -> Path:
    return Path(os.environ.get("GUARD_HOME", str(Path.home() / ".guard")))


def repo_key(repo_path: str | Path) -> str:
    """Stable filesystem-safe key for a repo path."""
    p = str(Path(repo_path).resolve())
    h = hashlib.sha256(p.encode()).hexdigest()[:12]
    name = re.sub(r"[^A-Za-z0-9_.-]", "_", Path(p).name)
    return f"{name}-{h}"


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


@dataclass
class WorkflowFinding:
    path: str
    state: str          # added | modified | removed | unchanged
    severity: str       # critical | high | info | ok
    detail: str = ""

    def __str__(self) -> str:
        return f"[{self.severity.upper()}] {self.path}: workflow {self.state}" + (f" — {self.detail}" if self.detail else "")


class WorkflowBaseline:
    def __init__(self, matcher=None, home: Path | None = None) -> None:
        """matcher: optional FingerprintMatcher for content scanning of changed files."""
        self.matcher = matcher
        self.home = home or guard_home()
        self.dir = self.home / "baselines"

    # --------------------------------------------------------------- discovery
    def _current_workflows(self, repo: Path) -> dict[str, str]:
        wf_root = repo / WORKFLOW_DIR
        result: dict[str, str] = {}
        if not wf_root.is_dir():
            return result
        for f in sorted(wf_root.rglob("*")):
            if f.is_file() and f.suffix.lower() in WORKFLOW_EXTS:
                rel = f.relative_to(repo).as_posix()
                result[rel] = sha256_file(f)
        return result

    def _baseline_path(self, repo: Path) -> Path:
        return self.dir / f"{repo_key(repo)}.json"

    def load_baseline(self, repo: str | Path) -> dict | None:
        p = self._baseline_path(Path(repo))
        if not p.exists():
            return None
        try:
            return json.loads(p.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return None

    # --------------------------------------------------------------- record
    def record(self, repo: str | Path, approved_by: str = "") -> dict:
        """Snapshot the CURRENT workflows as the approved baseline.

        SECURITY: only run this on a repo you have confirmed is clean. Recording a
        baseline on an already-infected repo would bless the malicious workflow.
        Callers should scan first and refuse to baseline if signatures match.
        """
        repo = Path(repo).resolve()
        from datetime import datetime, timezone
        workflows = self._current_workflows(repo)

        # Refuse to baseline obviously-infected workflow content, if a matcher is present.
        if self.matcher is not None:
            for rel in workflows:
                content = (repo / rel).read_text(encoding="utf-8", errors="replace")
                hits = self.matcher.scan_content(rel, content)
                if any(h.severity == "critical" for h in hits):
                    raise ValueError(
                        f"refusing to baseline: {rel} matches incident signatures. "
                        f"Clean the repo first, then record the baseline."
                    )

        data = {
            "repo": str(repo),
            "approved_at": datetime.now(timezone.utc).isoformat(),
            "approved_by": approved_by,
            "workflows": workflows,
        }
        self.dir.mkdir(parents=True, exist_ok=True)
        self._baseline_path(repo).write_text(json.dumps(data, indent=2), encoding="utf-8")
        return data

    # --------------------------------------------------------------- diff
    def diff(self, repo: str | Path) -> list[WorkflowFinding]:
        repo = Path(repo).resolve()
        current = self._current_workflows(repo)
        baseline = self.load_baseline(repo)

        findings: list[WorkflowFinding] = []

        if baseline is None:
            # No baseline yet: every workflow is unverified. Content-scan them and
            # report as 'added' pending human approval.
            for rel, digest in current.items():
                sev, detail = self._assess_content(repo, rel, base="no-baseline")
                findings.append(WorkflowFinding(rel, "added", sev, detail or "no baseline recorded yet — needs review"))
            return findings

        base_wf = baseline.get("workflows", {})

        for rel, digest in current.items():
            if rel not in base_wf:
                sev, detail = self._assess_content(repo, rel, base="added")
                findings.append(WorkflowFinding(rel, "added", sev, detail or "not in approved baseline"))
            elif base_wf[rel] != digest:
                sev, detail = self._assess_content(repo, rel, base="modified")
                findings.append(WorkflowFinding(rel, "modified", sev, detail or "content differs from approved baseline"))
            else:
                findings.append(WorkflowFinding(rel, "unchanged", "ok"))

        for rel in base_wf:
            if rel not in current:
                findings.append(WorkflowFinding(rel, "removed", "info", "was in baseline, now absent"))

        return findings

    def _assess_content(self, repo: Path, rel: str, base: str) -> tuple[str, str]:
        """Escalate to critical if the changed workflow's content matches signatures."""
        if self.matcher is None:
            return "high", ""
        try:
            content = (repo / rel).read_text(encoding="utf-8", errors="replace")
        except OSError:
            return "high", "unreadable"
        hits = self.matcher.scan_content(rel, content)
        crit = [h for h in hits if h.severity == "critical"]
        if crit:
            ids = ", ".join(sorted({h.sig_id for h in crit}))
            return "critical", f"content matches signatures: {ids}"
        return "high", ""

    @staticmethod
    def is_infected(findings: list[WorkflowFinding]) -> bool:
        return any(f.severity == "critical" for f in findings)


if __name__ == "__main__":
    import sys
    from fingerprint_matcher import FingerprintMatcher

    sig = json.loads(Path(__file__).with_name("signatures.json").read_text(encoding="utf-8"))
    wb = WorkflowBaseline(matcher=FingerprintMatcher(sig))

    if len(sys.argv) < 3 or sys.argv[1] not in ("record", "diff"):
        print("usage: workflow_baseline.py {record|diff} <repo> [approved_by]")
        raise SystemExit(2)

    cmd, repo = sys.argv[1], sys.argv[2]
    if cmd == "record":
        try:
            data = wb.record(repo, approved_by=sys.argv[3] if len(sys.argv) > 3 else "")
            print(f"baselined {len(data['workflows'])} workflow(s) for {data['repo']}")
        except ValueError as exc:
            print(f"ERROR: {exc}")
            raise SystemExit(1)
    else:
        findings = wb.diff(repo)
        for f in findings:
            if f.severity != "ok":
                print(f)
        raise SystemExit(1 if wb.is_infected(findings) else 0)
