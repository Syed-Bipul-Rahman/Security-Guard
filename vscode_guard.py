#!/usr/bin/env python3
"""
vscode_guard.py — inspect a repo's .vscode config BEFORE it is opened in VS Code.

Primary infection vector in the sparktechagency incident:
  .vscode/settings.json  ->  "task.allowAutomaticTasks": true
  .vscode/tasks.json     ->  a task with "runOn": "folderOpen" that runs
                             `node ./public/fonts/fa-solid-400.woff2`
Opening the folder auto-executes the dropper with NO user action, which then
re-injects the payload and commits under the current developer's identity.

This module answers one question: "is it safe to open this folder in VS Code?"
Intended to run at clone time, in a pre-open hook, or as a scheduled workstation
sweep by the Guard agent. It DETECTS and REPORTS; it does not delete on its own.

JSON parsing note: VS Code accepts JSONC (comments + trailing commas). We strip
those before json.loads so a commented malicious file can't evade the check.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path


DEFAULT_CFG = {
    "settings_file": ".vscode/settings.json",
    "tasks_file": ".vscode/tasks.json",
    "settings_danger_keys": ["task.allowAutomaticTasks"],
    "tasks_danger_runon": ["folderOpen"],
    "tasks_danger_commands": ["node", "npm", "npx", "sh", "bash", "powershell", "cmd"],
    "tasks_danger_arg_substrings": [
        "public/fonts/", ".woff2", ".woff", "curl", "wget", "iwr",
        "invoke-", "base64", "eval",
    ],
}


@dataclass
class VSCodeFinding:
    path: str
    severity: str
    reason: str
    detail: str = ""

    def __str__(self) -> str:
        return f"[{self.severity.upper()}] {self.path}: {self.reason}" + (f" ({self.detail})" if self.detail else "")


def strip_jsonc(text: str) -> str:
    """Remove // and /* */ comments and trailing commas so JSONC parses as JSON."""
    # Remove block comments
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.DOTALL)
    # Remove line comments (not inside strings — best-effort; VS Code configs are simple)
    text = re.sub(r"(^|[^:])//[^\n]*", lambda m: m.group(1), text)
    # Remove trailing commas before } or ]
    text = re.sub(r",(\s*[}\]])", r"\1", text)
    return text


class VSCodeGuard:
    def __init__(self, cfg: dict | None = None) -> None:
        c = cfg or DEFAULT_CFG
        self.settings_file = c["settings_file"]
        self.tasks_file = c["tasks_file"]
        self.danger_keys = c["settings_danger_keys"]
        self.danger_runon = [r.lower() for r in c["tasks_danger_runon"]]
        self.danger_cmds = [x.lower() for x in c["tasks_danger_commands"]]
        self.danger_args = [x.lower() for x in c["tasks_danger_arg_substrings"]]

    @classmethod
    def from_signatures(cls, sig: dict) -> "VSCodeGuard":
        return cls(cfg=sig.get("vscode_guard", DEFAULT_CFG))

    def _load_jsonc(self, path: Path) -> tuple[object | None, str]:
        try:
            raw = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            return None, f"unreadable: {exc}"
        try:
            return json.loads(strip_jsonc(raw)), raw
        except json.JSONDecodeError as exc:
            return None, f"parse-error: {exc}"

    def _check_settings(self, repo: Path) -> list[VSCodeFinding]:
        p = repo / self.settings_file
        if not p.exists():
            return []
        data, raw = self._load_jsonc(p)
        rel = self.settings_file
        findings: list[VSCodeFinding] = []
        if data is None:
            # If it won't parse, fall back to raw substring check — do not fail open
            for key in self.danger_keys:
                if key in raw and "true" in raw:
                    findings.append(VSCodeFinding(rel, "critical",
                        f"auto-task setting present in unparseable settings.json ({key})",
                        "raw substring match; treat as enabled"))
            return findings
        if isinstance(data, dict):
            for key in self.danger_keys:
                if data.get(key) is True:
                    findings.append(VSCodeFinding(rel, "critical",
                        f"{key} = true enables silent task auto-run on folder open"))
        return findings

    def _iter_task_commands(self, data: object):
        """Yield (command, args, runOn) tuples from a tasks.json structure."""
        if not isinstance(data, dict):
            return
        for task in data.get("tasks", []) or []:
            if not isinstance(task, dict):
                continue
            cmd = task.get("command", "")
            args = task.get("args", []) or []
            run_on = ""
            rr = task.get("runOptions")
            if isinstance(rr, dict):
                run_on = rr.get("runOn", "")
            # some configs put runOn at the top task level
            run_on = run_on or task.get("runOn", "")
            yield cmd, args, run_on

    def _check_tasks(self, repo: Path) -> list[VSCodeFinding]:
        p = repo / self.tasks_file
        if not p.exists():
            return []
        data, raw = self._load_jsonc(p)
        rel = self.tasks_file
        findings: list[VSCodeFinding] = []

        if data is None:
            low = raw.lower()
            if any(r in low for r in self.danger_runon) and any(c in low for c in self.danger_cmds):
                findings.append(VSCodeFinding(rel, "critical",
                    "unparseable tasks.json with folderOpen + command — treat as auto-run dropper",
                    "raw substring match"))
            return findings

        for cmd, args, run_on in self._iter_task_commands(data):
            cmd_l = str(cmd).lower()
            args_l = " ".join(str(a) for a in args).lower()
            blob = f"{cmd_l} {args_l}"
            auto = run_on.lower() in self.danger_runon
            is_cmd = any(c == cmd_l or c in cmd_l.split() or c in blob.split() for c in self.danger_cmds)
            bad_args = [a for a in self.danger_args if a in blob]

            if auto and (is_cmd or bad_args):
                findings.append(VSCodeFinding(rel, "critical",
                    f"auto-run task ({run_on}) executes '{cmd} {' '.join(map(str, args))}'".strip(),
                    f"dropper indicators: {', '.join(bad_args) or cmd_l}"))
            elif auto:
                findings.append(VSCodeFinding(rel, "high",
                    f"task auto-runs on {run_on} — review command '{cmd}'"))
            elif bad_args:
                findings.append(VSCodeFinding(rel, "high",
                    f"task references dropper-like path/command",
                    f"indicators: {', '.join(bad_args)}"))
        return findings

    def scan_repo(self, repo_path: str | Path) -> list[VSCodeFinding]:
        repo = Path(repo_path)
        return self._check_settings(repo) + self._check_tasks(repo)

    def is_safe_to_open(self, repo_path: str | Path) -> tuple[bool, list[VSCodeFinding]]:
        findings = self.scan_repo(repo_path)
        blocking = [f for f in findings if f.severity == "critical"]
        return (len(blocking) == 0, findings)


if __name__ == "__main__":
    import sys
    guard = VSCodeGuard()
    repo = sys.argv[1] if len(sys.argv) > 1 else "."
    safe, findings = guard.is_safe_to_open(repo)
    for f in findings:
        print(f)
    if not safe:
        print(f"\n>>> DO NOT OPEN {repo} IN VS CODE — critical auto-run task detected.")
        raise SystemExit(1)
    print(f"OK: no critical .vscode auto-run findings in {repo}")
    raise SystemExit(0)
