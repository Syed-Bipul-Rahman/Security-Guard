#!/usr/bin/env python3
"""
remediator.py - surgically REMOVE injected malicious code, not just alert.

An alert-only tool isn't an anti-malware. The supply-chain attacks Guard hunts
inject a payload INTO an otherwise-legitimate file (e.g. a malicious IIFE bolted
onto vite.config.ts, above the real config), or drop a whole payload file (a fake
fa-solid-400.woff2 that is really JavaScript). Git history can't be trusted to
undo it - the attacker AMENDED the original commit, so `git log` shows clean
history. Reset/cherry-pick would also throw away real work.

So we remediate the WORKING TREE by content, with three strategies:

  1. Injected block in a real file  -> EXCISE just the block, keep the file.
     The malicious IIFE is located and its exact bounds found by a string/comment
     aware bracket matcher (not a fragile regex), then cut out. The legitimate
     imports/config around it are untouched.
  2. Whole-file dropper             -> QUARANTINE the file (move to the store).
  3. .vscode/settings.json|tasks.json -> remove only the offending key/task.

SAFETY (this edits people's source, so it is conservative and reversible):
  * Every change is BACKED UP to <guard_home>/quarantine first; `guard restore`
    puts it back. An index.jsonl records every action.
  * A source file is NEVER deleted - only the injected span is removed. If the
    span can't be bounded confidently, or removing it would unbalance the file,
    we DON'T touch it and leave it for manual review (fail safe).
  * Only high-confidence malicious IIFEs are excised (must contain a strong
    marker like atob(process.env / eval(proxyInfo / AUTH_API_KEY, or eval + a
    fetch/env/atob combo).
"""
from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path

# ---------------------------------------------------------------------------
# string/comment-aware bracket matching (so we cut EXACT block bounds)
# ---------------------------------------------------------------------------

def _skip_string(s: str, i: int, quote: str) -> int:
    i += 1
    n = len(s)
    while i < n:
        c = s[i]
        if c == "\\":
            i += 2
            continue
        if c == quote:
            return i + 1
        i += 1
    return n


def _skip_line_comment(s: str, i: int) -> int:
    n = len(s)
    while i < n and s[i] != "\n":
        i += 1
    return i


def _skip_block_comment(s: str, i: int) -> int:
    n = len(s)
    i += 2
    while i < n:
        if s[i] == "*" and i + 1 < n and s[i + 1] == "/":
            return i + 2
        i += 1
    return n


def _skip_template(s: str, i: int) -> int:
    """s[i]=='`'; return index after the closing backtick, handling ${ ... }."""
    n = len(s)
    i += 1
    while i < n:
        c = s[i]
        if c == "\\":
            i += 2
            continue
        if c == "`":
            return i + 1
        if c == "$" and i + 1 < n and s[i + 1] == "{":
            i += 2
            depth = 1
            while i < n and depth > 0:
                cc = s[i]
                if cc == "\\":
                    i += 2
                    continue
                if cc in "'\"":
                    i = _skip_string(s, i, cc)
                    continue
                if cc == "`":
                    i = _skip_template(s, i)
                    continue
                if cc == "{":
                    depth += 1
                elif cc == "}":
                    depth -= 1
                i += 1
            continue
        i += 1
    return n


def _matching_bracket(s: str, i: int) -> int:
    """Index of the bracket matching s[i] (one of ( { [ ), or -1 if unbalanced.
    Skips strings, template literals and comments."""
    open_ch = s[i]
    close_ch = {"(": ")", "{": "}", "[": "]"}[open_ch]
    n = len(s)
    depth = 0
    while i < n:
        c = s[i]
        if c in "'\"":
            i = _skip_string(s, i, c)
            continue
        if c == "`":
            i = _skip_template(s, i)
            continue
        if c == "/" and i + 1 < n and s[i + 1] == "/":
            i = _skip_line_comment(s, i)
            continue
        if c == "/" and i + 1 < n and s[i + 1] == "*":
            i = _skip_block_comment(s, i)
            continue
        if c == open_ch:
            depth += 1
        elif c == close_ch:
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return -1


def _brackets_balanced(s: str) -> bool:
    stack = []
    pairs = {")": "(", "}": "{", "]": "["}
    n = len(s)
    i = 0
    while i < n:
        c = s[i]
        if c in "'\"":
            i = _skip_string(s, i, c)
            continue
        if c == "`":
            i = _skip_template(s, i)
            continue
        if c == "/" and i + 1 < n and s[i + 1] == "/":
            i = _skip_line_comment(s, i)
            continue
        if c == "/" and i + 1 < n and s[i + 1] == "*":
            i = _skip_block_comment(s, i)
            continue
        if c in "([{":
            stack.append(c)
        elif c in ")]}":
            if not stack or stack[-1] != pairs[c]:
                return False
            stack.pop()
        i += 1
    return not stack


# ---------------------------------------------------------------------------
# locate + excise malicious IIFEs
# ---------------------------------------------------------------------------

# An IIFE wrapper: ( async? function | (args)=> | ident=> ) ... ) ( ... ) ;
_IIFE_OPEN = re.compile(
    r"\(\s*(?:async\b\s*)?(?:function\b|\([^()]*\)\s*=>|[A-Za-z_$][\w$]*\s*=>)"
)

_STRONG_MARKERS = (
    "atob(process.env",
    "eval(proxyInfo",
    "eval(atob",
    "AUTH_API_KEY",
    "auth-confirm-ten.vercel.app",
)


def _iife_is_malicious(body: str) -> bool:
    if any(tok in body for tok in _STRONG_MARKERS):
        return True
    if "eval(" in body and ("node-fetch" in body or "process.env" in body or "atob(" in body):
        return True
    return False


def find_malicious_iifes(text: str) -> list[tuple[int, int]]:
    """Return (start, end) spans of top-level malicious IIFEs, non-overlapping."""
    spans: list[tuple[int, int]] = []
    for m in _IIFE_OPEN.finditer(text):
        i = m.start()  # the wrapper '('
        if any(a <= i < b for a, b in spans):
            continue  # already inside a found span
        j = _matching_bracket(text, i)
        if j < 0:
            continue
        # after the wrapper close, an IIFE is immediately invoked: ( ... )
        k = j + 1
        while k < len(text) and text[k] in " \t\r\n":
            k += 1
        if k >= len(text) or text[k] != "(":
            continue
        m2 = _matching_bracket(text, k)
        if m2 < 0:
            continue
        end = m2 + 1
        if end < len(text) and text[end] == ";":
            end += 1
        if _iife_is_malicious(text[i:end]):
            spans.append((i, end))
    return spans


def strip_malicious_iife(text: str) -> tuple[str, list[str]]:
    """Remove malicious IIFE blocks (and the blank space they leave). Returns
    (new_text, removed_blocks). new_text == text when nothing matched."""
    spans = find_malicious_iifes(text)
    if not spans:
        return text, []
    removed: list[str] = []
    out = text
    for i, end in sorted(spans, reverse=True):
        removed.append(out[i:end])
        # swallow a wholly-blank leading remainder of the line...
        ls = out.rfind("\n", 0, i) + 1
        seg_start = ls if out[ls:i].strip() == "" else i
        # ...and trailing spaces + one newline
        seg_end = end
        while seg_end < len(out) and out[seg_end] in " \t":
            seg_end += 1
        if seg_end < len(out) and out[seg_end] == "\n":
            seg_end += 1
        out = out[:seg_start] + out[seg_end:]
    out = re.sub(r"\n{3,}", "\n\n", out)
    return out, removed


# ---------------------------------------------------------------------------
# tolerant JSONC (VS Code config with comments / trailing commas)
# ---------------------------------------------------------------------------

def _strip_jsonc(text: str) -> str:
    # remove /* */ and // comments and trailing commas (string-aware)
    out = []
    n = len(text)
    i = 0
    while i < n:
        c = text[i]
        if c in "\"'":
            j = _skip_string(text, i, c)
            out.append(text[i:j])
            i = j
            continue
        if c == "/" and i + 1 < n and text[i + 1] == "/":
            i = _skip_line_comment(text, i)
            continue
        if c == "/" and i + 1 < n and text[i + 1] == "*":
            i = _skip_block_comment(text, i)
            continue
        out.append(c)
        i += 1
    s = "".join(out)
    s = re.sub(r",(\s*[}\]])", r"\1", s)  # trailing commas
    return s


def _load_jsonc(path: Path):
    return json.loads(_strip_jsonc(path.read_text(encoding="utf-8", errors="replace")))


# ---------------------------------------------------------------------------
# the remediator
# ---------------------------------------------------------------------------

_SCRIPT_EXTS = {".js", ".mjs", ".cjs", ".ts", ".jsx", ".tsx"}


class Remediator:
    def __init__(self, home: str | Path, log=print) -> None:
        self.home = Path(home)
        self.qdir = self.home / "quarantine"
        try:
            self.qdir.mkdir(parents=True, exist_ok=True)
        except OSError:
            pass
        self.index = self.qdir / "index.jsonl"
        self.log = log

    # -- backup / audit --
    def _sha(self, data: bytes) -> str:
        return hashlib.sha256(data).hexdigest()

    def _backup(self, path: Path) -> tuple[Path, str]:
        data = path.read_bytes()
        sha = self._sha(data)
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        safe = re.sub(r"[^A-Za-z0-9._-]", "_", str(path)).strip("_")
        dest = self.qdir / f"{ts}__{safe}.{sha[:8]}.bak"
        dest.write_bytes(data)
        return dest, sha

    def _record(self, action: str, path: Path, backup: Path | None,
                sha_before: str | None, sha_after: str | None, detail: str) -> None:
        rec = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "action": action,
            "path": str(path),
            "backup": str(backup) if backup else None,
            "sha_before": sha_before,
            "sha_after": sha_after,
            "detail": detail,
        }
        try:
            with self.index.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(rec) + "\n")
        except OSError:
            pass

    # -- strategies --
    def quarantine_file(self, path: Path, reason: str = "") -> dict:
        backup, sha = self._backup(path)
        try:
            path.unlink()
        except OSError as e:
            return {"action": "error", "path": str(path), "error": str(e)}
        self._record("quarantine", path, backup, sha, None, reason)
        self.log(f"remediate: quarantined dropper {path} -> {backup.name}")
        return {"action": "quarantine", "path": str(path), "backup": str(backup), "reason": reason}

    def neutralize_js(self, path: Path) -> dict | None:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return None
        new, removed = strip_malicious_iife(text)
        if not removed:
            return None
        if not _brackets_balanced(new):
            self.log(f"remediate: refusing to edit {path} (removal would unbalance it) — left for manual review")
            return {"action": "manual", "path": str(path),
                    "note": "malicious block found but safe bounds unclear; manual review"}
        backup, sha_before = self._backup(path)
        path.write_text(new, encoding="utf-8")
        sha_after = self._sha(new.encode("utf-8", "replace"))
        self._record("neutralize", path, backup, sha_before, sha_after,
                     f"removed {len(removed)} injected block(s)")
        self.log(f"remediate: excised {len(removed)} injected block(s) from {path} (kept the real code)")
        return {"action": "neutralize", "path": str(path), "blocks": len(removed),
                "backup": str(backup)}

    def clean_vscode_settings(self, path: Path) -> dict | None:
        try:
            data = _load_jsonc(path)
        except Exception:
            return None
        if not isinstance(data, dict) or "task.allowAutomaticTasks" not in data:
            return None
        backup, sha_before = self._backup(path)
        data.pop("task.allowAutomaticTasks", None)
        new = json.dumps(data, indent=2) + "\n"
        path.write_text(new, encoding="utf-8")
        self._record("clean-settings", path, backup, sha_before,
                     self._sha(new.encode()), "removed task.allowAutomaticTasks")
        self.log(f"remediate: removed auto-run flag from {path}")
        return {"action": "clean-settings", "path": str(path), "backup": str(backup)}

    def clean_vscode_tasks(self, path: Path) -> dict | None:
        try:
            data = _load_jsonc(path)
        except Exception:
            return None
        if not isinstance(data, dict) or not isinstance(data.get("tasks"), list):
            return None
        kept, dropped = [], 0
        for t in data["tasks"]:
            if isinstance(t, dict) and self._task_is_malicious(t):
                dropped += 1
            else:
                kept.append(t)
        if not dropped:
            return None
        backup, sha_before = self._backup(path)
        data["tasks"] = kept
        new = json.dumps(data, indent=2) + "\n"
        path.write_text(new, encoding="utf-8")
        self._record("clean-tasks", path, backup, sha_before,
                     self._sha(new.encode()), f"removed {dropped} auto-run task(s)")
        self.log(f"remediate: removed {dropped} malicious auto-run task(s) from {path}")
        return {"action": "clean-tasks", "path": str(path), "dropped": dropped,
                "backup": str(backup)}

    @staticmethod
    def _task_is_malicious(task: dict) -> bool:
        runon = ""
        ro = task.get("runOptions")
        if isinstance(ro, dict):
            runon = str(ro.get("runOn", "")).lower()
        blob = json.dumps(task).lower()
        auto = runon == "folderopen" or '"runon": "folderopen"' in blob
        bad = any(k in blob for k in ("public/fonts", ".woff2", "node ./", "atob(", "eval(",
                                      "invoke-expression", "iex ", "powershell -e"))
        return auto and bad

    # -- dispatch --
    def remediate_file(self, path: str | Path, is_dropper: bool = False) -> dict:
        p = Path(path)
        if not p.exists():
            return {"action": "gone", "path": str(p)}
        parent = p.parent.name.lower()
        name = p.name.lower()
        if parent == ".vscode" and name == "settings.json":
            return self.clean_vscode_settings(p) or {"action": "noop", "path": str(p)}
        if parent == ".vscode" and name in ("tasks.json", "launch.json"):
            return self.clean_vscode_tasks(p) or {"action": "noop", "path": str(p)}
        if is_dropper:
            return self.quarantine_file(p, "whole-file dropper / masquerade payload")
        if p.suffix.lower() in _SCRIPT_EXTS:
            r = self.neutralize_js(p)
            if r:
                return r
        # A real source file we couldn't surgically clean: NEVER delete it.
        return {"action": "manual", "path": str(p),
                "note": "malicious markers present but no safe automatic fix; manual review"}

    def clean_repo(self, repo: str | Path) -> dict:
        """Detect (reusing the scanner) then remediate every flagged file."""
        from scanner import GuardScanner, load_signatures
        sc = GuardScanner(load_signatures())
        repo = str(repo)
        summary = {"repo": repo, "neutralized": [], "quarantined": [],
                   "config_cleaned": [], "manual": [], "noop": []}
        seen: set[str] = set()  # files already handled (any pass)

        def route(res: dict):
            act = res.get("action")
            if act == "neutralize":
                summary["neutralized"].append(res["path"])
            elif act == "quarantine":
                summary["quarantined"].append(res["path"])
            elif act in ("clean-settings", "clean-tasks"):
                summary["config_cleaned"].append(res["path"])
            elif act == "manual":
                summary["manual"].append(res["path"])
            else:
                summary["noop"].append(res.get("path", ""))

        # 1. .vscode auto-run
        try:
            _safe, vf = sc.vscode.is_safe_to_open(repo)
            for f in vf:
                if getattr(f, "severity", "") != "critical":
                    continue
                fp = getattr(f, "path", None) or getattr(f, "where", None)
                fp = self._abs(repo, fp)
                if fp and fp not in seen:
                    seen.add(fp)
                    route(self.remediate_file(fp))
        except Exception as exc:
            self.log(f"remediate: vscode pass error: {exc}")

        # 2. tree: magic (masquerade droppers) + fingerprint (injections/payloads)
        try:
            res = sc.scan_tree(repo)
        except Exception as exc:
            self.log(f"remediate: scan error: {exc}")
            return summary

        binary_exts = {".woff2", ".woff", ".ttf", ".otf", ".png", ".jpg", ".jpeg",
                       ".ico", ".gif", ".webp"}
        for x in res.get("magic", []):
            if x.get("severity") != "critical":
                continue
            fp = self._abs(repo, x.get("path") or x.get("where"))
            if fp and fp not in seen:
                seen.add(fp)
                route(self.remediate_file(fp, is_dropper=True))
        for x in res.get("fingerprint", []):
            if x.get("severity") != "critical":
                continue
            fp = self._abs(repo, x.get("where") or x.get("path"))
            if not fp or fp in seen:
                continue
            seen.add(fp)
            dropper = Path(fp).suffix.lower() in binary_exts  # binary ext but flagged = masquerade
            route(self.remediate_file(fp, is_dropper=dropper))
        return summary

    @staticmethod
    def _abs(repo: str, rel) -> str | None:
        if not rel:
            return None
        p = Path(rel)
        return str(p if p.is_absolute() else Path(repo) / p)

    # -- undo --
    def restore(self, target: str) -> dict:
        """Restore the most recent backup for a given original path (or a backup
        filename) from the quarantine store."""
        if not self.index.exists():
            return {"restored": [], "error": "no quarantine index"}
        recs = [json.loads(l) for l in self.index.read_text().splitlines() if l.strip()]
        match = [r for r in recs if r.get("path") == target or
                 (r.get("backup") and Path(r["backup"]).name == target)]
        if not match:
            return {"restored": [], "error": f"no record for {target}"}
        r = match[-1]
        backup = r.get("backup")
        if not backup or not Path(backup).exists():
            return {"restored": [], "error": "backup file missing"}
        dest = Path(r["path"])
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(Path(backup).read_bytes())
        self._record("restore", dest, Path(backup), None, r.get("sha_before"), "restored from backup")
        self.log(f"remediate: restored {dest} from {Path(backup).name}")
        return {"restored": [str(dest)], "from": backup}


def _guard_home() -> Path:
    import os
    return Path(os.environ.get("GUARD_HOME", str(Path.home() / ".guard")))


def main(argv: list[str] | None = None) -> int:
    import sys
    argv = argv if argv is not None else sys.argv[1:]
    if not argv:
        print("usage: guard clean <path>   |   guard restore <original-path|backup-name>")
        return 0
    sub, rest = argv[0], argv[1:]
    rem = Remediator(_guard_home())
    if sub == "restore":
        if not rest:
            print("usage: guard restore <original-path|backup-name>", file=sys.stderr)
            return 2
        print(json.dumps(rem.restore(rest[0]), indent=2))
        return 0
    # default: clean a path (repo or single file)
    target = sub if sub not in ("clean",) else (rest[0] if rest else ".")
    p = Path(target)
    if p.is_file():
        print(json.dumps(rem.remediate_file(p), indent=2))
    else:
        print(json.dumps(rem.clean_repo(target), indent=2))
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())
