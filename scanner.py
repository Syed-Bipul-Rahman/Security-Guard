#!/usr/bin/env python3
"""
scanner.py — Guard repo/workstation scanner orchestrator.

Ties together the three engines:
  * VSCodeGuard        — .vscode auto-run dropper (the primary infection vector)
  * MagicByteChecker   — binary-disguised JS droppers (fake fonts/images)
  * FingerprintMatcher — .env / eval-IIFE / obfuscated-C2 / dropper-cmd signatures

Modes:
  scan-tree   : walk the working tree (default). Fast, no git required.
  scan-git    : also scan added lines across all commits on all branches
                (catches payloads that live only in history).
  guard-open  : ONLY the .vscode pre-open check; exit 1 if unsafe to open.

Exit codes: 0 = clean, 1 = infected (critical), 2 = usage/error.
Output:     human-readable by default, JSON with --json.

DETECT + REPORT + QUARANTINE-flag only. This tool never rewrites git history or
force-pushes. Remediation stays a reviewed, human-triggered process.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from dataclasses import asdict, is_dataclass
from pathlib import Path

from magic_bytes import MagicByteChecker
from vscode_guard import VSCodeGuard
from fingerprint_matcher import FingerprintMatcher


def load_signatures(path: str | Path | None = None) -> dict:
    p = Path(path) if path else Path(__file__).with_name("signatures.json")
    return json.loads(p.read_text(encoding="utf-8"))


def _finding_dict(f) -> dict:
    if is_dataclass(f):
        return asdict(f)
    return dict(f)


# Cap how much of any one file we read for text scanning. Incident payloads are
# small (config files, injected IIFEs); reading a bounded prefix keeps memory flat
# even if a repo contains multi-hundred-MB generated/vendored files.
MAX_SCAN_BYTES = 5 * 1024 * 1024  # 5 MB


def read_text_capped(path: Path, max_bytes: int = MAX_SCAN_BYTES) -> str | None:
    try:
        with path.open("rb") as fh:
            raw = fh.read(max_bytes)
        return raw.decode("utf-8", errors="replace")
    except OSError:
        return None


class GuardScanner:
    # Extensions the magic-byte checker cares about (binary-looking assets)
    BINARY_EXTS = {".woff2", ".woff", ".ttf", ".otf", ".eot", ".png", ".jpg", ".jpeg", ".gif", ".ico"}

    def __init__(self, sig: dict) -> None:
        self.sig = sig
        self.vscode = VSCodeGuard.from_signatures(sig)
        self.magic = MagicByteChecker.from_signatures(sig)
        self.matcher = FingerprintMatcher(sig)
        self.skip_prefixes = tuple(sig.get("skip_path_prefixes", []))
        # Malicious-dependency blocklist (GitHub malware advisories); optional
        try:
            from dep_blocklist import DepBlocklist
            self.dep_blocklist = DepBlocklist()
        except Exception:
            self.dep_blocklist = None
        # Workflow baseline diff (turns filename signals into confirmed verdicts)
        try:
            from workflow_baseline import WorkflowBaseline
            self.workflow_baseline = WorkflowBaseline(matcher=self.matcher)
        except Exception:
            self.workflow_baseline = None

    def _skip(self, rel: str) -> bool:
        return any(rel.startswith(p) for p in self.skip_prefixes)

    # ---------------------------------------------------------------- tree
    # Safety cap: no single tree scan should touch more files than this. Protects
    # against accidentally scanning a huge tree (e.g. a home dir). A real repo is
    # far smaller; hitting this means the target is wrong, so we bail loudly.
    MAX_FILES = 50000

    def scan_tree(self, repo_path: str | Path) -> dict:
        repo = Path(repo_path)
        results = {"repo": str(repo), "vscode": [], "magic": [], "fingerprint": [],
                   "workflow_baseline": [], "malicious_deps": [], "infected": False}

        # 1. VS Code pre-open guard (highest priority)
        results["vscode"] = [_finding_dict(f) for f in self.vscode.scan_repo(repo)]

        # 1b. Workflow baseline diff (only meaningful in a repo with .github/workflows)
        if self.workflow_baseline is not None and (repo / ".github" / "workflows").is_dir():
            for f in self.workflow_baseline.diff(repo):
                if f.severity != "ok":
                    results["workflow_baseline"].append(_finding_dict(f))

        # 2 & 3. Walk files (with a hard safety cap)
        seen = 0
        for path in repo.rglob("*"):
            if not path.is_file():
                continue
            rel = path.relative_to(repo).as_posix()
            if self._skip(rel):
                continue
            seen += 1
            if seen > self.MAX_FILES:
                results["fingerprint"].append({
                    "where": str(repo), "sig_id": "scan.aborted", "severity": "info",
                    "category": "scanner", "desc": f"tree exceeds {self.MAX_FILES} files — aborted (wrong target?)"})
                break
            ext = path.suffix.lower()

            if ext in self.BINARY_EXTS:
                for f in self.magic.check_file(path):
                    d = _finding_dict(f)
                    d["path"] = rel
                    results["magic"].append(d)

            # Fingerprint scan on text-ish files (source, config, env, json, yml)
            if ext not in self.BINARY_EXTS:
                content = read_text_capped(path)
                if content is None:
                    continue
                for f in self.matcher.scan_content(rel, content):
                    results["fingerprint"].append(_finding_dict(f))
                # Malicious-dependency check on manifests (GitHub malware blocklist)
                if self.dep_blocklist is not None and self.dep_blocklist.is_manifest(rel):
                    for df in self.dep_blocklist.check_manifest(rel, content):
                        results["malicious_deps"].append({
                            "where": df.where, "sig_id": df.sig_id, "severity": df.severity,
                            "category": df.category, "desc": df.desc,
                            "ecosystem": df.ecosystem, "name": df.name, "version": df.version})
                del content  # release before next file

        results["infected"] = self._is_infected(results)
        return results

    # ----------------------------------------------------------------- git
    def scan_git_history(self, repo_path: str | Path) -> dict:
        """Scan added lines of every commit across all branches."""
        repo = Path(repo_path)
        out = {"repo": str(repo), "diff_findings": [], "infected": False, "commits_scanned": 0}
        try:
            shas = subprocess.run(
                ["git", "-C", str(repo), "rev-list", "--all", "--no-merges"],
                capture_output=True, text=True, check=True,
            ).stdout.split()
        except (subprocess.CalledProcessError, FileNotFoundError) as exc:
            out["error"] = f"git rev-list failed: {exc}"
            return out

        for sha in shas:
            try:
                diff = subprocess.run(
                    ["git", "-C", str(repo), "show", "--format=%H%n%an <%ae>%n%aI", sha],
                    capture_output=True, text=True, check=True,
                ).stdout
            except subprocess.CalledProcessError:
                continue
            out["commits_scanned"] += 1
            for f in self.matcher.scan_diff(diff):
                d = _finding_dict(f)
                d["commit"] = sha[:12]
                out["diff_findings"].append(d)

        out["infected"] = any(x.get("severity") == "critical" for x in out["diff_findings"])
        return out

    # ------------------------------------------------------------- verdict
    @staticmethod
    def _is_infected(results: dict) -> bool:
        for bucket in ("vscode", "magic", "fingerprint", "workflow_baseline", "malicious_deps"):
            if any(x.get("severity") == "critical" for x in results.get(bucket, [])):
                return True
        return False


def _print_human(results: dict, git: dict | None) -> None:
    def dump(title, items):
        if items:
            print(f"\n== {title} ({len(items)}) ==")
            for x in items:
                sev = x.get("severity", "?").upper()
                loc = x.get("path") or x.get("where") or x.get("commit") or ""
                state = x.get("state", "")
                reason = x.get("reason") or x.get("desc") or x.get("detail") or ""
                sid = x.get("sig_id", "")
                print(f"  [{sev}] {loc} {sid} {state} {reason}".rstrip())

    print(f"Repo: {results['repo']}")
    dump("VS CODE AUTO-RUN (pre-open)", results["vscode"])
    dump("WORKFLOW BASELINE DIFF", results.get("workflow_baseline", []))
    dump("MALICIOUS DEPENDENCIES (GitHub malware list)", results.get("malicious_deps", []))
    dump("BINARY-DISGUISED DROPPERS", results["magic"])
    dump("FINGERPRINT MATCHES", results["fingerprint"])
    if git:
        dump(f"GIT HISTORY (added lines, {git.get('commits_scanned', 0)} commits)", git.get("diff_findings", []))
        if git.get("error"):
            print(f"  (git scan note: {git['error']})")

    infected = results["infected"] or (git and git.get("infected"))
    print("\n" + ("RESULT: INFECTED (critical findings present)" if infected else "RESULT: clean"))


def main() -> int:
    ap = argparse.ArgumentParser(description="Guard supply-chain scanner")
    ap.add_argument("mode", choices=["scan-tree", "scan-git", "guard-open"], nargs="?", default="scan-tree")
    ap.add_argument("path", nargs="?", default=".")
    ap.add_argument("--signatures", default=None, help="path to signatures.json")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    args = ap.parse_args()

    sig = load_signatures(args.signatures)
    scanner = GuardScanner(sig)

    if args.mode == "guard-open":
        safe, findings = scanner.vscode.is_safe_to_open(args.path)
        payload = {"repo": args.path, "safe_to_open": safe,
                   "findings": [_finding_dict(f) for f in findings]}
        if args.json:
            print(json.dumps(payload, indent=2))
        else:
            for f in findings:
                print(f)
            print("SAFE TO OPEN" if safe else ">>> DO NOT OPEN — critical auto-run task detected")
        return 0 if safe else 1

    results = scanner.scan_tree(args.path)
    git = scanner.scan_git_history(args.path) if args.mode == "scan-git" else None

    if args.json:
        print(json.dumps({"tree": results, "git": git}, indent=2))
    else:
        _print_human(results, git)

    infected = results["infected"] or bool(git and git.get("infected"))
    return 1 if infected else 0


if __name__ == "__main__":
    sys.exit(main())
