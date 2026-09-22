#!/usr/bin/env python3
"""
watcher.py — always-on filesystem watcher for the Guard agent.

Runs as a service (launchd / systemd / Windows service) so it starts at boot and
restarts on crash. Watches configured roots (dev folders, Downloads, Desktop) for:

  * new .git directories            -> repo CLONED           -> full scan + guard-open
  * changes to .git/HEAD|refs|FETCH_HEAD -> PULL/FETCH/CHECKOUT -> rescan repo
  * new directories                 -> possible new project   -> scan if it is a repo
  * new files (downloads, etc.)     -> single-file scan (magic bytes + fingerprints)

On a CRITICAL finding it writes an alert (JSONL) and, if configured, invokes a
quarantine hook. It DETECTS and REPORTS; it never rewrites git history.

Implementation: dependency-free polling snapshot diff (stdlib only). Production can
swap in FSEvents/inotify/watchdog for lower latency; the event handling is the same.
State is persisted so a restart does not re-alert on everything already seen.

Config (JSON), default <guard_home>/watcher.config.json:
{
  "watch_roots": ["~/Projects", "~/Desktop", "~/Downloads"],
  "poll_interval_sec": 5,
  "max_depth": 6,
  "exclude_dir_names": ["node_modules", "dist", "build", ".next", "coverage", "Library"],
  "scan_new_files_ext": [".ts",".js",".mjs",".cjs",".json",".yml",".yaml",".env",
                         ".woff2",".woff",".ttf",".otf",".png",".jpg",".ico"],
  "quarantine_cmd": null
}
"""

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from scanner import GuardScanner, load_signatures, read_text_capped
from workflow_baseline import WorkflowBaseline
from snapshot_store import SnapshotStore
from memguard import MemoryGuard


def guard_home() -> Path:
    return Path(os.environ.get("GUARD_HOME", str(Path.home() / ".guard")))


def _windows_user_profiles() -> list[str]:
    """Every REAL user profile under C:\\Users, skipping system/built-in ones.
    The GuardWatcher task runs as SYSTEM, whose ~ is the systemprofile dir — so
    a '~/Desktop' default would watch the wrong (empty) folder. SYSTEM can read
    all of these with no prompts, so we point the watch roots at them directly."""
    base = Path((os.environ.get("SystemDrive", "C:") or "C:") + "\\Users")
    skip = {"default", "default user", "public", "all users", "defaultapppool",
            "wdagutilityaccount", "systemprofile", "localservice", "networkservice"}
    profs: list[str] = []
    try:
        for d in base.iterdir():
            try:
                if d.is_dir() and d.name.lower() not in skip:
                    profs.append(str(d))
            except OSError:
                continue
    except OSError:
        pass
    return profs


DEFAULT_CONFIG = {
    "watch_roots": ["~/Projects", "~/Desktop", "~/Downloads", "~/Documents"],
    "poll_interval_sec": 5,
    "max_depth": 6,
    "exclude_dir_names": ["node_modules", "dist", "build", ".next", "coverage",
                          "Library", ".Trash", "venv", ".venv", "__pycache__",
                          ".dart_tool", "Pods", ".gradle", ".symlinks", "vendor",
                          "target", ".pub-cache", ".cache", "DerivedData", "Carthage"],
    "scan_new_files_ext": [".ts", ".js", ".mjs", ".cjs", ".json", ".yml", ".yaml",
                           ".env", ".woff2", ".woff", ".ttf", ".otf", ".png", ".jpg", ".ico"],
    "git_trigger_files": ["HEAD", "FETCH_HEAD", "ORIG_HEAD", "MERGE_HEAD",
                          "packed-refs", "config"],
    "repo_debounce_sec": 30,
    "batch_size": 2000,
    "max_changes_per_pass": 2000,
    "mem_budget_fraction": 0.10,
    "hard_memory_ceiling": False,
    "update_check_sec": 21600,  # OTA auto-update cadence (6h)
    "notify": True,             # pop a visual desktop alert on a critical detection
    "quarantine_cmd": None,
}


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class Event:
    kind: str      # clone | git-change | new-dir | new-file
    path: str
    detail: str = ""


class Watcher:
    def __init__(self, config: dict | None = None, home: Path | None = None) -> None:
        self.home = home or guard_home()
        self.home.mkdir(parents=True, exist_ok=True)
        self.cfg = {**DEFAULT_CONFIG, **(config or {})}
        self.roots = self._expand_roots(self.cfg["watch_roots"])
        self.exclude = set(self.cfg["exclude_dir_names"])
        self.scan_exts = set(self.cfg["scan_new_files_ext"])
        self.git_trigger = set(self.cfg["git_trigger_files"])
        self.max_depth = int(self.cfg["max_depth"])
        self.interval = float(self.cfg["poll_interval_sec"])

        self.db_path = self.home / "watcher.snapshot.db"
        self.alert_path = self.home / "alerts.jsonl"
        self.log_path = self.home / "watcher.log"

        sig = load_signatures()
        self.scanner = GuardScanner(sig)
        from fingerprint_matcher import FingerprintMatcher
        self.wb = WorkflowBaseline(matcher=FingerprintMatcher(sig), home=self.home)

        self.repo_debounce_sec = float(self.cfg.get("repo_debounce_sec", 30))
        self._repo_scan_times: dict[str, float] = {}
        self._repo_dirty: dict[str, str] = {}  # repos that changed while debounced -> settle & rescan
        self._telemetry_dirty = False  # set on a new detection -> prompt a telemetry send
        self._perm_blocked: set[str] = set()  # paths os.walk couldn't read (TCC etc.)
        self._notify_times: dict[str, float] = {}  # per-path throttle for desktop alerts

        # Memory-friendliness controls
        self.batch_size = int(self.cfg.get("batch_size", 2000))
        self.max_changes_per_pass = int(self.cfg.get("max_changes_per_pass", 2000))
        self._memguard = MemoryGuard(
            fraction=float(self.cfg.get("mem_budget_fraction", 0.10)),
            log=self.log,
        )
        if self.cfg.get("hard_memory_ceiling", False):
            self._memguard.install_hard_ceiling()

        # Disk-backed snapshot (never holds the whole tree in RAM)
        self._store = SnapshotStore(self.db_path)

        self._running = True

    # --------------------------------------------------------------- logging
    def log(self, msg: str) -> None:
        line = f"{now_iso()}  {msg}"
        print(line, flush=True)
        try:
            with self.log_path.open("a", encoding="utf-8") as fh:
                fh.write(line + "\n")
        except OSError:
            pass

    def alert(self, kind: str, path: str, findings) -> None:
        rec = {"ts": now_iso(), "kind": kind, "path": path,
               "findings": findings if isinstance(findings, list) else [str(findings)]}
        try:
            with self.alert_path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(rec, default=str) + "\n")
        except OSError:
            pass
        self.log(f"ALERT [{kind}] {path} — {len(rec['findings'])} finding(s)")
        self._telemetry_dirty = True  # a new detection -> report on next loop tick
        self._maybe_notify(path, rec["findings"])
        qcmd = self.cfg.get("quarantine_cmd")
        if qcmd:
            try:
                subprocess.run(qcmd + [path], check=False, timeout=30)
            except Exception as exc:
                self.log(f"quarantine hook failed: {exc}")

    def _maybe_notify(self, path: str, findings) -> None:
        """Pop a visual desktop alert (like an antivirus) on a critical detection.
        Throttled per path so one infected repo doesn't stack multiple popups."""
        if not self.cfg.get("notify", True):
            return
        now = time.time()
        if now - self._notify_times.get(path, 0.0) < 60:
            return
        self._notify_times[path] = now
        try:
            from notifier import notify
            name = os.path.basename(path.rstrip("/\\")) or path
            n = len(findings) if isinstance(findings, list) else 1
            notify("Guard - Threat detected",
                   f"Malicious code found in '{name}'. {n} critical finding(s). "
                   f"Do NOT open this folder.\n{path}")
        except Exception as exc:
            self.log(f"notify failed: {exc}")

    # --------------------------------------------------------------- roots
    def _expand_roots(self, raw: list[str]) -> list[Path]:
        """Resolve configured watch roots. On Windows the service runs as SYSTEM,
        so a '~'-based root (e.g. '~/Desktop') must NOT expand to SYSTEM's profile —
        expand it to that same subpath under EVERY real user profile instead, so the
        employee's C:\\Users\\<name>\\Desktop is actually watched. Absolute roots and
        all non-Windows platforms keep normal expanduser behavior."""
        out: list[Path] = []
        is_win = sys.platform.startswith("win")
        for r in raw:
            if is_win and (r == "~" or r.startswith("~/") or r.startswith("~\\")):
                rest = r[1:].lstrip("/\\")
                for prof in _windows_user_profiles():
                    out.append((Path(prof) / rest if rest else Path(prof)))
            else:
                out.append(Path(os.path.expanduser(r)))
        # resolve + dedup, preserving order
        seen: set[str] = set()
        uniq: list[Path] = []
        for p in out:
            try:
                rp = p.resolve()
            except OSError:
                rp = p
            s = str(rp)
            if s not in seen:
                seen.add(s)
                uniq.append(rp)
        return uniq

    # --------------------------------------------------------------- walk
    def _walk_onerror(self, err: OSError) -> None:
        """os.walk swallows errors by default. Surface permission blocks (macOS TCC:
        Desktop/Documents/Downloads/removable volumes) so Guard is never silently
        blind to a watched tree. Dedup + cap so a gated tree can't flood the log."""
        fn = getattr(err, "filename", "") or ""
        if isinstance(err, PermissionError):
            if fn not in self._perm_blocked:
                self._perm_blocked.add(fn)
                if len(self._perm_blocked) <= 50:
                    if sys.platform == "darwin":
                        hint = ("grant access: run 'guard permissions request' in your "
                                "login session, or enable Full Disk Access for guard")
                        self._telemetry_dirty = True  # a blocked root on macOS = real blindness
                    else:
                        # On Windows these are usually legacy reparse junctions
                        # (My Music/My Pictures/My Videos) that deny listing by design.
                        hint = "skipped (access denied)"
                    self.log(f"WARNING: cannot read {fn} — {hint}")

    def _iter_paths(self, root: Path):
        """Yield (path, is_dir, mtime) up to max_depth, honoring excludes."""
        if not root.exists():
            return
        root_depth = len(root.parts)
        for dirpath, dirnames, filenames in os.walk(root, onerror=self._walk_onerror):
            d = Path(dirpath)
            depth = len(d.parts) - root_depth
            if depth >= self.max_depth:
                dirnames[:] = []
            # prune excluded dirs (but keep .git — we watch it)
            dirnames[:] = [n for n in dirnames if n not in self.exclude]
            for n in dirnames:
                p = d / n
                try:
                    yield str(p), True, p.stat().st_mtime
                except OSError:
                    continue
            for n in filenames:
                p = d / n
                try:
                    yield str(p), False, p.stat().st_mtime
                except OSError:
                    continue

    # --------------------------------------------------------------- detect
    def _classify(self, path: str, is_dir: bool) -> Event | None:
        base = os.path.basename(path)
        if is_dir:
            if base == ".git":
                return Event("clone", str(Path(path).parent), "new .git directory")
            return Event("new-dir", path, "new directory")
        # file
        parts = Path(path).parts
        if ".git" in parts:
            # trigger only on meaningful git files
            if base in self.git_trigger:
                # repo root = path up to the .git parent
                idx = parts.index(".git")
                repo = str(Path(*parts[:idx]))
                return Event("git-change", repo, f".git/{base} changed")
            return None
        ext = Path(path).suffix.lower()
        if ext in self.scan_exts:
            return Event("new-file", path, f"new {ext} file")
        return None

    # --------------------------------------------------------------- handle
    def _repo_root(self, path: str) -> str | None:
        """Nearest ancestor containing .git, WITHOUT ascending above the watch
        root that contains `path`. This prevents a file in a watch root that
        itself sits inside a large git repo (e.g. the home dir) from resolving to
        that huge outer repo and triggering a full-tree scan of it."""
        p = Path(path).resolve()
        # Find the watch root that contains this path; that is the ceiling.
        ceiling = None
        for root in self.roots:
            try:
                p.relative_to(root)
                # deepest matching root wins
                if ceiling is None or len(root.parts) > len(ceiling.parts):
                    ceiling = root
            except ValueError:
                continue
        if ceiling is None:
            return None
        for cand in [p, *p.parents]:
            if (cand / ".git").exists():
                return str(cand)
            if cand == ceiling:
                break  # do not ascend above the watch root
        return None

    def _debounced(self, repo: str) -> bool:
        """True if this repo was scanned very recently (skip to avoid storms)."""
        last = self._repo_scan_times.get(repo, 0.0)
        return (time.time() - last) < self.repo_debounce_sec

    def _scan_repo(self, repo: str, kind: str) -> None:
        # 1) pre-open guard (highest priority)
        safe, vf = self.scanner.vscode.is_safe_to_open(repo)
        crit = [str(f) for f in vf if getattr(f, "severity", "") == "critical"]
        if crit:
            self.alert("vscode-autorun", repo, crit)
        # 2) tree scan
        results = self.scanner.scan_tree(repo)
        tree_crit = [x for b in ("magic", "fingerprint") for x in results[b]
                     if x.get("severity") == "critical"]
        if tree_crit:
            self.alert("tree", repo, tree_crit)
        # 3) workflow baseline diff
        wf = [str(f) for f in self.wb.diff(repo) if f.severity == "critical"]
        if wf:
            self.alert("workflow-baseline", repo, wf)
        if not (crit or tree_crit or wf):
            self.log(f"scan clean: {repo}")

    def _scan_file(self, path: str) -> None:
        p = Path(path)
        ext = p.suffix.lower()
        findings = []
        if ext in self.scanner.BINARY_EXTS:
            findings = [str(f) for f in self.scanner.magic.check_file(p)
                        if getattr(f, "severity", "") in ("critical", "high")]
        else:
            content = read_text_capped(p)
            if content is None:
                return
            findings = [str(f) for f in self.scanner.matcher.scan_content(str(p), content)
                        if getattr(f, "severity", "") == "critical"]
        if findings:
            self.alert("new-file", path, findings)

    # --------------------------------------------------------------- loop
    def _handle_changes(self, changes, repos_to_scan, files_to_scan, is_dir_map):
        """Classify a batch of (path, status) changes into repo/file scan sets.
        Bounded: stops collecting once max_changes_per_pass is reached so a first
        mass-change (e.g. a huge extract) can't grow these sets without limit."""
        for path, _status in changes:
            if len(repos_to_scan) + len(files_to_scan) >= self.max_changes_per_pass:
                return
            ev = self._classify(path, is_dir_map.get(path, False))
            if ev is None:
                continue
            if ev.kind in ("clone", "git-change"):
                repos_to_scan.setdefault(ev.path, ev.detail)
            elif ev.kind == "new-dir":
                repo = self._repo_root(ev.path)
                if repo:
                    repos_to_scan.setdefault(repo, "new dir in repo")
            elif ev.kind == "new-file":
                repo = self._repo_root(path)
                if repo:
                    repos_to_scan.setdefault(repo, "new file in repo")
                elif len(files_to_scan) < self.max_changes_per_pass:
                    files_to_scan.append(path)

    def poll_once(self, prime: bool = False) -> int:
        """Stream every watched path through the SQLite snapshot in BATCHES, so we
        never hold the whole tree in RAM. Only changed paths become scan work.

        prime=True records the current tree without scanning (first run)."""
        gen = self._store.next_generation()
        batch: list[tuple[str, float]] = []
        is_dir_map: dict[str, bool] = {}
        repos_to_scan: dict[str, str] = {}
        files_to_scan: list[str] = []

        def flush(b):
            if not b:
                return
            if prime:
                self._store.touch_batch(b, gen)
            else:
                changes = self._store.upsert_batch(b, gen)
                if changes:
                    self._handle_changes(changes, repos_to_scan, files_to_scan, is_dir_map)
            b.clear()
            is_dir_map.clear()
            self._memguard.check_and_throttle()

        for root in self.roots:
            for path, is_dir, mtime in self._iter_paths(root):
                batch.append((path, mtime))
                if is_dir:
                    is_dir_map[path] = True
                if len(batch) >= self.batch_size:
                    flush(batch)
        flush(batch)

        # Files removed since last pass (rows from an older generation).
        try:
            self._store.sweep_deleted(gen)
        except Exception as exc:
            self.log(f"sweep error: {exc}")

        if prime:
            return 0

        handled = 0
        for repo, reason in repos_to_scan.items():
            if self._debounced(repo):
                # Changes are still arriving for a repo we just scanned (e.g. a git
                # checkout still landing files after a clone was scanned early).
                # Remember it and rescan once the debounce window closes.
                self._repo_dirty[repo] = reason
                continue
            self._repo_scan_times[repo] = time.time()
            self.log(f"scan trigger: {repo} ({reason})")
            try:
                self._scan_repo(repo, reason)
            except Exception as exc:
                self.log(f"repo scan error {repo}: {exc}")
            handled += 1
            self._memguard.check_and_throttle()
        # Settled rescan: a repo that kept changing while debounced gets ONE more
        # scan once it stabilizes, so a clone scanned mid-checkout (empty working
        # tree) isn't permanently missed after the files finish landing.
        for repo in list(self._repo_dirty):
            if repo in repos_to_scan or self._debounced(repo):
                continue  # handled this pass, or still within the debounce window
            reason = self._repo_dirty.pop(repo)
            self._repo_scan_times[repo] = time.time()
            self.log(f"scan trigger (settled): {repo} ({reason})")
            try:
                self._scan_repo(repo, reason)
            except Exception as exc:
                self.log(f"repo scan error {repo}: {exc}")
            handled += 1
            self._memguard.check_and_throttle()
        for f in files_to_scan:
            try:
                self._scan_file(f)
            except Exception as exc:
                self.log(f"file scan error {f}: {exc}")
            handled += 1
        return handled

    def run(self) -> None:
        signal.signal(signal.SIGTERM, self._stop)
        signal.signal(signal.SIGINT, self._stop)
        self.log(f"watcher started; roots={[str(r) for r in self.roots]} interval={self.interval}s")
        self.log(f"memguard: {self._memguard.summary()}")
        self._check_permissions()
        # Prime state silently on first run so we don't alert on the entire existing
        # tree. Uses the same batched, disk-backed path so priming is also low-memory.
        if self._store.is_empty():
            self.log("priming baseline snapshot (first run — existing files not re-alerted)")
            self.poll_once(prime=True)
            self.log(f"primed {self._store.count()} paths")
        update_every = float(self.cfg.get("update_check_sec", 6 * 3600))  # OTA check cadence
        tel_every = float(self.cfg.get("telemetry_sec", 3600))            # telemetry cadence
        last_update = 0.0
        last_tel = 0.0
        while self._running:
            try:
                self.poll_once()
            except Exception as exc:
                self.log(f"poll error: {exc}")
            # Telemetry: periodic, or promptly after a new critical detection.
            if tel_every > 0 and ((time.time() - last_tel) >= tel_every or self._telemetry_dirty):
                last_tel = time.time()
                self._telemetry_dirty = False
                try:
                    from telemetry import run_once
                    run_once(self.home)
                except Exception as exc:
                    self.log(f"telemetry error: {exc}")
            # Periodic signed OTA check (blocklist + binary). Never fatal to the watcher.
            if update_every > 0 and (time.time() - last_update) >= update_every:
                last_update = time.time()
                try:
                    from updater import Updater
                    res = Updater(log=self.log).check_and_apply()
                    if res.get("binary_updated"):
                        self.log("new binary installed via OTA - restarting to run it")
                        try:
                            self._store.close()
                        except Exception:
                            pass
                        # Unix: launchd/systemd restart on any exit (0 fine).
                        # Windows: the scheduled task restarts on FAILURE, so exit
                        # non-zero to trigger it (a clean exit wouldn't relaunch).
                        os._exit(1 if sys.platform.startswith("win") else 0)
                except Exception as exc:
                    self.log(f"update check error: {exc}")
            for _ in range(int(self.interval * 10)):
                if not self._running:
                    break
                time.sleep(0.1)
        self._store.close()
        self.log("watcher stopped")

    def _check_permissions(self) -> None:
        """At startup, verify Guard can actually READ its watch roots. On macOS,
        TCC blocks Desktop/Documents/Downloads/removable volumes for a process that
        hasn't been allowed; a silently-unreadable root makes Guard blind. If we're
        running in the user's GUI session (LaunchAgent), raise the native "Allow"
        prompts so the employee just clicks Allow; otherwise log a clear warning."""
        blocked = []
        for r in self.roots:
            if not r.exists():
                continue
            try:
                with os.scandir(r) as it:
                    for _ in it:
                        break
            except PermissionError:
                blocked.append(str(r))
            except OSError:
                pass
        if not blocked:
            return
        self.log(f"WARNING: cannot read {len(blocked)} watch root(s): {blocked}")
        self._telemetry_dirty = True
        if sys.platform == "darwin":
            try:
                from permissions import request as perm_request
                self.log("requesting access (an Allow prompt should appear)…")
                perm_request(log=self.log)
            except Exception as exc:
                self.log(f"permission request failed: {exc}")

    def _stop(self, *_a) -> None:
        self._running = False


def load_config() -> dict:
    cfg_path = guard_home() / "watcher.config.json"
    if cfg_path.exists():
        try:
            return {**DEFAULT_CONFIG, **json.loads(cfg_path.read_text(encoding="utf-8"))}
        except json.JSONDecodeError:
            pass
    return dict(DEFAULT_CONFIG)


def main() -> int:
    import argparse
    ap = argparse.ArgumentParser(description="Guard filesystem watcher")
    ap.add_argument("--once", action="store_true", help="single poll pass then exit (testing)")
    ap.add_argument("--roots", nargs="*", help="override watch roots")
    ap.add_argument("--interval", type=float, help="poll interval seconds")
    ap.add_argument("--print-default-config", action="store_true")
    args = ap.parse_args()

    if args.print_default_config:
        print(json.dumps(DEFAULT_CONFIG, indent=2))
        return 0

    cfg = load_config()
    if args.roots:
        cfg["watch_roots"] = args.roots
    if args.interval:
        cfg["poll_interval_sec"] = args.interval

    w = Watcher(cfg)
    if args.once:
        # Do not prime; report events found in this pass (used by tests).
        n = w.poll_once()
        w.log(f"--once complete: {n} event(s) handled")
        return 0
    w.run()
    return 0


if __name__ == "__main__":
    sys.exit(main())
