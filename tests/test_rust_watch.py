"""`guard watch` in the Rust binary against watcher.py (Python), side by side.

Each test builds the same tree twice (tmp/py and tmp/rs, homes tmp/home-py and
tmp/home-rs), runs `guard.py watch ...` and the binary, and requires the same
log lines, alerts, cleaned files, backups and snapshot database. Timestamps and
the per-build folders are the only things normalised. The service mode (events
and polling until SIGTERM) is compared on what it detects and cleans, since its
timing differs from run to run.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import signal
import sqlite3
import subprocess
import sys
import time
from pathlib import Path

import pytest

import samples
from conftest import write
from rustbin import ROOT, WINDOWS, clean_env, run_python, run_rust, rust_guard  # noqa: F401  (fixture)
from test_rust_scan import PAYLOAD, TASKS, backups, index, norm, text, tree

QUIET = {"notify": False, "telemetry_sec": 0, "update_check_sec": 0}
LOG_TS = re.compile(r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d{6})?\+00:00  ", re.M)


def lines(s: str, tmp_path: Path) -> str:
    return norm(LOG_TS.sub("", s.replace("\r\n", "\n")), tmp_path)


def setup(tmp_path: Path, build, config: dict | None = None) -> None:
    for who in ("py", "rs"):
        build(tmp_path / who)
        home = tmp_path / f"home-{who}"
        home.mkdir(parents=True, exist_ok=True)
        if config is not None:
            (home / "watcher.config.json").write_text(json.dumps({**QUIET, **config}), encoding="utf-8")


def watch_each(tmp_path, rust_guard, *args):
    out = {}
    for who in ("py", "rs"):
        env = {"GUARD_HOME": str(tmp_path / f"home-{who}"), "PYTHONIOENCODING": "utf-8"}
        a = [str(x).replace("{w}", str(tmp_path / who)) for x in args]
        out[who] = run_python("watch", *a, env=env) if who == "py" else run_rust(rust_guard, "watch", *a, env=env)
    return out["py"], out["rs"]


def alerts(home: Path, tmp_path: Path) -> list[dict]:
    f = home / "alerts.jsonl"
    if not f.exists():
        return []
    recs = [json.loads(norm(x, tmp_path)) for x in f.read_text(encoding="utf-8").splitlines() if x.strip()]
    for r in recs:
        assert re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d{6})?\+00:00", r.pop("ts"))
    return recs


def snapshot(home: Path, tmp_path: Path, mtimes: bool = True) -> dict:
    db = home / "watcher.snapshot.db"
    if not db.exists():
        return {}
    con = sqlite3.connect(db)
    try:
        rows = {norm(p, tmp_path): (m if mtimes else None, g) for p, m, g in con.execute("SELECT path, mtime, gen FROM paths")}
        meta = dict(con.execute("SELECT k, v FROM meta"))
    finally:
        con.close()
    return {"rows": rows, "meta": meta}


def same_watch(tmp_path, py, rs):
    assert rs.returncode == py.returncode, (text(py.stderr), text(rs.stderr))
    assert lines(text(rs.stdout), tmp_path) == lines(text(py.stdout), tmp_path)
    assert norm(text(rs.stderr), tmp_path) == norm(text(py.stderr), tmp_path)
    for who in ("py", "rs"):
        log = tmp_path / f"home-{who}" / "watcher.log"
        # the log has every run so far; this one is its tail
        assert not log.exists() or lines(log.read_text(encoding="utf-8"), tmp_path).endswith(lines(text(py.stdout), tmp_path))
    assert tree(tmp_path / "rs") == tree(tmp_path / "py")
    assert alerts(tmp_path / "home-rs", tmp_path) == alerts(tmp_path / "home-py", tmp_path)
    assert index(tmp_path / "home-rs", tmp_path) == index(tmp_path / "home-py", tmp_path)
    assert backups(tmp_path / "home-rs", tmp_path) == backups(tmp_path / "home-py", tmp_path)
    # each copy of the tree was written at its own time: compare paths and generations
    assert snapshot(tmp_path / "home-rs", tmp_path, False) == snapshot(tmp_path / "home-py", tmp_path, False)


# ---------------------------------------------------------------------------
# a watched tree: downloads, repos, excluded and deep folders
# ---------------------------------------------------------------------------
def watched(root: Path) -> None:
    dl = root / "Downloads"
    write(dl / "invoice.js", "const a = 1;\n" + PAYLOAD)                       # critical, loose file
    write(dl / "notes.json", '{"ok": true}\n')                                 # clean, scanned
    write(dl / "eicar.com", samples.eicar())                                  # not a watched extension
    write(dl / "fa-solid-400.woff2", "const x = require('child_process');\n")  # disguised dropper
    write(dl / "real.woff2", b"wOF2" + bytes(64))
    write(dl / "font.ttf", b"function f() { eval(proxyInfo) }\n")             # bad magic, text
    write(dl / "\u00e9t\u00e9.ts", "// caf\u00e9\n")
    # a clone: .git plus an infected tree
    repo = root / "Projects" / "app"
    (repo / ".git" / "refs").mkdir(parents=True)
    write(repo / ".git" / "HEAD", "ref: refs/heads/main\n")
    write(repo / ".git" / "objects" / "ab" / "cdef", b"\x00blob")
    write(repo / "src" / "server.ts", "import express from 'express';\n\n" + PAYLOAD + "\nexport const app = express();\n")
    write(repo / "public" / "fonts" / "fa-solid-400.woff2", "global['!']='9'; module.exports = 1;\n")
    write(repo / ".vscode" / "tasks.json", TASKS)
    write(repo / ".vscode" / "settings.json", '{"task.allowAutomaticTasks": true}\n')
    write(repo / ".github" / "workflows" / "ci.yml", "run: node ./public/fonts/x.js && eval(proxyInfo)\n")
    write(repo / "tools" / "e.com", samples.eicar())
    # a clean repo, and a loose folder that is not one
    clean = root / "Projects" / "clean"
    (clean / ".git").mkdir(parents=True)
    write(clean / "index.js", "module.exports = 1;\n")
    write(root / "Projects" / "loose" / "x.js", "console.log(1)\n")
    # excluded and too-deep paths are never seen
    write(root / "Projects" / "node_modules" / "evil" / "index.js", PAYLOAD)
    write(root / "Desktop" / "a" / "b" / "c" / "d" / "e" / "f" / "g" / "deep.js", PAYLOAD)
    write(root / "Desktop" / "a" / "b" / "c" / "d" / "e" / "edge.js", PAYLOAD)
    if not WINDOWS:
        os.symlink(root / "Downloads", root / "Desktop" / "dl-link")
        os.symlink(root / "missing.js", root / "Desktop" / "broken.js")


@pytest.mark.parametrize("config", [{}, {"remediate": False}, {"max_depth": 2, "exclude_dir_names": ["Downloads"]},
                                    {"scan_new_files_ext": [".com", ".TS"], "max_changes_per_pass": 3}])
def test_once_over_a_tree(tmp_path, rust_guard, config):
    setup(tmp_path, watched, config)
    same_watch(tmp_path, *watch_each(tmp_path, rust_guard, "--once", "--roots", "{w}"))
    # a second pass finds nothing new (nothing was primed: --once compares to the last pass)
    same_watch(tmp_path, *watch_each(tmp_path, rust_guard, "--once", "--roots", "{w}"))


def test_once_with_several_roots(tmp_path, rust_guard):
    setup(tmp_path, watched, {"repo_debounce_sec": 0})
    py, rs = watch_each(tmp_path, rust_guard, "--once", "--roots", "{w}/Downloads", "{w}/Projects", "{w}/Projects/app",
                        "{w}/nowhere")
    same_watch(tmp_path, py, rs)


def test_changes_between_passes(tmp_path, rust_guard):
    """New, modified and deleted paths after the first pass, and git activity."""
    setup(tmp_path, watched, {"remediate": False, "repo_debounce_sec": 0})
    same_watch(tmp_path, *watch_each(tmp_path, rust_guard, "--once", "--roots", "{w}"))
    for who in ("py", "rs"):
        r = tmp_path / who
        write(r / "Downloads" / "new.mjs", "eval(proxyInfo)\n")
        (r / "Downloads" / "notes.json").unlink()
        f = r / "Downloads" / "invoice.js"
        st = f.stat()
        os.utime(f, (st.st_atime, st.st_mtime + 10))
        write(r / "Projects" / "clean" / ".git" / "FETCH_HEAD", "abc\n")
        write(r / "Projects" / "clean" / "lib" / "a.js", "eval(proxyInfo)\n")
        write(r / "Projects" / "loose" / ".git" / "HEAD", "ref: x\n")
    same_watch(tmp_path, *watch_each(tmp_path, rust_guard, "--once", "--roots", "{w}"))


def test_quarantine_hook(tmp_path, rust_guard):
    if WINDOWS:
        hook = [sys.executable, "-c", "import sys; open(sys.argv[1] + '.hooked', 'w').close()"]
    else:
        hook = ["sh", "-c", 'touch "$0.hooked"']
    setup(tmp_path, lambda d: write(d / "x.js", "eval(proxyInfo)\n"),
          {"remediate": False, "quarantine_cmd": hook})
    same_watch(tmp_path, *watch_each(tmp_path, rust_guard, "--once", "--roots", "{w}"))
    assert (tmp_path / "rs" / "x.js.hooked").exists()
    setup(tmp_path / "2", lambda d: write(d / "x.js", "eval(proxyInfo)\n"),
          {"remediate": False, "quarantine_cmd": ["/no/such/hook"]})
    same_watch(tmp_path / "2", *watch_each(tmp_path / "2", rust_guard, "--once", "--roots", "{w}"))


@pytest.mark.skipif(WINDOWS, reason="the default ~ roots mean every profile under C:\\Users there")
@pytest.mark.parametrize("cfg", ["{not json", "", json.dumps({"watch_roots": []})])
def test_config_files(tmp_path, rust_guard, cfg):
    setup(tmp_path, watched)
    for who in ("py", "rs"):
        (tmp_path / f"home-{who}" / "watcher.config.json").write_text(cfg, encoding="utf-8")
    # no --roots: the config's, or the default ~/Projects, ~/Desktop, ...
    out = {}
    for who in ("py", "rs"):
        env = {"GUARD_HOME": str(tmp_path / f"home-{who}"), "HOME": str(tmp_path / who),
               "PYTHONIOENCODING": "utf-8"}
        out[who] = run_python("watch", "--once", env=env) if who == "py" else run_rust(rust_guard, "watch", "--once", env=env)
    same_watch(tmp_path, out["py"], out["rs"])


def test_snapshot_carries_across_builds(tmp_path, rust_guard):
    """A machine switching builds keeps its snapshot: the other build sees
    only what changed since, exactly as the first build would."""
    d = tmp_path / "tree"
    watched(d)
    cfg = {**QUIET, "remediate": False}
    env = lambda h: {"GUARD_HOME": str(h), "PYTHONIOENCODING": "utf-8"}  # noqa: E731
    for first in ("py", "rs"):
        home = tmp_path / f"first-{first}"
        home.mkdir()
        (home / "watcher.config.json").write_text(json.dumps(cfg))
        r = run_python("watch", "--once", "--roots", str(d), env=env(home)) if first == "py" else \
            run_rust(rust_guard, "watch", "--once", "--roots", str(d), env=env(home))
        assert r.returncode == 0
    write(d / "Downloads" / "later.js", "eval(proxyInfo)\n")
    (d / "Downloads" / "notes.json").unlink()
    results = {}
    for first in ("py", "rs"):
        for then in ("py", "rs"):
            home = tmp_path / f"{first}-then-{then}"
            shutil.copytree(tmp_path / f"first-{first}", home)
            r = run_python("watch", "--once", "--roots", str(d), env=env(home)) if then == "py" else \
                run_rust(rust_guard, "watch", "--once", "--roots", str(d), env=env(home))
            assert r.returncode == 0, text(r.stderr)
            results[(first, then)] = (LOG_TS.sub("", text(r.stdout)), snapshot(home, tmp_path))
    assert "later.js" in results[("py", "py")][0] and "Projects" not in results[("py", "py")][0]
    assert len({json.dumps(v, sort_keys=True, default=str) for v in results.values()}) == 1


# ---------------------------------------------------------------------------
# arguments
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("args", [
    ["--print-default-config"], ["--p"], ["-h"], ["--help"], ["--he"], ["-hx"], ["x"], ["-"], ["-x"], ["-1"],
    ["--", "x"], ["--roots", "--", "a"], ["--once=1"], ["--print-default-config=x"], ["--interval"],
    ["--interval", "x"], ["--interval", "--once"], ["--interval=1_0", "--p"], ["--i", " 2 ", "--p"],
    ["--interval", "1__0"], ["--interval", "inf", "--p"], ["--roots=a", "b"], ["--roots", "a", "-1", "--bogus"],
    ["--nope", "--print-default-config"], ["--print-default-config", "--interval", "-5"],
])
def test_usage(tmp_path, rust_guard, args):
    env = {"GUARD_HOME": str(tmp_path / "home")}
    py, rs = run_python("watch", *args, env=env), run_rust(rust_guard, "watch", *args, env=env)
    assert rs.returncode == py.returncode
    assert text(rs.stdout) == text(py.stdout)
    assert text(rs.stderr) == text(py.stderr)


# ---------------------------------------------------------------------------
# the service: events / polling until SIGTERM
# ---------------------------------------------------------------------------
def _start(cmd, home: Path) -> subprocess.Popen:
    env = clean_env({"GUARD_HOME": str(home), "PYTHONIOENCODING": "utf-8"})
    return subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)


def _wait_for(pred, timeout=60.0) -> bool:
    end = time.time() + timeout
    while time.time() < end:
        if pred():
            return True
        time.sleep(0.2)
    return False


def _log(home: Path) -> str:
    f = home / "watcher.log"
    return f.read_text(encoding="utf-8") if f.exists() else ""


@pytest.mark.skipif(WINDOWS, reason="stops the service with SIGTERM")
@pytest.mark.parametrize("native", [True, False])
def test_service_detects_and_stops(tmp_path, rust_guard, native):
    cfg = {"native_events": native, "poll_interval_sec": 0.5, "full_rescan_sec": 300}
    setup(tmp_path, watched, cfg)
    procs = {}
    for who in ("py", "rs"):
        cmd = [sys.executable, str(ROOT / "guard.py"), "watch"] if who == "py" else [str(rust_guard), "watch"]
        procs[who] = _start([*cmd, "--roots", str(tmp_path / who)], tmp_path / f"home-{who}")
    try:
        for who in ("py", "rs"):
            assert _wait_for(lambda: "primed " in _log(tmp_path / f"home-{who}")), _log(tmp_path / f"home-{who}")
        time.sleep(0.5)
        for who in ("py", "rs"):
            r = tmp_path / who
            write(r / "Downloads" / "dropped.js", "eval(proxyInfo)\n")
            write(r / "Downloads" / "fa-solid-900.woff2", "module.exports = require('x');\n")
            new = r / "Projects" / "cloned"
            write(new / "src" / "app.ts", "const a = 1;\n" + PAYLOAD)
            (new / ".git").mkdir()
        for who in ("py", "rs"):
            assert _wait_for(lambda: len(alerts(tmp_path / f"home-{who}", tmp_path)) >= 3), _log(tmp_path / f"home-{who}")
            assert _wait_for(lambda: "remediated " in _log(tmp_path / f"home-{who}"))
        time.sleep(1.5)
    finally:
        for p in procs.values():
            p.send_signal(signal.SIGTERM)
        outs = {who: p.communicate(timeout=60) for who, p in procs.items()}
    for who, p in procs.items():
        assert p.returncode == 0, outs[who][1].decode()
        assert "watcher stopped" in _log(tmp_path / f"home-{who}")
    norm_alerts = lambda who: sorted((a["kind"], a["path"], json.dumps(a["findings"])) for a in alerts(tmp_path / f"home-{who}", tmp_path))  # noqa: E731
    assert norm_alerts("rs") == norm_alerts("py")
    assert tree(tmp_path / "rs") == tree(tmp_path / "py")
    assert sorted(index(tmp_path / "home-rs", tmp_path), key=json.dumps) == sorted(index(tmp_path / "home-py", tmp_path), key=json.dumps)
    # the startup lines match too (memguard's numbers are per process)
    start = {}
    for who in ("py", "rs"):
        log = lines(_log(tmp_path / f"home-{who}"), tmp_path)
        head = log.split("priming baseline snapshot")[0]
        start[who] = re.sub(r"memguard: .*", "memguard", head)
    assert start["rs"] == start["py"]
