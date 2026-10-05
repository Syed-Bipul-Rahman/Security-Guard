"""The watcher on native file events: handle_native() must find exactly what a
polling pass would for the same paths, and guard_core.FsWatcher must deliver
those paths (inotify / FSEvents / ReadDirectoryChangesW)."""

from __future__ import annotations

import os
import time
from pathlib import Path

import pytest

import watcher as W
from conftest import NATIVE_MODULE


@pytest.fixture
def make(tmp_path, monkeypatch):
    made = []

    def build(**cfg):
        root = tmp_path / "root"
        root.mkdir(exist_ok=True)
        w = W.Watcher(config={"watch_roots": [str(root)], "notify": False, "max_depth": 3,
                              "repo_debounce_sec": 0, **cfg},
                      home=tmp_path / "home")
        w.scanned = []
        monkeypatch.setattr(w, "_scan_repo", lambda repo, kind: w.scanned.append(("repo", repo)))
        monkeypatch.setattr(w, "_scan_file", lambda path: w.scanned.append(("file", path)))
        made.append(w)
        return w, w.roots[0]

    yield build
    for w in made:
        w._store.close()


def touch(p: Path, data: bytes = b"x") -> Path:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(data)
    return p


def test_new_file_is_scanned_once(make):
    w, root = make()
    w.poll_once(prime=True)
    f = touch(root / "Downloads" / "a.js")
    assert w.handle_native([str(f)]) == 1
    assert w.scanned == [("file", str(f))]
    # a repeat event with no newer mtime is not new work
    w.scanned.clear()
    assert w.handle_native([str(f)]) == 0


def test_modified_file_is_rescanned(make):
    w, root = make()
    f = touch(root / "a.js")
    w.poll_once(prime=True)
    old = f.stat().st_mtime
    os.utime(f, (old + 10, old + 10))
    w.handle_native([str(f)])
    assert w.scanned == [("file", str(f))]


def test_directory_moved_in_is_walked(make, tmp_path):
    """A clone or a folder moved in raises one event for the top dir; what is
    inside must still be found."""
    w, root = make()
    w.poll_once(prime=True)
    src = tmp_path / "elsewhere" / "proj"
    touch(src / ".git" / "HEAD", b"ref: refs/heads/main\n")
    touch(src / "src" / "index.js")
    src.rename(root / "proj")
    w.handle_native([str(root / "proj")])
    assert w.scanned == [("repo", str(root / "proj"))]


def test_scope_matches_polling_walk(make):
    """_in_scope() must agree with _iter_paths() on excludes and depth."""
    w, root = make()
    for rel in ["a.js", "d1/b.js", "d1/d2/c.js", "d1/d2/d3/d.js", "d1/d2/d3/d4/e.js",
                "node_modules/x.js", "d1/node_modules/y.js", "d1/build", ".git/HEAD"]:
        touch(root / rel)
    walked = {p for p, _d, _m in w._iter_paths(root)}
    every = {str(p) for p in root.rglob("*")}
    scoped = {p for p in every if w._in_scope(Path(p), Path(p).is_dir()) is not None}
    assert scoped == walked
    assert str(root / "d1" / "build") in scoped  # a *file* named like an excluded dir


def test_guard_home_and_outside_roots_ignored(make, tmp_path):
    w, root = make()
    assert w._in_scope(w._home_real / "watcher.log", False) is None
    assert w._in_scope(tmp_path / "other" / "a.js", False) is None
    assert w._in_scope(root, True) is None
    w.poll_once(prime=True)
    assert w.handle_native([str(root / "gone.js")]) == 0  # deleted before we looked


def test_native_rows_survive_the_next_sweep(make):
    w, root = make()
    w.poll_once(prime=True)
    f = touch(root / "a.js")
    w.handle_native([str(f)])
    w.scanned.clear()
    w.poll_once()  # full pass: f is already recorded, so not re-reported
    assert w.scanned == []


def test_falls_back_to_polling_without_guard_core(make, monkeypatch):
    import guard_av._native as N
    monkeypatch.setattr(N, "NATIVE", None)
    w, _ = make()
    assert w._start_native() is None
    w2, _ = make(native_events=False)
    assert w2._start_native() is None


needs_native = pytest.mark.skipif(NATIVE_MODULE is None or not hasattr(NATIVE_MODULE, "FsWatcher"),
                                  reason="guard_core extension not built")


def wait_for(w, want: str, timeout: float = 5.0) -> tuple[list[str], bool]:
    seen: list[str] = []
    lost = False
    end = time.time() + timeout
    while time.time() < end and want not in seen and not lost:
        got, overflow = w._wait_native()
        seen += got
        lost = lost or overflow
    return seen, lost


@needs_native
def test_native_events_end_to_end(make):
    w, root = make(poll_interval_sec=0.5)
    w.poll_once(prime=True)
    w._native = w._start_native()
    assert w._native is not None and w._native.watch_count >= 1
    # The file lands before the new directory's watch exists: the event for the
    # directory alone must be enough (handle_native walks it).
    f = touch(root / "Downloads" / "payload.js")
    end = time.time() + 5
    while time.time() < end and ("file", str(f)) not in w.scanned:
        w.handle_native(w._wait_native()[0])
    assert ("file", str(f)) in w.scanned
    # and a file in that directory once it is watched is reported directly
    g = touch(root / "Downloads" / "second.js")
    paths, _ = wait_for(w, str(g))
    assert str(g) in paths


@needs_native
def test_native_events_skip_excludes_and_home(make, tmp_path):
    w, root = make(poll_interval_sec=0.5)
    (root / "node_modules").mkdir()
    w._native = w._start_native()
    touch(root / "node_modules" / "dep.js")
    w.log("noise in guard home")
    marker = touch(root / "marker.js")
    paths, _ = wait_for(w, str(marker))
    assert not any("node_modules" in p for p in paths)
    assert not any(p.startswith(str(w._home_real)) for p in paths)


@needs_native
def test_queue_overflow_requests_full_pass(make):
    w, root = make(poll_interval_sec=0.5, native_queue_cap=3)
    w._native = w._start_native()
    for i in range(20):
        touch(root / f"f{i}.js")
    _, lost = wait_for(w, "never")
    assert lost
