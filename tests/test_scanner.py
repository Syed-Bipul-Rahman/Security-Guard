"""Integration tests for scanner.py (tree / git-history / pre-open + av engine)."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys

import pytest

import samples
import scanner as S
from conftest import ROOT, make_zip, write

INFECTED = ROOT / "testdata" / "fake-infected-repo"
CLEAN = ROOT / "testdata" / "clean-repo"
SIG = S.load_signatures()


@pytest.fixture(scope="module")
def sc():
    return S.GuardScanner(SIG)


def git(repo, *args):
    subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True,
                   env={"GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.org",
                        "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.org",
                        "HOME": str(repo), "PATH": "/usr/bin:/bin:/usr/local/bin"})


def test_read_text_capped(tmp_path):
    f = write(tmp_path / "a.txt", "x" * 100)
    assert S.read_text_capped(f, 10) == "x" * 10
    assert S.read_text_capped(tmp_path / "missing") is None


def test_finding_dict():
    assert S._finding_dict({"a": 1}) == {"a": 1}


def test_infected_fixture(sc):
    r = sc.scan_tree(INFECTED)
    assert r["infected"]
    assert r["vscode"] and r["magic"] and r["fingerprint"]
    assert {x["path"] for x in r["magic"]} == {"public/fonts/fa-solid-400.woff2"}


def test_clean_fixture(sc):
    r = sc.scan_tree(CLEAN)
    assert not r["infected"] and r["av"] == [] and r["fingerprint"] == []


def test_av_bucket_malicious_and_suspicious(sc, tmp_path):
    write(tmp_path / "dl" / "eicar.com", samples.eicar())
    write(tmp_path / "pool.json", samples.decoded(samples.SUSPICIOUS)["miner.json"][1])
    write(tmp_path / "bundle.zip", make_zip({"x/e.com": samples.eicar()}))
    write(tmp_path / "node_modules" / "skip" / "e.com", samples.eicar())       # pruned dir
    r = sc.scan_tree(tmp_path)
    by = {x["path"]: x for x in r["av"]}
    assert set(by) == {"dl/eicar.com", "pool.json", "bundle.zip"}
    assert by["dl/eicar.com"]["severity"] == "critical" and by["dl/eicar.com"]["action"] == "quarantine"
    assert by["pool.json"]["severity"] == "medium" and by["pool.json"]["action"] == ""
    assert by["bundle.zip"]["threat"] == "EICAR-Test-File"
    assert r["infected"]


def test_av_scan_file_none_paths(sc, tmp_path):
    assert sc.av_scan_file(tmp_path / "missing") is None
    assert sc.av_scan_file(write(tmp_path / "ok.txt", "hello")) is None
    hit = sc.av_scan_file(write(tmp_path / "e.com", samples.eicar()))
    assert hit["path"] == str(tmp_path / "e.com")


def test_optional_engines_absent(tmp_path, monkeypatch):
    import builtins
    real_import = builtins.__import__

    def deny(name, *a, **k):
        if name in ("dep_blocklist", "workflow_baseline", "guard_av.engine"):
            raise ImportError(name)
        return real_import(name, *a, **k)
    monkeypatch.setattr(builtins, "__import__", deny)
    s = S.GuardScanner(SIG)
    assert s.dep_blocklist is None and s.workflow_baseline is None and s.av is None
    assert s.av_scan_file(tmp_path) is None
    write(tmp_path / ".github" / "workflows" / "x.yml", "on: push")
    write(tmp_path / "requirements.txt", "x==1")
    assert not s.scan_tree(tmp_path)["infected"]


def test_skip_helper(sc):
    assert sc._skip("a/node_modules/b.js") and not sc._skip("src/b.js")


def test_workflow_and_deps_buckets(tmp_path, monkeypatch):
    bl = write(tmp_path / "bl.json", json.dumps({"pip": {"badpy": [">= 0"]}}))
    monkeypatch.setenv("GUARD_DEP_BLOCKLIST", str(bl))
    s = S.GuardScanner(SIG)
    repo = tmp_path / "repo"
    write(repo / "requirements.txt", "badpy==1.0\n")
    write(repo / ".github" / "workflows" / "deploy.yml", "on: push\n")
    r = s.scan_tree(repo)
    assert r["malicious_deps"][0]["name"] == "badpy"
    assert r["workflow_baseline"][0]["state"] == "added"
    assert r["infected"]


def test_max_files_abort(tmp_path, monkeypatch, sc):
    monkeypatch.setattr(S.GuardScanner, "MAX_FILES", 3)
    for i in range(5):
        write(tmp_path / f"d{i}" / "f.txt", "x")
    r = sc.scan_tree(tmp_path)
    assert r["fingerprint"][-1]["sig_id"] == "scan.aborted"


def test_relative_to_failure_is_skipped(tmp_path, monkeypatch, sc):
    write(tmp_path / "a.txt", "x")
    monkeypatch.setattr(S.os, "walk", lambda p: iter([("/elsewhere", [], ["a.txt"])]))
    assert sc.scan_tree(tmp_path)["fingerprint"] == []


def test_unreadable_text_file_skipped(tmp_path, monkeypatch, sc):
    write(tmp_path / "a.js", "eval(proxyInfo)")
    monkeypatch.setattr(S, "read_text_capped", lambda p: None)
    assert sc.scan_tree(tmp_path)["fingerprint"] == []


@pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")
def test_git_history_finds_removed_payload(sc, tmp_path):
    repo = tmp_path / "g"
    repo.mkdir()
    git(repo, "init", "-q")
    write(repo / "a.js", "eval(proxyInfo)\n")
    git(repo, "add", ".")
    git(repo, "commit", "-qm", "bad")
    write(repo / "a.js", "console.log(1)\n")
    git(repo, "commit", "-qam", "clean")
    out = sc.scan_git_history(repo)
    assert out["infected"] and out["commits_scanned"] == 2
    assert len(out["diff_findings"][0]["commit"]) == 12
    assert not sc.scan_tree(repo)["infected"]           # HEAD is clean; history is not


def test_git_history_errors(sc, tmp_path, monkeypatch):
    out = sc.scan_git_history(tmp_path)                  # not a repo
    assert "error" in out and not out["infected"]

    calls = {"n": 0}

    def fake_run(cmd, **kw):
        calls["n"] += 1
        if "rev-list" in cmd:
            return subprocess.CompletedProcess(cmd, 0, stdout="abc\ndef\n")
        raise subprocess.CalledProcessError(1, cmd)
    monkeypatch.setattr(S.subprocess, "run", fake_run)
    out = sc.scan_git_history(tmp_path)
    assert out["commits_scanned"] == 0 and calls["n"] == 3


def test_print_human(capsys):
    results = {"repo": "r", "vscode": [{"severity": "critical", "path": "p", "reason": "why"}],
               "magic": [], "fingerprint": [{"severity": "high", "where": "w", "sig_id": "s", "desc": "d"}],
               "av": [{"commit": "c", "state": "x"}], "infected": False}
    S._print_human(results, {"commits_scanned": 2, "diff_findings": [{"severity": "critical", "detail": "dd"}],
                             "error": "oops", "infected": True})
    out = capsys.readouterr().out
    assert "VS CODE" in out and "ANTIVIRUS ENGINE" in out and "git scan note: oops" in out
    assert "RESULT: INFECTED" in out
    S._print_human({**results, "vscode": []}, None)
    assert "RESULT: clean" in capsys.readouterr().out
    S._print_human(results, {"commits_scanned": 1, "diff_findings": []})
    assert "git scan note" not in capsys.readouterr().out


@pytest.mark.parametrize("argv,rc,needle", [
    (["scan-tree", str(INFECTED)], 1, "RESULT: INFECTED"),
    (["scan-tree", str(CLEAN), "--json"], 0, '"infected": false'),
    (["guard-open", str(INFECTED)], 1, "DO NOT OPEN"),
    (["guard-open", str(CLEAN), "--json"], 0, '"safe_to_open": true'),
])
def test_main(monkeypatch, capsys, argv, rc, needle):
    monkeypatch.setattr(sys, "argv", ["scanner.py"] + argv)
    assert S.main() == rc
    assert needle in capsys.readouterr().out


def test_main_scan_git_outside_a_repo(monkeypatch, capsys, tmp_path):
    monkeypatch.setattr(sys, "argv", ["scanner.py", "scan-git", str(tmp_path)])
    monkeypatch.setenv("GIT_CEILING_DIRECTORIES", str(tmp_path.parent))
    assert S.main() == 0
    assert "git scan note" in capsys.readouterr().out


def test_baselined_workflow_not_reported(sc, tmp_path):
    repo = tmp_path / "repo"
    write(repo / ".github" / "workflows" / "build.yml", "on: push\n")
    sc.workflow_baseline.record(repo)
    assert sc.scan_tree(repo)["workflow_baseline"] == []


def test_main_custom_signature_path(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["scanner.py", "guard-open", str(CLEAN), "--signatures",
                                      str(ROOT / "signatures.json")])
    assert S.main() == 0


def test_module_entry(monkeypatch, capsys):
    import runpy
    monkeypatch.setattr(sys, "argv", ["scanner.py", "guard-open", str(CLEAN)])
    with pytest.raises(SystemExit) as exc:
        runpy.run_path(str(ROOT / "scanner.py"), run_name="__main__")
    assert exc.value.code == 0
