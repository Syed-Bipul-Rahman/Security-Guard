"""Integration points of the av engine with the always-on watcher and the
single `guard` entrypoint."""

from __future__ import annotations

import json

import pytest

import guard
import samples
import watcher as W
from conftest import ROOT, write


@pytest.fixture
def watch(tmp_path, monkeypatch):
    monkeypatch.setattr(W.Watcher, "_maybe_notify", lambda self, *a, **k: None)
    monkeypatch.setattr(W.Watcher, "_notify_neutralized", lambda self, *a, **k: None)
    w = W.Watcher(config={"watch_roots": [str(tmp_path / "root")], "notify": False},
                  home=tmp_path / "home")
    yield w
    w._store.close()


def alerts(w) -> list[dict]:
    if not w.alert_path.exists():
        return []
    return [json.loads(x) for x in w.alert_path.read_text().splitlines()]


def test_watcher_quarantines_downloaded_malware(watch, tmp_path):
    f = write(tmp_path / "Downloads" / "invoice.com", samples.eicar())
    watch._scan_file(str(f))
    assert not f.exists()                                        # quarantined, backed up
    assert alerts(watch)[0]["kind"] == "new-file"
    assert "EICAR-Test-File" in alerts(watch)[0]["findings"][0]


def test_watcher_leaves_clean_and_suspicious_files(watch, tmp_path):
    ok = write(tmp_path / "Downloads" / "notes.txt", "hello")
    pua = write(tmp_path / "Downloads" / "pool.json", samples.decoded(samples.SUSPICIOUS)["miner.json"][1])
    watch._scan_file(str(ok))
    watch._scan_file(str(pua))
    assert ok.exists() and pua.exists() and alerts(watch) == []


def test_watcher_alert_only_mode(tmp_path, monkeypatch):
    monkeypatch.setattr(W.Watcher, "_maybe_notify", lambda self, *a, **k: None)
    w = W.Watcher(config={"watch_roots": [str(tmp_path)], "remediate": False}, home=tmp_path / "h")
    f = write(tmp_path / "x.com", samples.eicar())
    w._scan_file(str(f))
    w._store.close()
    assert f.exists() and alerts(w)[0]["kind"] == "new-file"


def test_watcher_review_hit_in_source_is_not_deleted(watch, tmp_path):
    f = write(tmp_path / "site" / "index.php", samples.decoded(samples.MALICIOUS)["webshell_eval.php"][1])
    watch._scan_file(str(f))
    assert f.exists() and alerts(watch)


def test_watcher_repo_scan_counts_av_bucket(watch, tmp_path):
    repo = tmp_path / "repo"
    (repo / ".git").mkdir(parents=True)
    write(repo / "tools" / "e.com", samples.eicar())
    watch._scan_repo(str(repo), "clone")
    assert not (repo / "tools" / "e.com").exists()
    assert any(a["kind"] == "tree" for a in alerts(watch))


# ------------------------------------------------------------------ guard CLI
def test_guard_av_dispatch(tmp_path, capsys):
    f = write(tmp_path / "e.com", samples.eicar())
    assert guard.main(["av", "scan", str(f)]) == 1
    assert "EICAR-Test-File" in capsys.readouterr().out
    assert guard.main(["av", "hash", str(f)]) == 0


def test_guard_version_and_help(capsys):
    assert guard.main(["version"]) == 0
    assert capsys.readouterr().out.strip() == f"guard {guard.VERSION}"
    assert guard.main([]) == 0
    assert "guard av scan" in capsys.readouterr().out


def test_guard_scan_reports_av_findings(tmp_path, capsys):
    write(tmp_path / "e.com", samples.eicar())
    assert guard.main(["scan", str(tmp_path)]) == 1
    assert "ANTIVIRUS ENGINE" in capsys.readouterr().out
    assert guard.main(["scan", str(ROOT / "testdata" / "clean-repo")]) == 0


def test_build_spec_bundles_engine():
    spec = (ROOT / "build" / "guard.spec").read_text()
    assert '(str(ROOT / "guard_av"), "guard_av")' in spec
    for mod in ("zipfile", "tarfile", "lzma", "bz2", "unicodedata"):
        assert f'"{mod}"' in spec
