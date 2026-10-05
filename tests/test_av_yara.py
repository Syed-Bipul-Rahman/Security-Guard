"""YARA rules (yara-x in guard_core) next to the JSON rules.

Runs once per backend: with the Rust core YARA rules match; without it they are
read but reported as unavailable, and scans are unchanged.
"""

from __future__ import annotations

import pytest

from conftest import write
from guard_av import cli
from guard_av import yara_rules as Y
from guard_av.allowlist import Allowlist
from guard_av.engine import ScanEngine
from guard_av.model import Verdict
from guard_av.rules import RuleError

RULES = r"""
rule DropperMarker : dropper {
    meta:
        verdict = "malicious"
        whole_file = true
        description = "drops the second stage"
    strings:
        $url = "evil.example/stage2"
        $mz = { 4D 5A 90 00 }
    condition:
        any of them
}

rule LooseHunt : hunting research {
    meta:
        verdict = "nonsense"
    strings:
        $a = "hunting-marker"
    condition:
        $a
}

rule ClaimsClean {
    meta:
        verdict = "clean"
        whole_file = "yes"
    condition:
        filesize == 13
}

private rule helper { condition: true }
"""

SAMPLE = b"GET http://evil.example/stage2 HTTP/1.1"


@pytest.fixture
def sigdir(tmp_path):
    d = tmp_path / "sigs"
    write(d / "community.yar", RULES)
    write(d / "notes.txt", "not a rule file")
    return d


def scan(engine: ScanEngine, data: bytes, name: str = "x.bin"):
    return engine.scan_bytes(data, name)


def test_yara_rules_detect(sigdir, av_backend):
    engine = ScanEngine.default(extra_dirs=[sigdir])
    res = scan(engine, SAMPLE)
    yara_hits = [d for d in res.detections if d.engine == "yara"]
    if av_backend == "python":
        assert engine.yara.unavailable and len(engine.yara) == 0 and engine.yara.warnings == []
        assert yara_hits == []
        return
    assert not engine.yara.unavailable and len(engine.yara) == 4
    [d] = yara_hits
    assert (d.name, d.rule_id, d.verdict) == ("DropperMarker", "yara:community.DropperMarker",
                                              Verdict.MALICIOUS)
    assert d.whole_file and d.description == "drops the second stage"
    assert d.evidence == "$url@11: evil.example/stage2 HTTP/1.1"
    assert res.verdict is Verdict.MALICIOUS


@pytest.mark.parametrize("data, name, why", [
    (b"..hunting-marker..", "LooseHunt", "unknown verdict"),
    (b"thirteen byte", "ClaimsClean", "a rule cannot clear a file"),
])
def test_yara_defaults_to_suspicious(sigdir, av_backend, data, name, why):
    if av_backend == "python":
        pytest.skip("YARA needs the Rust core")
    engine = ScanEngine.default(extra_dirs=[sigdir])
    [d] = [d for d in scan(engine, data).detections if d.engine == "yara"]
    assert d.name == name and d.verdict is Verdict.SUSPICIOUS, why
    assert not d.whole_file
    if name == "LooseHunt":
        assert d.description == "hunting research"      # tags stand in for a description
    else:
        assert d.evidence == ""                          # no strings, nothing to show


def test_rule_files_are_allowlisted_and_rules_can_be_disabled(sigdir, av_backend):
    engine = ScanEngine.default(extra_dirs=[sigdir])
    assert scan(engine, (sigdir / "community.yar").read_bytes(), "community.yar").allowlisted
    engine.allowlist.merge(Allowlist(rules=["yara:community.DropperMarker"]))
    engine._cache.clear()
    assert [d for d in scan(engine, SAMPLE).detections if d.engine == "yara"] == []


def test_compile_errors_name_the_file(tmp_path, av_backend):
    d = tmp_path / "bad"
    write(d / "broken.yara", "rule broken { condition: $missing }")
    if av_backend == "python":
        assert ScanEngine.default(extra_dirs=[d]).yara.unavailable
        return
    with pytest.raises(RuleError, match="broken.yara"):
        ScanEngine.default(extra_dirs=[d])


def test_sources_recompile_when_added(av_backend):
    ys = Y.YaraRuleSet()
    assert len(ys) == 0 and ys.scan(b"abc") == [] and not ys.unavailable
    ys.add_source('rule one { strings: $a = "one" condition: $a }', namespace="n1")
    if av_backend == "python":
        assert ys.unavailable and ys.compile() is None
        return
    first = ys.compile()
    assert ys.compile() is first                         # cached until something changes
    ys.add_source('rule two { strings: $a = "two" condition: $a }', namespace="n2")
    assert len(ys) == 2 and ys.compile() is not first
    assert [d.rule_id for d in ys.scan(b"one two")] == ["yara:n1.one", "yara:n2.two"]


def test_timeouts_skip_the_file(av_backend):
    class Slow:
        def scan(self, *_):
            raise TimeoutError("timed out")

    ys = Y.YaraRuleSet()
    ys.add_source("rule r { condition: true }")
    if av_backend == "python":
        assert ys.scan(b"x") == []
        return
    ys.compile()
    ys._compiled = Slow()
    assert ys.scan(b"x") == [] and ys.timeouts == 1


def test_cli_lists_and_validates_yara(tmp_path, sigdir, av_backend, capsys):
    write(tmp_path / "guard_home" / "av" / "community.yar", RULES)
    assert cli.main(["rules"]) == 0
    out = capsys.readouterr().out
    bad = write(tmp_path / "bad.yar", "rule bad { condition: $nope }")
    warn = write(tmp_path / "warn.yar", "rule w { strings: $a = { 00 [0-1] [0-1] 01 } condition: $a }")
    rc = cli.main(["rules", "--validate", str(sigdir / "community.yar"), str(bad), str(warn)])
    checked = capsys.readouterr().out
    if av_backend == "python":
        assert "0 YARA rule(s)" in out and "no Rust core" in out
        assert rc == 2 and checked.count("FAIL") == 3
        return
    assert "4 YARA rule(s)" in out and "no Rust core" not in out
    assert rc == 2 and checked.count("FAIL") == 1
    assert f"OK   {sigdir / 'community.yar'}: 4 rule(s)" in checked
    assert "WARN" in checked
