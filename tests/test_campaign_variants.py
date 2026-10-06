"""Campaign variants that replaced a whole config or hid in a fake font.

Fixtures are synthetic: the campaign id marker is real, the body is not.
"""

from __future__ import annotations

import json

import magic_bytes as MB
import remediator as RM
import scanner as S
from conftest import ROOT, write

INFECTED = ROOT / "testdata" / "campaign-infected"
CLEAN = ROOT / "testdata" / "campaign-clean"
SIG = S.load_signatures()


def test_signature_regex_matches_the_shared_marker():
    raw = json.loads((ROOT / "signatures.json").read_text(encoding="utf-8"))
    pattern = next(r["pattern"] for r in raw["regexes"] if r["id"] == "campaign.a10.marker")
    assert pattern == MB.CAMPAIGN_MARKER_TEXT
    assert set(RM._CAMPAIGN_PUSHERS) <= set(raw["known_dropper_filenames"])


def test_marker_shapes_and_near_misses():
    m = S.GuardScanner(SIG).matcher
    assert {x.sig_id for x in m.scan_content("postcss.config.mjs", 'global.i="A10-*41560";')} == {
        "campaign.a10.marker"}
    assert any(x.sig_id == "campaign.a10.marker"
               for x in m.scan_content("a.mjs", "global.i = 'A10-*050';"))
    assert m.scan_content("a.mjs", 'global.installed = "A10-100";') == []
    assert m.scan_content("a.mjs", 'const id = "A10-*000";') == []
    ids = {x.sig_id for x in m.scan_content("temp_auto_push.bat", "")}
    assert "drop.file.name" in ids
    ids = {x.sig_id for x in m.scan_content(".vscode/tasks.json",
                                            '"command": "node ./public/fonts/fa-solid-600.eot"')}
    assert "drop.cmd.4" in ids


def test_fake_font_is_critical_real_font_is_not():
    c = MB.MagicByteChecker.from_signatures(SIG)
    eot = c.check_file(INFECTED / "public" / "fonts" / "fa-solid-600.eot")
    assert eot and eot[0].severity == "critical" and "campaign payload" in eot[0].reason
    woff = c.check_bytes("x.woff2", b"wOF2" + b" " * 80 + b"global.i='A10-*003';")
    assert woff[0].severity == "critical" and "campaign payload" in woff[0].reason
    assert c.check_file(CLEAN / "public" / "fonts" / "fa-solid-900.woff2") == []
    assert c.check_file(CLEAN / "public" / "fonts" / "fa-solid-900.eot") == []
    # .eot with ordinary source text, and no campaign marker, stays high.
    assert c.check_bytes("a.eot", b"module.exports = 1")[0].severity == "high"


def test_infected_fixture_detected_clean_control_is_not():
    sc = S.GuardScanner(SIG)
    bad = sc.scan_tree(INFECTED)
    assert bad["infected"]
    ids = {x["sig_id"] for x in bad["fingerprint"]}
    assert "campaign.a10.marker" in ids and "drop.file.name" in ids
    magic_paths = {x["path"] for x in bad["magic"] if x["severity"] == "critical"}
    assert magic_paths == {
        "public/fonts/fa-solid-600.eot",
        "public/fonts/fa-solid-500.woff2",
    }
    good = sc.scan_tree(CLEAN)
    assert not good["infected"] and good["fingerprint"] == [] and good["magic"] == []


def test_clean_repo_quarantines_payloads_and_restores(tmp_path):
    rem = RM.Remediator(tmp_path / "home", log=lambda *_: None)
    repo = tmp_path / "repo"
    for src in INFECTED.rglob("*"):
        if src.is_file():
            dest = repo / src.relative_to(INFECTED)
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(src.read_bytes())
    summary = rem.clean_repo(repo)
    quarantined = set(summary["quarantined"])
    assert str(repo / "postcss.config.mjs") in quarantined
    assert str(repo / "public" / "fonts" / "fa-solid-600.eot") in quarantined
    assert str(repo / "public" / "fonts" / "fa-solid-500.woff2") in quarantined
    assert str(repo / "temp_auto_push.bat") in quarantined
    assert str(repo / "temp_interactive_push.bat") in quarantined
    assert not (repo / "postcss.config.mjs").exists()
    assert summary["manual"] == []
    assert not S.GuardScanner(SIG).scan_tree(repo)["infected"]
    restored = rem.restore(str(repo / "postcss.config.mjs"))
    assert restored["restored"] == [str(repo / "postcss.config.mjs")]
    assert "A10-*000" in (repo / "postcss.config.mjs").read_text()
    assert S.GuardScanner(SIG).scan_tree(repo)["infected"]


def test_remediate_file_campaign_paths(tmp_path):
    rem = RM.Remediator(tmp_path / "home", log=lambda *_: None)
    cfg = write(tmp_path / "tailwind.config.js", 'global.i="A10-*004";\n')
    res = rem.remediate_file(cfg)
    assert res["action"] == "quarantine" and res["reason"].startswith("whole-file")
    assert not cfg.exists()

    font = write(tmp_path / "fa-solid-600.eot", "   global.i = 'A10-*005';\n")
    res = rem.remediate_file(font)
    assert res["action"] == "quarantine" and not font.exists()

    bat = write(tmp_path / "temp_interactive_push.bat", "@echo off\n")
    res = rem.remediate_file(bat)
    assert res["action"] == "quarantine" and res["reason"] == "campaign push helper"

    src = write(tmp_path / "app.js", 'global.i = "A10-*006";\nexport const n = 1;\n')
    assert rem.remediate_file(src)["action"] == "manual" and src.exists()

    assert rem._is_campaign_payload(tmp_path / "postcss.config.mjs") is False
    missing_dir = tmp_path / "nested"
    missing_dir.mkdir()
    as_config = missing_dir / "postcss.config.mjs"
    as_config.mkdir()
    assert rem._is_campaign_payload(as_config) is False


def test_clean_config_is_not_a_campaign_payload(tmp_path):
    rem = RM.Remediator(tmp_path / "home")
    cfg = write(tmp_path / "next.config.mjs", "export default {};\n")
    assert rem._is_campaign_payload(cfg) is False
    assert rem.remediate_file(cfg)["action"] == "manual" and cfg.exists()
