"""Engine pipeline, quarantine vault and CLI tests."""

from __future__ import annotations

import json
import os
import runpy
import sys
from pathlib import Path

import pytest

import samples
from conftest import EXEC, READ, WRITE, build_pe, gz, make_tar, make_zip, random_bytes, write
from guard_av import cli
from guard_av import quarantine as Q
from guard_av.allowlist import Allowlist
from guard_av.archive import ArchiveLimits
from guard_av.engine import DATA_DIR, EngineConfig, ScanEngine, ScanSummary, action_hint
from guard_av.hashdb import HashDatabase
from guard_av.hashing import hash_bytes
from guard_av.model import Detection, ScanResult, Verdict
from guard_av.rules import RuleSet

EICAR = samples.eicar()
WEBSHELL = samples.decoded(samples.MALICIOUS)["webshell_eval.php"][1]
MINER = samples.decoded(samples.SUSPICIOUS)["miner.json"][1]


def evil_pe(name_extra: bytes = b"") -> bytes:
    return build_pe(
        sections=[(b"UPX0", EXEC | WRITE | READ, random_bytes(4096)), (b".rsrc", READ, b"\0" * 64)],
        entry=0x9000, extra=b"VirtualAllocEx\0WriteProcessMemory\0CreateRemoteThread\0" + name_extra)


# ------------------------------------------------------------------ engine
class TestPipeline:
    def test_eicar_hash_and_rule(self, engine):
        r = engine.scan_bytes(EICAR, "eicar.com")
        assert r.infected and {d.engine for d in r.detections} == {"hash", "rule"}
        assert action_hint(r) == "quarantine"

    def test_eicar_with_trailing_whitespace_caught_by_rule_only(self, engine):
        r = engine.scan_bytes(EICAR + b"\r\n", "eicar.txt")
        assert [d.engine for d in r.detections] == ["rule"] and r.infected

    def test_eicar_not_at_offset_zero_is_not_eicar(self, engine):
        assert engine.scan_bytes(b"x" + EICAR, "e.txt").verdict is Verdict.CLEAN

    def test_rule_hit_in_source_file_is_review_not_quarantine(self, engine):
        r = engine.scan_bytes(WEBSHELL, "index.php")
        assert r.infected and action_hint(r) == "review"

    def test_suspicious_has_no_action(self, engine):
        r = engine.scan_bytes(MINER, "config.json")
        assert r.verdict is Verdict.SUSPICIOUS and action_hint(r) == ""

    def test_heuristic_malicious_pe(self, engine):
        r = engine.scan_bytes(evil_pe(), "svch0st.exe")
        assert r.infected and r.threat_name.startswith("Heur.Malware.")
        assert r.heuristic_score >= 150 and action_hint(r) == "quarantine"

    def test_heuristic_suspicious_only(self, engine):
        codes = b",".join(b"%d" % (65 + i % 26) for i in range(40))
        r = engine.scan_bytes(b"_0x1a2b " * 60 + b"eval(String.fromCharCode(" + codes + b"))", "a.js")
        assert r.verdict is Verdict.SUSPICIOUS and r.threat_name.startswith("Heur.Suspicious.")

    def test_heuristics_disabled(self):
        e = ScanEngine.default(EngineConfig(heuristics=False))
        r = e.scan_bytes(evil_pe(), "x.exe")
        assert r.verdict is Verdict.CLEAN and r.heuristic_score == 0

    def test_masquerading_pe_executable_is_quarantined(self):
        e = ScanEngine.default(EngineConfig(suspicious_threshold=10, malicious_threshold=40,
                                            malicious_min_strong=1))
        r = e.scan_bytes(build_pe(), "cv.pdf")
        assert r.infected and action_hint(r) == "quarantine"

    def test_nested_archives(self, engine):
        inner = make_zip({"payload/eicar.com": EICAR, "clean.txt": b"hello"})
        outer = make_tar({"inner.zip": inner, "readme.md": b"# hi"}, "w:gz")
        r = engine.scan_bytes(outer, "bundle.tgz")
        assert r.infected and action_hint(r) == "quarantine"
        assert [c.path for c in r.children] == ["bundle.tgz!inner.zip"]
        assert r.children[0].children[0].path == "bundle.tgz!inner.zip!payload/eicar.com"
        assert r.threat_name == "EICAR-Test-File"

    def test_archive_depth_limit(self):
        e = ScanEngine.default(EngineConfig(max_archive_depth=1))
        deep = make_zip({"l1.zip": make_zip({"eicar.com": EICAR})})
        assert e.scan_bytes(deep, "d.zip").verdict is Verdict.CLEAN
        assert ScanEngine.default().scan_bytes(deep, "d.zip").infected

    def test_archives_disabled(self):
        e = ScanEngine.default(EngineConfig(scan_archives=False))
        assert e.scan_bytes(make_zip({"e.com": EICAR}), "z.zip").verdict is Verdict.CLEAN

    def test_gzip_stream_of_webshell(self, engine):
        assert engine.scan_bytes(gz(WEBSHELL), "shell.php.gz").infected

    def test_zip_bomb_is_suspicious(self, engine):
        r = engine.scan_bytes(make_zip({"zeros": b"\0" * (4 * 1024 * 1024)}), "bomb.zip")
        assert r.verdict is Verdict.SUSPICIOUS and r.threat_name == "Archive.Bomb"

    def test_allowlist_by_path_hash_and_rule(self):
        e = ScanEngine.default()
        e.allowlist.merge(Allowlist(paths=["*/fixtures/*"], rules=["Archive.Bomb", "webshell.php.superglobal-exec"]))
        assert e.scan_bytes(EICAR, "/x/fixtures/eicar").allowlisted.startswith("path")
        assert e.scan_bytes(WEBSHELL, "a.php").verdict is Verdict.CLEAN
        assert e.scan_bytes(make_zip({"z": b"\0" * (4 * 1024 * 1024)}), "b.zip").verdict is Verdict.CLEAN
        e.allowlist.add_hash(hash_bytes(MINER)["sha256"])
        assert "known-good" in e.scan_bytes(MINER, "m.json").allowlisted

    def test_allowlist_suppresses_heuristic_name(self):
        e = ScanEngine.default()
        e.allowlist.merge(Allowlist(rules=["Heur.Malware.pe.api.process-injection"]))
        assert e.scan_bytes(evil_pe(), "x.exe").verdict is Verdict.CLEAN

    def test_engine_never_flags_its_own_databases(self, engine):
        for f in DATA_DIR.iterdir():
            r = engine.scan_file(f)
            assert r.verdict is Verdict.CLEAN and r.allowlisted, f

    def test_empty_engine(self):
        r = ScanEngine().scan_bytes(EICAR, "e")
        assert r.verdict is Verdict.CLEAN


class TestCache:
    def test_cache_hit_rebases_path(self):
        e = ScanEngine.default()
        a = e.scan_bytes(WEBSHELL, "/a/x.php")
        b = e.scan_bytes(WEBSHELL, "/b/x.php")
        assert a.path == "/a/x.php" and b.path == "/b/x.php"
        assert b.threat_name == a.threat_name and b.detections is not a.detections

    def test_same_content_different_name_rescanned(self):
        e = ScanEngine.default()
        assert e.scan_bytes(build_pe(), "a.exe").verdict is Verdict.CLEAN
        assert e.scan_bytes(build_pe(), "a.pdf.exe").heuristic_score > 0

    def test_lru_eviction_and_disabled(self):
        e = ScanEngine.default(EngineConfig(cache_size=2))
        for i in range(3):
            e.scan_bytes(b"x%d" % i, "f")
        assert len(e._cache) == 2
        e.scan_bytes(b"x1", "f")                    # hit: moves to end
        assert list(e._cache)[-1][0] == hash_bytes(b"x1")["sha256"]
        off = ScanEngine.default(EngineConfig(cache_size=0))
        off.scan_bytes(b"y", "f")
        assert len(off._cache) == 0


class TestFiles:
    def test_scan_file_reads_and_hashes(self, tmp_path, engine):
        f = write(tmp_path / "e.com", EICAR)
        r = engine.scan_file(f)
        assert r.infected and r.size == 68 and r.path == str(f)

    def test_large_file_hashes_whole_file_but_scans_prefix(self, tmp_path):
        e = ScanEngine.default(EngineConfig(max_scan_bytes=1024))
        data = EICAR + b"\n" + b"A" * 5000
        f = write(tmp_path / "big.bin", data)
        r = e.scan_file(f)
        assert r.size == len(data) and r.sha256 == hash_bytes(data)["sha256"]
        db = HashDatabase()
        db.add(hash_bytes(data)["sha256"], "Big.Bad")
        e2 = ScanEngine(EngineConfig(max_scan_bytes=1024), hashdb=db)
        assert e2.scan_file(f).threat_name == "Big.Bad"

    def test_scan_file_error(self, tmp_path, engine):
        r = engine.scan_file(tmp_path / "missing")
        assert r.error.startswith("FileNotFoundError")

    def test_scan_path_walks_skips_and_summarises(self, tmp_path, engine):
        write(tmp_path / "ok.txt", "hello")
        write(tmp_path / "sub" / "e.com", EICAR)
        write(tmp_path / "sub" / "m.json", MINER)
        write(tmp_path / ".git" / "objects" / "e.com", EICAR)       # skipped dir
        os.symlink(tmp_path / "sub" / "e.com", tmp_path / "link.com")   # never followed
        os.mkfifo(tmp_path / "pipe")                                  # not a regular file
        bad = write(tmp_path / "noperm.txt", "x")
        bad.chmod(0)
        seen = []
        s = engine.scan_path(tmp_path, on_result=seen.append)
        expected_errors = 0 if os.geteuid() == 0 else 1
        assert s.scanned == 4 and len(seen) == 4
        assert (s.malicious, s.suspicious, s.errors) == (1, 1, expected_errors)
        assert len(s.results) == 2 + expected_errors
        d = s.to_dict()
        assert d["scanned"] == 4 and isinstance(d["elapsed_sec"], float)
        bad.chmod(0o600)

    def test_scan_path_error_counted(self, tmp_path, engine, monkeypatch):
        write(tmp_path / "a.txt", "x")
        monkeypatch.setattr(engine, "scan_file", lambda p: ScanResult(str(p), error="boom"))
        s = engine.scan_path(tmp_path)
        assert s.errors == 1 and s.results[0].error == "boom"

    def test_scan_single_file_target(self, tmp_path, engine):
        f = write(tmp_path / "e.com", EICAR)
        assert engine.scan_path(f).malicious == 1

    def test_load_dir_user_signatures(self, tmp_path):
        d = tmp_path / "sigs"
        write(d / "rules-extra.json", json.dumps({"rules": [{"id": "u", "name": "User.Rule",
                                                             "strings": {"$a": {"text": "zzmarker"}},
                                                             "condition": "$a"}]}))
        write(d / "hashes-extra.txt", hash_bytes(b"custom-bad")["sha256"] + " Custom.Bad\n")
        write(d / "hashes-more.json", json.dumps({"entries": [{"md5": hash_bytes(b"x2")["md5"], "name": "X2"}]}))
        write(d / "allowlist-team.json", json.dumps({"paths": ["*/trusted/*"]}))
        e = ScanEngine.default(extra_dirs=[d])
        assert e.scan_bytes(b"..zzmarker..", "f").threat_name == "User.Rule"
        assert e.scan_bytes(b"custom-bad", "f").threat_name == "Custom.Bad"
        assert e.scan_bytes(b"x2", "f").threat_name == "X2"
        assert e.scan_bytes(EICAR, "/p/trusted/e").verdict is Verdict.CLEAN
        assert e.scan_file(d / "rules-extra.json").allowlisted

    def test_default_with_alternate_data_dir(self, tmp_path):
        e = ScanEngine.default(data_dir=tmp_path)
        assert len(e.rules) == 0 and len(e.hashdb) == 0

    def test_summary_defaults(self):
        assert ScanSummary().to_dict()["results"] == []

    def test_action_hint_cases(self):
        clean = ScanResult("x")
        assert action_hint(clean) == ""
        r = ScanResult("x", filetype="zip", detections=[Detection("rule", "n", Verdict.MALICIOUS)]).finalize()
        assert action_hint(r) == "quarantine"
        r = ScanResult("x", filetype="text", detections=[Detection("rule", "n", Verdict.MALICIOUS),
                                                         Detection("archive", "b", Verdict.SUSPICIOUS,
                                                                   whole_file=True)]).finalize()
        assert action_hint(r) == "review"

    def test_custom_components(self):
        rs, db, al = RuleSet(), HashDatabase(), Allowlist()
        e = ScanEngine(rules=rs, hashdb=db, allowlist=al)
        assert e.rules is rs and e.hashdb is db and e.allowlist is al


# -------------------------------------------------------------- quarantine
class TestQuarantine:
    def test_roundtrip(self, tmp_path):
        v = Q.QuarantineVault(tmp_path / "vault")
        assert v.list() == []
        f = write(tmp_path / "e.com", EICAR)
        rec = v.quarantine(f, threat="EICAR")
        assert not f.exists() and "key" not in rec
        stored = (tmp_path / "vault" / f"{rec['id']}.bin").read_bytes()
        assert stored != EICAR and b"EICAR" not in stored          # neutered at rest
        assert [x["id"] for x in v.list()] == [rec["id"]] and "key" not in v.list()[0]
        out = v.restore(rec["id"])
        assert out == f and f.read_bytes() == EICAR and v.list() == []

    def test_keep_original_restore_elsewhere_overwrite(self, tmp_path):
        v = Q.QuarantineVault(tmp_path / "vault")
        f = write(tmp_path / "a.bin", b"data" * 100)
        rec = v.quarantine(f, remove_original=False)
        assert f.exists()
        with pytest.raises(Q.QuarantineError, match="exists"):
            v.restore(rec["id"])
        assert v.restore(rec["id"], overwrite=True) == f
        rec = v.quarantine(f)
        dest = tmp_path / "out" / "copy.bin"
        assert v.restore(rec["id"], dest=dest) == dest and dest.read_bytes() == b"data" * 100

    def test_delete_and_errors(self, tmp_path):
        v = Q.QuarantineVault(tmp_path / "vault")
        rec = v.quarantine(write(tmp_path / "a", b"x"))
        v.delete(rec["id"])
        assert v.list() == []
        with pytest.raises(Q.QuarantineError, match="no quarantined item"):
            v.delete(rec["id"])
        with pytest.raises(Q.QuarantineError, match="invalid quarantine id"):
            v.restore("../../etc/passwd")
        with pytest.raises(Q.QuarantineError, match="cannot read"):
            v.quarantine(tmp_path / "missing")

    def test_integrity_failure(self, tmp_path):
        v = Q.QuarantineVault(tmp_path / "vault")
        rec = v.quarantine(write(tmp_path / "a", b"payload"))
        b = tmp_path / "vault" / f"{rec['id']}.bin"
        b.write_bytes(b"tampered")
        with pytest.raises(Q.QuarantineError, match="integrity"):
            v.restore(rec["id"])

    def test_list_skips_corrupt_records_and_sorts(self, tmp_path):
        v = Q.QuarantineVault(tmp_path / "vault")
        r1 = v.quarantine(write(tmp_path / "a", b"1"))
        r2 = v.quarantine(write(tmp_path / "b", b"2"))
        write(tmp_path / "vault" / "junk.json", "{not json")
        ids = [x["id"] for x in v.list()]
        assert ids == [r["id"] for r in sorted([r1, r2], key=lambda r: r["quarantined_at"])]

    def test_unlink_failure_is_recorded(self, tmp_path, monkeypatch):
        v = Q.QuarantineVault(tmp_path / "vault")
        f = write(tmp_path / "a", b"x")
        monkeypatch.setattr(Path, "unlink", lambda self, *a, **k: (_ for _ in ()).throw(PermissionError("ro")))
        rec = v.quarantine(f)
        assert "original not removed" in rec["note"] and f.exists()

    def test_chmod_failure_tolerated(self, tmp_path, monkeypatch):
        monkeypatch.setattr(os, "chmod", lambda *a, **k: (_ for _ in ()).throw(OSError("nope")))
        rec = Q.QuarantineVault(tmp_path / "vault").quarantine(write(tmp_path / "a", b"x"))
        assert rec["id"]

    def test_keystream_is_involution(self):
        key = b"k" * 32
        data = random_bytes(1000)
        assert Q._keystream_xor(Q._keystream_xor(data, key), key) == data
        assert Q._keystream_xor(b"", key) == b""


# --------------------------------------------------------------------- cli
class TestCLI:
    def test_scan_clean_and_infected_text(self, tmp_path, capsys):
        write(tmp_path / "clean" / "a.txt", "hello")
        assert cli.main(["scan", str(tmp_path / "clean")]) == 0
        write(tmp_path / "bad" / "e.com", EICAR)
        assert cli.main(["scan", str(tmp_path / "bad")]) == 1
        out = capsys.readouterr().out
        assert "[MALICIOUS]" in out and "EICAR-Test-File" in out and "-> quarantine" in out
        assert "1 malicious" in out

    def test_scan_json_and_quarantine(self, tmp_path, capsys):
        f = write(tmp_path / "t" / "e.com", EICAR)
        write(tmp_path / "t" / "shell.php", WEBSHELL)
        vault = tmp_path / "vault"
        rc = cli.main(["--vault", str(vault), "scan", str(tmp_path / "t"), "--json", "--quarantine"])
        out = json.loads(capsys.readouterr().out)
        assert rc == 1 and out["summary"]["malicious"] == 2
        by_action = {r["action"]: r for r in out["results"]}
        assert by_action["quarantine"]["quarantine_id"] and not f.exists()
        assert "quarantine_id" not in by_action["review"]                 # source file left in place
        assert cli.main(["--vault", str(vault), "quarantine", "list"]) == 0
        listed = json.loads(capsys.readouterr().out)
        qid = listed[0]["id"]
        assert cli.main(["--vault", str(vault), "quarantine", "restore", qid]) == 0
        assert f.read_bytes() == EICAR
        capsys.readouterr()
        rc = cli.main(["--vault", str(vault), "scan", str(f), "--quarantine"])
        assert rc == 1 and "quarantined" in capsys.readouterr().out

    def test_quarantine_failure_reported(self, tmp_path, capsys, monkeypatch):
        write(tmp_path / "e.com", EICAR)

        def boom(self, *a, **k):
            raise Q.QuarantineError("disk full")
        monkeypatch.setattr(Q.QuarantineVault, "quarantine", boom)
        cli.main(["--vault", str(tmp_path / "v"), "scan", str(tmp_path), "--json", "--quarantine"])
        assert json.loads(capsys.readouterr().out)["results"][0]["quarantine_error"] == "disk full"

    def test_suspicious_exit_codes_and_flags(self, tmp_path, capsys):
        write(tmp_path / "m.json", MINER)
        assert cli.main(["scan", str(tmp_path)]) == 0
        assert cli.main(["scan", str(tmp_path), "--fail-on-suspicious"]) == 1
        write(tmp_path / "z.zip", make_zip({"e.com": EICAR}))
        assert cli.main(["scan", str(tmp_path / "z.zip"), "--no-archives", "--no-heuristics"]) == 0

    def test_scan_error_line_and_missing_path(self, tmp_path, capsys, monkeypatch):
        assert cli.main(["scan", str(tmp_path / "nope")]) == 2
        assert "no such file" in capsys.readouterr().err
        write(tmp_path / "a.txt", "x")
        monkeypatch.setattr(ScanEngine, "scan_file", lambda self, p: ScanResult(str(p), error="EACCES"))
        assert cli.main(["scan", str(tmp_path)]) == 0
        assert "[ERROR]" in capsys.readouterr().out

    def test_scan_extra_signatures_and_guard_home(self, tmp_path, capsys, monkeypatch):
        sig = tmp_path / "sig"
        write(sig / "hashes.txt", hash_bytes(b"team-bad")["sha256"] + " Team.Bad\n")
        home_sig = tmp_path / "guard_home" / "av"
        write(home_sig / "hashes.txt", hash_bytes(b"home-bad")["sha256"] + " Home.Bad\n")
        write(tmp_path / "t" / "a", b"team-bad")
        write(tmp_path / "t" / "b", b"home-bad")
        assert cli.main(["scan", str(tmp_path / "t"), "--signatures", str(sig)]) == 1
        out = capsys.readouterr().out
        assert "Team.Bad" in out and "Home.Bad" in out

    def test_quarantine_errors_and_delete(self, tmp_path, capsys):
        v = str(tmp_path / "v")
        assert cli.main(["--vault", v, "quarantine", "restore", "bad-id"]) == 2
        assert "invalid quarantine id" in capsys.readouterr().err
        rec = Q.QuarantineVault(v).quarantine(write(tmp_path / "x", b"1"))
        assert cli.main(["--vault", v, "quarantine", "delete", rec["id"]]) == 0
        assert "deleted" in capsys.readouterr().out

    def test_default_vault_location(self, tmp_path, monkeypatch):
        args = cli._build_parser().parse_args(["quarantine", "list"])
        assert cli._vault(args).root == tmp_path / "guard_home" / "av-quarantine"
        monkeypatch.delenv("GUARD_HOME")
        assert cli.guard_home() == Path.home() / ".guard"

    def test_rules_listing_and_validation(self, tmp_path, capsys):
        assert cli.main(["rules"]) == 0
        out = capsys.readouterr().out
        assert "test.eicar" in out and "hash signature(s)" in out
        bad = write(tmp_path / "bad.json", json.dumps({"rules": [{"id": "x"}]}))
        assert cli.main(["rules", "--validate", str(DATA_DIR / "rules.json"), str(bad),
                         str(tmp_path / "missing.json")]) == 2
        out = capsys.readouterr().out
        assert "OK   " in out and out.count("FAIL") == 2

    def test_hash_command(self, tmp_path, capsys):
        f = write(tmp_path / "a", b"abc")
        assert cli.main(["hash", str(f)]) == 0
        assert hash_bytes(b"abc")["sha256"] in capsys.readouterr().out
        assert cli.main(["hash", str(tmp_path / "missing")]) == 2

    def test_usage_errors(self, capsys):
        assert cli.main([]) == 2
        assert cli.main(["--help"]) == 0

    def test_module_entry_point(self, tmp_path, monkeypatch, capsys):
        f = write(tmp_path / "a", b"abc")
        monkeypatch.setattr(sys, "argv", ["guard_av", "hash", str(f)])
        with pytest.raises(SystemExit) as exc:
            runpy.run_module("guard_av", run_name="__main__")
        assert exc.value.code == 0


def test_archive_limits_configurable():
    e = ScanEngine.default(EngineConfig(archive_limits=ArchiveLimits(max_members=1)))
    z = make_zip({"a.txt": b"fine", "e.com": EICAR})
    assert e.scan_bytes(z, "z.zip").verdict is Verdict.CLEAN
