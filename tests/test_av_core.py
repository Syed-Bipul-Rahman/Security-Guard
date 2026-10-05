"""Unit tests: model, hashing, filetype, hashdb, allowlist."""

from __future__ import annotations

import hashlib
import json

import pytest

from conftest import build_elf, build_pe, write
from guard_av import filetype as ft
from guard_av.allowlist import Allowlist
from guard_av.hashdb import HashDatabase, algo_for
from guard_av.hashing import hash_bytes, hash_file, shannon_entropy
from guard_av.model import Detection, ScanResult, Verdict


# ---------------------------------------------------------------- model
class TestVerdict:
    def test_ordering_and_max(self):
        assert max(Verdict.CLEAN, Verdict.MALICIOUS, Verdict.SUSPICIOUS) is Verdict.MALICIOUS

    @pytest.mark.parametrize("raw,want", [("malicious", Verdict.MALICIOUS), (" Suspicious ", Verdict.SUSPICIOUS),
                                          (Verdict.CLEAN, Verdict.CLEAN)])
    def test_parse(self, raw, want):
        assert Verdict.parse(raw) is want

    def test_parse_rejects_unknown(self):
        with pytest.raises(ValueError, match="unknown verdict"):
            Verdict.parse("evil")

    def test_label(self):
        assert Verdict.SUSPICIOUS.label == "suspicious"


class TestScanResult:
    def test_clean_defaults(self):
        r = ScanResult("x")
        assert not r.infected and r.threat_name == "" and r.finalize().verdict is Verdict.CLEAN

    def test_finalize_takes_worst_of_own_and_children(self):
        child = ScanResult("a!b", detections=[Detection("rule", "Bad", Verdict.MALICIOUS)]).finalize()
        r = ScanResult("a", detections=[Detection("heuristic", "Meh", Verdict.SUSPICIOUS)], children=[child])
        r.finalize()
        assert r.infected
        assert r.threat_name == "Bad"
        assert [d.name for d in r.iter_detections()] == ["Meh", "Bad"]

    def test_to_dict_roundtrips_to_json(self):
        d = Detection("rule", "T", Verdict.MALICIOUS, rule_id="r1", whole_file=True)
        r = ScanResult("p", detections=[d], children=[ScanResult("p!c")]).finalize()
        out = json.loads(json.dumps(r.to_dict()))
        assert out["verdict"] == "malicious" and out["threat"] == "T"
        assert out["detections"][0]["verdict"] == "malicious"
        assert out["children"][0]["path"] == "p!c"


# -------------------------------------------------------------- hashing
def test_hash_bytes_and_file_agree(tmp_path):
    data = b"guard" * 300000   # > 1 MiB chunk, exercises streaming
    f = write(tmp_path / "f.bin", data)
    assert hash_file(f) == hash_bytes(data)
    assert hash_bytes(data)["sha256"] == hashlib.sha256(data).hexdigest()


@pytest.mark.parametrize("data,lo,hi", [(b"", 0, 0), (b"aaaa", 0, 0), (bytes(range(256)), 8, 8),
                                        (b"ab" * 50, 1, 1)])
def test_entropy(data, lo, hi):
    assert lo <= round(shannon_entropy(data), 6) <= hi


# ------------------------------------------------------------- filetype
@pytest.mark.parametrize("head,name,tag", [
    (build_pe(), "", "pe"),
    (build_elf(), "", "elf"),
    (b"\xcf\xfa\xed\xfe" + b"\0" * 8, "", "macho"),
    (b"\xca\xfe\xba\xbe\x00\x00\x00\x02", "", "macho-fat"),
    (b"\xca\xfe\xba\xbe\x00\x00\x00\x34", "", "java-class"),
    (b"\xca\xfe\xba\xbe", "", "macho-fat"),
    (b"PK\x03\x04rest", "", "zip"),
    (b"\x1f\x8b\x08", "", "gzip"),
    (b"\0" * 257 + b"ustar\x0000", "", "tar"),
    (b"%PDF-1.7", "", "pdf"),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "", "ole"),
    (b"#!/usr/bin/env python3\nprint()", "", "python"),
    (b"#!/bin/bash\necho", "", "shell"),
    (b"#!/usr/bin/env\n", "", "script"),
    (b"#!/opt/weird/interp\n", "", "script"),
    (b"#!\n", "", "script"),
    (b"#!/usr/local/bin/node\n", "", "javascript"),
    (b"console.log(1)", "a.js", "javascript"),
    (b"Write-Host hi", "a.PS1", "powershell"),
    (b"plain words", "notes", "text"),
    (b"", "", "text"),
    (b"\xff\xfeh\x00i\x00", "", "text"),
    (b"caf\xc3", "", "text"),                 # multibyte char cut at the sniff boundary
    (b"\x00\x01\x02\x03binary", "", "binary"),
    (b"\xc3\x28" + b"x" * 20, "", "binary"),  # invalid utf-8 early
])
def test_identify(head, name, tag):
    assert ft.identify(head, name) == tag


def test_type_groups():
    assert ft.is_executable("pe") and not ft.is_executable("zip")
    assert ft.is_archive("tar") and not ft.is_archive("pe")
    assert ft.is_script("powershell") and not ft.is_script("text")


# --------------------------------------------------------------- hashdb
class TestHashDatabase:
    def test_algo_for(self):
        assert algo_for("a" * 32) == "md5" and algo_for("A" * 40) == "sha1" and algo_for("0" * 64) == "sha256"
        assert algo_for("xyz") is None and algo_for("a" * 33) is None and algo_for("") is None

    def test_add_lookup_prefers_sha256(self):
        db = HashDatabase()
        h = hash_bytes(b"evil")
        db.add(h["md5"], "ByMd5")
        db.add(h["sha256"].upper(), "BySha", "suspicious")
        algo, entry = db.lookup(h)
        assert algo == "sha256" and entry.name == "BySha" and entry.verdict is Verdict.SUSPICIOUS
        assert len(db) == 2
        assert db.lookup(hash_bytes(b"good")) is None
        assert db.lookup({"md5": h["md5"]})[1].name == "ByMd5"

    def test_add_rejects_garbage(self):
        with pytest.raises(ValueError):
            HashDatabase().add("nothex", "x")

    def test_json_roundtrip(self, tmp_path):
        db = HashDatabase()
        db.add("a" * 64, "A")
        db.add("b" * 40, "B", "suspicious")
        f = write(tmp_path / "h.json", json.dumps(db.to_json()))
        db2 = HashDatabase()
        assert db2.load(f) == 2
        assert db2.lookup({"sha1": "b" * 40})[1].verdict is Verdict.SUSPICIOUS
        f2 = write(tmp_path / "h2.json", json.dumps({"entries": [{"md5": "c" * 32}]}))
        db2.load_json(f2)
        assert db2.lookup({"md5": "c" * 32})[1].name == "Unnamed"

    def test_text_import(self, tmp_path):
        f = write(tmp_path / "list.txt", "# comment\n\n" + "d" * 64 + "  Trojan.X  # trailing\n"
                  + "e" * 32 + "\nnot-a-hash Foo\n")
        db = HashDatabase()
        assert db.load(f) == 2
        assert db.lookup({"sha256": "d" * 64})[1].name == "Trojan.X"
        assert db.lookup({"md5": "e" * 32})[1].name == "Hash.Blocklisted"


# ------------------------------------------------------------ allowlist
class TestAllowlist:
    def test_hash_path_and_rule(self, tmp_path):
        f = write(tmp_path / "a.json", json.dumps({"sha256": ["AB" * 32], "paths": ["*/vendor/*"],
                                                   "rules": ["rule.x", "Threat.Y"]}))
        al = Allowlist.load(f)
        assert al.file_reason("x", "ab" * 32).startswith("known-good hash")
        assert al.file_reason("C:\\proj\\vendor\\lib.dll") == "path matches */vendor/*"
        assert al.file_reason("/proj/src/a.js", "00" * 32) == ""
        assert al.suppresses(Detection("rule", "Other", Verdict.MALICIOUS, rule_id="rule.x"))
        assert al.suppresses(Detection("heuristic", "Threat.Y", Verdict.SUSPICIOUS))
        assert not al.suppresses(Detection("rule", "Z", Verdict.MALICIOUS, rule_id="rule.z"))

    def test_merge_add_and_json(self):
        a = Allowlist(paths=["*/a/*"])
        a.merge(Allowlist(sha256=["CC" * 32], paths=["*/a/*", "*/b/*"], rules=["r"]))
        a.add_hash("DD" * 32)
        out = a.to_json()
        assert out["paths"] == ["*/a/*", "*/b/*"] and out["rules"] == ["r"]
        assert out["sha256"] == sorted(["cc" * 32, "dd" * 32])
        assert Allowlist().to_json() == {"sha256": [], "paths": [], "rules": []}
