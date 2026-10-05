"""Unit tests for the YARA-style rule engine."""

from __future__ import annotations

import json
import re

import pytest

from conftest import write
from guard_av import rules as R
from guard_av.engine import DATA_DIR
from guard_av.model import Verdict
from guard_av.rules import Rule, RuleError, RuleSet, compile_hex, compile_string


def rule(**kw) -> Rule:
    base = {"id": "t", "name": "T", "strings": {"$a": {"text": "abc"}}, "condition": "$a"}
    base.update(kw)
    return Rule.from_dict(base)


# ------------------------------------------------------------------ hex
@pytest.mark.parametrize("spec,data,hit", [
    ("4D 5A", b"MZ", True),
    ("4d5a", b"xMZ", True),
    ("4D ?? 5A", b"M\x00Z", True),
    ("4D [2-3] 5A", b"M..Z", True),
    ("4D [2-3] 5A", b"M.Z", False),
    ("4D [2] 5A", b"M..Z", True),
    ("(41|42) 43", b"BC", True),
    ("(41|42) 43", b"CC", False),
    ("2E", b"x", False),          # '.' must be escaped, not a wildcard
])
def test_compile_hex_semantics(spec, data, hit):
    assert bool(re.search(compile_hex(spec), data, re.DOTALL)) is hit


@pytest.mark.parametrize("spec,msg", [
    ("41 | 42", "outside a group"), ("41 )", "unbalanced"), ("(41", "unbalanced"),
    ("41 [2-", "unterminated"), ("41 [x] 42", "bad jump"), ("41 [5-2] 42", "inverted"),
    ("4G", "invalid token"), ("4", "invalid token"), ("", "empty"),
])
def test_compile_hex_errors(spec, msg):
    with pytest.raises(RuleError, match=msg):
        compile_hex(spec)


# --------------------------------------------------------------- strings
def test_text_string_variants():
    assert compile_string("$a", {"text": "Eval", "nocase": True}).search(b"EVAL")
    wide = compile_string("$w", {"text": "hi", "wide": True})
    assert wide.search(b"h\x00i\x00") and wide.search(b"hi")
    only_wide = compile_string("$w", {"text": "hi", "wide": True, "ascii": False})
    assert only_wide.search(b"h\x00i\x00") and not only_wide.search(b"hi")


def test_regex_string_flags():
    assert compile_string("$r", {"regex": "^b", "multiline": True}).search(b"a\nb")
    assert not compile_string("$r", {"regex": "a.b"}).search(b"a\nb")
    assert compile_string("$r", {"regex": "a.b", "dotall": True}).search(b"a\nb")


@pytest.mark.parametrize("spec,msg", [
    ("nope", "must be an object"), ({"text": ""}, "empty"),
    ({"text": "x", "ascii": False}, "disables both"), ({"foo": 1}, "needs one of"),
    ({"regex": "("}, "does not compile"),
])
def test_compile_string_errors(spec, msg):
    with pytest.raises(RuleError, match=msg):
        compile_string("$s", spec)


# ------------------------------------------------------------ conditions
DEF = ["$a", "$b", "$c1", "$c2"]


@pytest.mark.parametrize("cond", [
    "$a", {"all": "them"}, {"any": ["$a", "$b"]}, {"at_least": 2, "of": ["$c*"]},
    {"at_least": 1}, {"and": ["$a", {"not": "$b"}]}, {"or": ["$a"]},
    {"at": "$a", "offset": 0}, {"count": "$a", "min": 2}, {"filesize_max": 10}, {"filesize_min": 1},
])
def test_validate_ok(cond):
    R.validate_condition(cond, DEF)


@pytest.mark.parametrize("cond,msg", [
    ("$zz", "undefined"), ({"all": ["$q*"]}, "matches no string"), (42, "bad condition"),
    ({}, "bad condition"), ({"at_least": 0}, "positive"), ({"and": []}, "non-empty"),
    ({"or": "x"}, "non-empty"), ({"at": "$c*", "offset": 0}, "undefined"),
    ({"at": "$a", "offset": "0"}, "integer offset"), ({"count": "$q", "min": 1}, "undefined"),
    ({"count": "$a"}, "integer min"), ({"filesize_max": "1"}, "integer"), ({"xor": 1}, "unknown"),
    ({"not": "$nope"}, "undefined"),
])
def test_validate_errors(cond, msg):
    with pytest.raises(RuleError, match=msg):
        R.validate_condition(cond, DEF)


def test_evaluate_operators():
    m = {"$a": [0, 5], "$b": [], "$c1": [3], "$c2": []}
    ev = lambda c, size=100: R.evaluate(c, m, size)  # noqa: E731
    assert ev("$a") and not ev("$b")
    assert not ev({"all": "them"}) and ev({"all": ["$a", "$c1"]})
    assert ev({"any": "them"}) and not ev({"any": ["$b", "$c2"]})
    assert ev({"at_least": 2, "of": "them"}) and not ev({"at_least": 2, "of": ["$c*"]})
    assert ev({"at_least": 1})
    assert ev({"all": "$a"}) and not ev({"any": "$b"})        # a bare name instead of a list
    assert not R.evaluate({"at_least": 1, "of": "them"}, {}, 0)   # no strings, no quorum

    assert ev({"and": ["$a", {"not": "$b"}]}) and not ev({"and": ["$a", "$b"]})
    assert ev({"or": ["$b", "$a"]}) and not ev({"or": ["$b"]})
    assert ev({"at": "$a", "offset": 5}) and not ev({"at": "$a", "offset": 1})
    assert ev({"count": "$a", "min": 2}) and not ev({"count": "$a", "min": 3})
    assert ev({"filesize_max": 100}) and not ev({"filesize_max": 99})
    assert ev({"filesize_min": 100}) and not ev({"filesize_min": 101})


# ----------------------------------------------------------------- rules
@pytest.mark.parametrize("d,msg", [
    ("x", "must be an object"), ({"id": "a", "name": "b"}, "missing 'condition'"),
    ({"id": "a", "name": "b", "condition": "$a", "verdict": "awful"}, "unknown verdict"),
    ({"id": "a", "name": "b", "condition": "$a", "verdict": "clean"}, "cannot be clean"),
    ({"id": "a", "name": "b", "condition": "$a", "strings": ["$a"]}, "strings must be an object"),
    ({"id": "a", "name": "b", "condition": "$a", "strings": {}}, "undefined"),
])
def test_rule_from_dict_errors(d, msg):
    with pytest.raises(RuleError, match=msg):
        Rule.from_dict(d)


def test_rule_without_strings_condition_on_size():
    r = Rule.from_dict({"id": "big", "name": "Big", "condition": {"filesize_min": 3}})
    assert r.match(b"abcd")[0] and not r.match(b"ab")[0]
    assert r.match(b"ab", filesize=10)[0]


def test_rule_applies_filters():
    r = rule(filetypes=["script"], exclude_extensions=[".MD"], max_filesize=10)
    assert r.applies("x.py", "python", 5)
    assert not r.applies("x.md", "python", 5)
    assert not r.applies("x.py", "python", 11)
    assert not r.applies("x.bin", "pe", 5)
    assert rule().applies("anything", "pe", 10 ** 9)


@pytest.mark.parametrize("wanted,tag,ok", [
    (["any"], "pe", True), (["pe"], "pe", True), (["executable"], "elf", True),
    (["archive"], "zip", True), (["script"], "shell", True), (["textual"], "text", True),
    (["textual"], "script", True), (["textual"], "php", True), (["textual"], "pe", False),
    (["archive", "executable"], "pdf", False),
])
def test_type_matches(wanted, tag, ok):
    assert R._type_matches(wanted, tag) is ok


def test_match_caps_offsets(monkeypatch):
    monkeypatch.setattr(R, "MAX_MATCHES_PER_STRING", 3)
    hit, m = rule(condition={"count": "$a", "min": 3}).match(b"abc" * 10)
    assert hit and len(m["$a"]) == 3


def test_ruleset_scan_and_evidence(tmp_path):
    rs = RuleSet()
    rs.load_dicts([
        {"id": "a", "name": "A", "strings": {"$x": {"text": "evil\x01"}}, "condition": "$x", "whole_file": True},
        {"id": "b", "name": "B", "verdict": "suspicious", "strings": {"$y": {"text": "nope"}}, "condition": "$y"},
        {"id": "c", "name": "C", "condition": {"not": {"filesize_max": 2}}},
        {"id": "d", "name": "D", "filetypes": ["pe"], "condition": {"filesize_min": 0}},
    ])
    assert len(rs) == 4
    dets = rs.scan(b"xx evil\x01 yy", "f.txt", "text")
    assert [d.name for d in dets] == ["A", "C"]
    assert dets[0].whole_file and dets[0].evidence == "$x@3: evil. yy"
    assert dets[1].evidence == ""
    assert dets[0].verdict is Verdict.MALICIOUS
    assert rs.scan(b"x", "f", "text", filesize=1) == []


def test_evidence_uses_first_matching_string():
    r = rule(strings={"$miss": {"text": "zzz"}, "$hit": {"text": "abc"}}, condition={"any": "them"})
    dets = RuleSet([r]).scan(b"..abc", "f", "text")
    assert dets[0].evidence == "$hit@2: abc"


def test_ruleset_duplicate_and_file_formats(tmp_path):
    rs = RuleSet()
    rs.add(rule())
    with pytest.raises(RuleError, match="duplicate"):
        rs.add(rule())
    f1 = write(tmp_path / "list.json", json.dumps([{"id": "l", "name": "L", "condition": {"filesize_min": 0}}]))
    f2 = write(tmp_path / "obj.json", json.dumps({"rules": [{"id": "o", "name": "O", "condition": {"filesize_min": 0}}]}))
    assert RuleSet().load(f1) == 1 and RuleSet().load(f2) == 1
    assert RuleSet([rule()]).rules[0].id == "t"


def test_bundled_rules_are_valid_and_unique():
    rs = RuleSet()
    n = rs.load(DATA_DIR / "rules.json")
    assert n == len(rs) >= 15
    for r in rs.rules:
        assert r.description, r.id
        assert r.verdict in (Verdict.MALICIOUS, Verdict.SUSPICIOUS)


def test_lazy_matches_computed_once():
    lm = R.LazyMatches({"$a": re.compile(b"a")}, b"aXa")
    assert lm["$a"] is lm["$a"] and list(lm) == ["$a"] and len(lm) == 1
    assert R.evaluate({"and": ["$a", {"count": "$a", "min": 2}]}, lm, 3)
