"""
rules.py - a small, dependency-free YARA-style rule engine.

A rule (JSON) names some STRINGS and a boolean CONDITION over them:

    {
      "id": "webshell.php.superglobal-exec",
      "name": "Webshell.PHP.SuperglobalExec",
      "verdict": "malicious",            # or "suspicious"
      "description": "...",
      "filetypes": ["php", "text"],      # optional; tags or groups (see _type_matches)
      "exclude_extensions": [".md"],      # optional; documentation is not malware
      "max_filesize": 1048576,            # optional
      "whole_file": false,                # optional; true => whole file is the threat
      "strings": {
        "$a": {"text": "eval(", "nocase": true, "wide": false},
        "$b": {"hex": "4D 5A ?? [2-4] (90|CC)"},
        "$c": {"regex": "system\\s*\\(", "nocase": true}
      },
      "condition": {"and": ["$a", {"any": ["$b", "$c"]}]}
    }

Condition forms:
    "$name"                              string matched at least once
    {"all": [names] | "them"}            every listed string matched
    {"any": [names] | "them"}            at least one matched
    {"at_least": N, "of": [names]|"them"}
    {"and": [cond, ...]} / {"or": [...]} / {"not": cond}
    {"at": "$name", "offset": N}         a match starts exactly at offset N
    {"count": "$name", "min": N}         at least N matches
    {"filesize_max": N} / {"filesize_min": N}
Name lists accept a trailing '*' wildcard ("$cmd*") like YARA.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path, PurePath

from . import filetype as ft
from .model import Detection, Verdict

MAX_MATCHES_PER_STRING = 64
_HEXDIGITS = set("0123456789abcdefABCDEF")


class RuleError(ValueError):
    """A rule failed validation."""


# --------------------------------------------------------------------- strings
def compile_hex(spec: str) -> bytes:
    """Translate a YARA hex string into a bytes regex source."""
    s = "".join(spec.split())
    out: list[bytes] = []
    i, depth = 0, 0
    while i < len(s):
        c = s[i]
        if c == "(":
            out.append(b"(?:")
            depth += 1
            i += 1
        elif c == "|":
            if depth == 0:
                raise RuleError(f"'|' outside a group in hex string {spec!r}")
            out.append(b"|")
            i += 1
        elif c == ")":
            if depth == 0:
                raise RuleError(f"unbalanced ')' in hex string {spec!r}")
            out.append(b")")
            depth -= 1
            i += 1
        elif c == "[":
            j = s.find("]", i)
            if j < 0:
                raise RuleError(f"unterminated jump in hex string {spec!r}")
            m = re.fullmatch(r"(\d+)(?:-(\d+))?", s[i + 1:j])
            if not m:
                raise RuleError(f"bad jump {s[i:j + 1]!r} in hex string {spec!r}")
            lo, hi = m.group(1), m.group(2) if m.group(2) is not None else m.group(1)
            if int(hi) < int(lo):
                raise RuleError(f"inverted jump {s[i:j + 1]!r} in hex string {spec!r}")
            out.append(b".{%d,%d}" % (int(lo), int(hi)))
            i = j + 1
        elif s[i:i + 2] == "??":
            out.append(b".")
            i += 2
        elif c in _HEXDIGITS and i + 1 < len(s) and s[i + 1] in _HEXDIGITS:
            out.append(re.escape(bytes.fromhex(s[i:i + 2])))
            i += 2
        else:
            raise RuleError(f"invalid token at {s[i:i + 4]!r} in hex string {spec!r}")
    if depth:
        raise RuleError(f"unbalanced '(' in hex string {spec!r}")
    if not out:
        raise RuleError("empty hex string")
    return b"".join(out)


def compile_string(name: str, spec: dict) -> re.Pattern:
    if not isinstance(spec, dict):
        raise RuleError(f"string {name} must be an object")
    flags = re.DOTALL
    if spec.get("nocase"):
        flags |= re.IGNORECASE
    if "hex" in spec:
        src = compile_hex(str(spec["hex"]))
    elif "text" in spec:
        text = str(spec["text"])
        if not text:
            raise RuleError(f"string {name} is empty")
        forms = []
        if spec.get("ascii", True):
            forms.append(re.escape(text.encode("utf-8")))
        if spec.get("wide"):
            forms.append(re.escape(text.encode("utf-16-le")))
        if not forms:
            raise RuleError(f"string {name} disables both ascii and wide")
        src = b"|".join(forms)
    elif "regex" in spec:
        src = str(spec["regex"]).encode("utf-8")
        if spec.get("multiline"):
            flags |= re.MULTILINE
        if not spec.get("dotall", False):
            flags &= ~re.DOTALL
    else:
        raise RuleError(f"string {name} needs one of text / hex / regex")
    try:
        return re.compile(src, flags)
    except re.error as exc:
        raise RuleError(f"string {name} does not compile: {exc}") from None


# ------------------------------------------------------------------ conditions
def _expand(names, defined: list[str]) -> list[str]:
    if names == "them":
        return list(defined)
    if isinstance(names, str):
        names = [names]
    out: list[str] = []
    for n in names:
        if isinstance(n, str) and n.endswith("*"):
            hit = [d for d in defined if d.startswith(n[:-1])]
            if not hit:
                raise RuleError(f"wildcard {n} matches no string")
            out.extend(hit)
        elif n in defined:
            out.append(n)
        else:
            raise RuleError(f"condition references undefined string {n!r}")
    return out


def validate_condition(cond, defined: list[str]) -> None:
    """Raise RuleError if the condition is malformed or references unknown strings."""
    if isinstance(cond, str):
        _expand([cond], defined)
        return
    if not isinstance(cond, dict) or len(cond) == 0:
        raise RuleError(f"bad condition: {cond!r}")
    if "all" in cond:
        _expand(cond["all"], defined)
    elif "any" in cond:
        _expand(cond["any"], defined)
    elif "at_least" in cond:
        if not isinstance(cond["at_least"], int) or cond["at_least"] < 1:
            raise RuleError("at_least must be a positive integer")
        _expand(cond.get("of", "them"), defined)
    elif "and" in cond or "or" in cond:
        parts = cond.get("and", cond.get("or"))
        if not isinstance(parts, list) or not parts:
            raise RuleError("and/or need a non-empty list")
        for p in parts:
            validate_condition(p, defined)
    elif "not" in cond:
        validate_condition(cond["not"], defined)
    elif "at" in cond:
        if cond["at"] not in defined:
            raise RuleError(f"at references undefined string {cond['at']!r}")
        if not isinstance(cond.get("offset"), int):
            raise RuleError("at needs an integer offset")
    elif "count" in cond:
        if cond["count"] not in defined:
            raise RuleError(f"count references undefined string {cond['count']!r}")
        if not isinstance(cond.get("min"), int):
            raise RuleError("count needs an integer min")
    elif "filesize_max" in cond or "filesize_min" in cond:
        v = cond.get("filesize_max", cond.get("filesize_min"))
        if not isinstance(v, int):
            raise RuleError("filesize bound must be an integer")
    else:
        raise RuleError(f"unknown condition operator in {cond!r}")


class LazyMatches(Mapping):
    """String-name -> match offsets, computed on first access.

    Conditions short-circuit, so a rule like {"and": ["$rare", "$costly"]} never
    runs the costly regex on data where the cheap one already failed.
    """

    def __init__(self, strings: dict[str, re.Pattern], data: bytes) -> None:
        self._strings = strings
        self._data = data
        self.computed: dict[str, list[int]] = {}

    def __getitem__(self, name: str) -> list[int]:
        if name not in self.computed:
            offs = []
            for m in self._strings[name].finditer(self._data):
                offs.append(m.start())
                if len(offs) >= MAX_MATCHES_PER_STRING:
                    break
            self.computed[name] = offs
        return self.computed[name]

    def __iter__(self):
        return iter(self._strings)

    def __len__(self) -> int:
        return len(self._strings)


def evaluate(cond, matches: Mapping[str, list[int]], filesize: int) -> bool:
    names = list(matches)
    if isinstance(cond, str):
        return all(matches[n] for n in _expand([cond], names))
    if "all" in cond:
        return all(matches[n] for n in _expand(cond["all"], names))
    if "any" in cond:
        return any(matches[n] for n in _expand(cond["any"], names))
    if "at_least" in cond:
        need, pool = cond["at_least"], _expand(cond.get("of", "them"), names)
        hits = 0
        for i, n in enumerate(pool):
            if matches[n]:
                hits += 1
                if hits >= need:
                    return True
            if hits + (len(pool) - i - 1) < need:
                return False      # can no longer reach the quorum
        return False
    if "and" in cond:
        return all(evaluate(c, matches, filesize) for c in cond["and"])
    if "or" in cond:
        return any(evaluate(c, matches, filesize) for c in cond["or"])
    if "not" in cond:
        return not evaluate(cond["not"], matches, filesize)
    if "at" in cond:
        return cond["offset"] in matches[cond["at"]]
    if "count" in cond:
        return len(matches[cond["count"]]) >= cond["min"]
    if "filesize_max" in cond:
        return filesize <= cond["filesize_max"]
    return filesize >= cond["filesize_min"]


# ----------------------------------------------------------------------- rules
def _type_matches(wanted: list[str], tag: str) -> bool:
    for w in wanted:
        if w == "any" or w == tag:
            return True
        if w == "executable" and ft.is_executable(tag):
            return True
        if w == "archive" and ft.is_archive(tag):
            return True
        if w == "script" and ft.is_script(tag):
            return True
        if w == "textual" and (ft.is_script(tag) or tag in ("text", "script")):
            return True
    return False


@dataclass
class Rule:
    id: str
    name: str
    verdict: Verdict
    condition: object
    strings: dict[str, re.Pattern]
    description: str = ""
    category: str = ""
    filetypes: list[str] = field(default_factory=lambda: ["any"])
    exclude_extensions: frozenset = frozenset()
    max_filesize: int = 0
    whole_file: bool = False

    @classmethod
    def from_dict(cls, d: dict) -> "Rule":
        if not isinstance(d, dict):
            raise RuleError("rule must be an object")
        for key in ("id", "name", "condition"):
            if key not in d:
                raise RuleError(f"rule {d.get('id', '?')} missing {key!r}")
        try:
            verdict = Verdict.parse(d.get("verdict", "malicious"))
        except ValueError as exc:
            raise RuleError(f"rule {d['id']}: {exc}") from None
        if verdict is Verdict.CLEAN:
            raise RuleError(f"rule {d['id']}: verdict cannot be clean")
        raw_strings = d.get("strings") or {}
        if not isinstance(raw_strings, dict):
            raise RuleError(f"rule {d['id']}: strings must be an object")
        strings = {n: compile_string(n, s) for n, s in raw_strings.items()}
        validate_condition(d["condition"], list(strings))
        return cls(
            id=str(d["id"]), name=str(d["name"]), verdict=verdict,
            condition=d["condition"], strings=strings,
            description=str(d.get("description", "")), category=str(d.get("category", "")),
            filetypes=list(d.get("filetypes") or ["any"]),
            exclude_extensions=frozenset(e.lower() for e in d.get("exclude_extensions", [])),
            max_filesize=int(d.get("max_filesize", 0)),
            whole_file=bool(d.get("whole_file", False)),
        )

    def applies(self, name: str, tag: str, size: int) -> bool:
        if self.max_filesize and size > self.max_filesize:
            return False
        if self.exclude_extensions and PurePath(name).suffix.lower() in self.exclude_extensions:
            return False
        return _type_matches(self.filetypes, tag)

    def match(self, data: bytes, filesize: int | None = None) -> tuple[bool, dict[str, list[int]]]:
        """(hit, offsets of every string the condition needed to look at)."""
        size = len(data) if filesize is None else filesize
        matches = LazyMatches(self.strings, data)
        return evaluate(self.condition, matches, size), matches.computed


def _evidence(data: bytes, matches: dict[str, list[int]], width: int = 48) -> str:
    for n, offs in matches.items():
        if offs:
            o = offs[0]
            chunk = data[o:o + width]
            text = chunk.decode("latin-1")
            printable = "".join(ch if 32 <= ord(ch) < 127 else "." for ch in text)
            return f"{n}@{o}: {printable}"
    return ""


class RuleSet:
    def __init__(self, rules: list[Rule] | None = None) -> None:
        self.rules: list[Rule] = list(rules or [])

    def __len__(self) -> int:
        return len(self.rules)

    def add(self, rule: Rule) -> None:
        if any(r.id == rule.id for r in self.rules):
            raise RuleError(f"duplicate rule id {rule.id}")
        self.rules.append(rule)

    def load_dicts(self, items: list[dict]) -> int:
        for d in items:
            self.add(Rule.from_dict(d))
        return len(items)

    def load(self, path: str | Path) -> int:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        items = data.get("rules", []) if isinstance(data, dict) else data
        return self.load_dicts(items)

    def scan(self, data: bytes, name: str, tag: str, filesize: int | None = None) -> list[Detection]:
        size = len(data) if filesize is None else filesize
        out: list[Detection] = []
        for r in self.rules:
            if not r.applies(name, tag, size):
                continue
            hit, matches = r.match(data, size)
            if hit:
                out.append(Detection(
                    engine="rule", name=r.name, verdict=r.verdict, rule_id=r.id,
                    description=r.description, evidence=_evidence(data, matches),
                    whole_file=r.whole_file,
                ))
        return out
