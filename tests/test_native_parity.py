"""Python <-> Rust backend parity, the backend loader, and the fallback path.

The Rust extension (core/, `guard_core`) must reproduce the Python engine
exactly: same indicators, same rule hits, same evidence. These tests feed both
implementations the same real-world corpus and compare the results.
"""

from __future__ import annotations

import builtins
import json
import sysconfig
from pathlib import Path

import pytest

import samples
from conftest import (CODE, EXEC, NATIVE_MODULE, READ, WRITE, build_elf, build_pe, make_zip,
                      random_bytes)
from guard_av import _native
from guard_av import heuristics as H
from guard_av.engine import DATA_DIR, ScanEngine
from guard_av.hashing import shannon_entropy
from guard_av.model import Verdict
from guard_av.rules import RuleSet

needs_rust = pytest.mark.skipif(NATIVE_MODULE is None, reason="guard_core extension not built")


def corpus() -> list[tuple[str, bytes]]:
    """Malicious + benign samples, synthetic binaries, and real stdlib files."""
    items = [(n, d) for n, (_t, d) in samples.decoded(samples.MALICIOUS).items()]
    items += [(n, d) for n, (_t, d) in samples.decoded(samples.SUSPICIOUS).items()]
    items += [("eicar.com", samples.eicar()), ("eicar.txt", samples.eicar() + b"\r\n")]
    injector = build_pe(sections=[(b"UPX0", EXEC | WRITE | READ, random_bytes(4096)),
                                  (b".r'\x01\xad", READ, b"\0" * 64)], entry=0x9000,
                        extra=b"VirtualAllocEx\0WriteProcessMemory\0CreateRemoteThread\0")
    items += [
        ("ok.exe", build_pe()), ("inj.exe", injector), ("bad.exe", b"MZ" + b"\0" * 100),
        ("dll.dll", build_pe(sections=[(b".text", EXEC | CODE, b"\x90" * 64)], entry=0x5000, dll=True)),
        ("nonc.exe", build_pe(sections=[(b".data", READ, b"\0" * 64)], entry=0x1000)),
        ("a.so", build_elf(b"UPX!" + random_bytes(8192) + b"/etc/ld.so.preload")),
        ("m.dylib", b"\xcf\xfa\xed\xfe" + random_bytes(5000)),
        ("obf.js", b"_0x1a2b " * 60 + b"eval(String.fromCharCode(" + b",".join(b"65" for _ in range(40)) + b"))"),
        ("hex.js", b"\\x41" * 400), ("blob.js", b"eval(x);" + b"QUJD" * 600),
        ("ps.ps1", b"powershell -w hidden -enc " + b"A" * 120 + b" IEX FromBase64String"),
        ("z.zip", make_zip({"a": b"b"})), ("empty", b""),
    ]
    stdlib = Path(sysconfig.get_paths()["stdlib"])
    for i, p in enumerate(sorted(stdlib.rglob("*.py"))):
        if i >= 400:
            break
        items.append((p.name, p.read_bytes()[:200_000]))
    return items


def run_both(fn, monkeypatch):
    monkeypatch.setattr(_native, "NATIVE", None)
    py = fn()
    monkeypatch.setattr(_native, "NATIVE", NATIVE_MODULE)
    rs = fn()
    return py, rs


@needs_rust
def test_heuristics_parity(monkeypatch):
    for name, data in corpus():
        for f in (H.pe_indicators, H.elf_indicators, H.macho_indicators, H.script_indicators):
            py, rs = run_both(lambda: f(data), monkeypatch)
            assert py == rs, (name, f.__name__)


@needs_rust
def test_entropy_parity(monkeypatch):
    for name, data in corpus():
        py, rs = run_both(lambda: shannon_entropy(data), monkeypatch)
        assert py == pytest.approx(rs, abs=1e-9), name


@needs_rust
def test_rule_scan_parity(monkeypatch):
    rs_ = RuleSet()
    rs_.load(DATA_DIR / "rules.json")
    for name, data in corpus():
        for tag in ("text", "php", "powershell", "python", "shell", "pe", "javascript"):
            py, rs = run_both(lambda: rs_.scan(data, name, tag), monkeypatch)
            assert py == rs, (name, tag)


@needs_rust
def test_full_engine_parity(monkeypatch):
    for name, data in corpus():
        py, rs = run_both(lambda: ScanEngine.default().scan_bytes(data, name).to_dict(), monkeypatch)
        assert py == rs, name


@needs_rust
def test_native_compile_error_falls_back_to_python(monkeypatch):
    monkeypatch.setattr(_native, "NATIVE", NATIVE_MODULE)
    rs = RuleSet()
    rs.load_dicts([{"id": "lb", "name": "LookBehind", "condition": "$a",
                    "strings": {"$a": {"regex": "(?<=x)evil"}}}])
    dets = rs.scan(b"xevil", "f", "text")
    assert [d.name for d in dets] == ["LookBehind"]                  # matched by Python
    assert "lb" in rs.native_error or "look" in rs.native_error.lower()
    assert rs.scan(b"evil", "f", "text") == []                       # cached decision reused


@needs_rust
def test_compiled_rules_are_cached_and_invalidated(monkeypatch):
    monkeypatch.setattr(_native, "NATIVE", NATIVE_MODULE)
    rs = RuleSet()
    rs.load_dicts([{"id": "a", "name": "A", "strings": {"$a": {"text": "aaa"}}, "condition": "$a"}])
    rs.scan(b"aaa", "f", "text")
    first = rs._native[1]
    rs.scan(b"aaa", "f", "text")
    assert rs._native[1] is first and len(first) == 1
    rs.load_dicts([{"id": "b", "name": "B", "strings": {"$b": {"text": "bbb"}}, "condition": "$b"}])
    assert [d.name for d in rs.scan(b"aaa bbb", "f", "text")] == ["A", "B"]
    assert rs._native[1] is not first


def test_no_applicable_rules_skips_compilation(monkeypatch):
    rs = RuleSet()
    rs.load_dicts([{"id": "p", "name": "P", "filetypes": ["pe"], "condition": {"filesize_min": 0}}])
    assert rs.scan(b"x", "f", "text") == [] and rs._native is None


@needs_rust
def test_native_module_surface():
    assert NATIVE_MODULE.__version__
    with pytest.raises(ValueError):
        NATIVE_MODULE.RuleSet("{}")
    hits = NATIVE_MODULE.RuleSet(json.dumps([{"id": "e", "condition": {"filesize_min": 0}}])).scan(
        b"x", [0, 7], 1, 64)                                         # out-of-range index ignored
    assert hits == [(0, "")]


# ------------------------------------------------------------------- loader
def test_loader_env_override(monkeypatch):
    monkeypatch.setenv("GUARD_AV_BACKEND", "python")
    assert _native.load() is None


def test_loader_without_extension(monkeypatch):
    monkeypatch.delenv("GUARD_AV_BACKEND", raising=False)
    real = builtins.__import__

    def deny(name, *a, **k):
        if name == "guard_core":
            raise ImportError(name)
        return real(name, *a, **k)
    monkeypatch.setattr(builtins, "__import__", deny)
    assert _native.load() is None


@needs_rust
def test_loader_with_extension(monkeypatch):
    monkeypatch.delenv("GUARD_AV_BACKEND", raising=False)
    assert _native.load() is NATIVE_MODULE


def test_backend_name(monkeypatch, av_backend):
    assert _native.backend() == av_backend
    monkeypatch.setattr(_native, "NATIVE", None)
    assert _native.backend() == "python"


def test_engine_verdicts_do_not_depend_on_backend(engine):
    assert engine.scan_bytes(samples.eicar(), "e.com").verdict is Verdict.MALICIOUS
