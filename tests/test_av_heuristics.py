"""Unit tests for static heuristics and archive extraction."""

from __future__ import annotations

import bz2
import lzma
import struct
import tarfile
import zipfile

import pytest

from conftest import CODE, EXEC, READ, WRITE, build_elf, build_pe, gz, make_tar, make_zip, random_bytes
from guard_av import archive as A
from guard_av import heuristics as H


def ids(indicators) -> set[str]:
    return {i.id for i in indicators}


# --------------------------------------------------------------- filenames
@pytest.mark.parametrize("name,tag,expect", [
    ("invoice.pdf.exe", "pe", {"name.double-extension"}),
    ("photo.JPG.js", "javascript", {"name.double-extension"}),
    ("report.final.pdf", "pdf", set()),
    ("archive.tar.gz", "gzip", set()),
    ("invoice          .exe", "pe", {"name.padded-extension"}),
    ("readme          .txt", "text", set()),
    ("doc\u202efdp.exe", "pe", {"name.bidi-override"}),
    ("holiday.jpg", "pe", {"name.masquerade"}),
    ("c:\\users\\x\\setup.exe", "pe", set()),
    ("in\u200bvoice.exe", "pe", {"name.invisible-char"}),
    ("\ufeffbom.txt", "text", set()),
    ("noext", "elf", set()),
])
def test_filename_indicators(name, tag, expect):
    assert ids(H.filename_indicators(name, tag)) == expect


def test_indicator_str():
    assert str(H.Indicator("x", 5, "d")) == "x(+5)"


# ---------------------------------------------------------------------- PE
def test_parse_pe_valid_and_dll():
    info = H.parse_pe(build_pe(dll=True))
    assert info.is_dll and [s.name for s in info.sections] == [b".text", b".data"]
    assert H.parse_pe(build_pe(opt_magic=0x20B)) is not None


@pytest.mark.parametrize("data", [
    b"ELF", b"MZ", b"MZ" + b"\0" * 0x3A + struct.pack("<I", 0x40) + b"XX\0\0",
    build_pe(opt_magic=0x999), build_pe()[:0x58],
])
def test_parse_pe_rejects(data):
    assert H.parse_pe(data) is None


def test_benign_pe_has_no_indicators():
    assert H.pe_indicators(build_pe()) == []
    # anti-debug alone is common in legit software and stays tiny
    lone = H.pe_indicators(build_pe(extra=b"IsDebuggerPresent\0CheckRemoteDebuggerPresent\0"))
    assert ids(lone) == {"pe.api.anti-debug"} and sum(i.score for i in lone) < 70


def test_malformed_pe():
    assert ids(H.pe_indicators(b"MZ" + b"\0" * 100)) == {"pe.malformed"}


def test_packed_injector_pe():
    pe = build_pe(
        sections=[(b"UPX0", EXEC | WRITE | READ, random_bytes(4096)), (b".rsrc", READ, b"\0" * 64)],
        entry=0x9000,
        extra=b"VirtualAllocEx\0WriteProcessMemory\0CreateRemoteThread\0"
              b"NtUnmapViewOfSection\0SetThreadContext\0ResumeThread\0"
              b"SetWindowsHookExA\0GetAsyncKeyState\0")
    got = ids(H.pe_indicators(pe))
    assert got == {"pe.packer", "pe.section.high-entropy", "pe.section.wx", "pe.entry.outside",
                   "pe.api.process-injection", "pe.api.process-hollowing", "pe.api.keylogger"}


def test_entry_in_non_code_section():
    pe = build_pe(sections=[(b".text", EXEC | CODE | READ, b"\x90" * 64), (b".data", READ | WRITE, b"\0" * 64)],
                  entry=0x2000)
    assert ids(H.pe_indicators(pe)) == {"pe.entry.non-code"}


def test_resource_only_dll_without_entry_point():
    assert H.pe_indicators(build_pe(entry=0, dll=True)) == []
    assert H.pe_indicators(build_pe(sections=[], entry=0x1000)) == []


def test_small_high_entropy_section_ignored():
    pe = build_pe(sections=[(b".text", EXEC | CODE, random_bytes(512))])
    assert ids(H.pe_indicators(pe)) == set()


# ------------------------------------------------------------- ELF / Mach-O
def test_elf_indicators():
    assert H.elf_indicators(build_elf(b"\0" * 64)) == []
    got = ids(H.elf_indicators(build_elf(b"UPX!" + random_bytes(8192) + b"/etc/ld.so.preload")))
    assert got == {"elf.packer", "elf.high-entropy", "elf.ld-preload"}
    tail_packed = build_elf(b"\0" * 9000 + b"UPX!")
    assert ids(H.elf_indicators(tail_packed)) == {"elf.packer"}


def test_macho_indicators():
    assert H.macho_indicators(b"\xcf\xfa\xed\xfe" + b"\0" * 5000) == []
    assert ids(H.macho_indicators(b"\xcf\xfa\xed\xfe" + random_bytes(5000))) == {"macho.high-entropy"}


# ----------------------------------------------------------------- scripts
BLOB = b"QUJD" * 600


SCRIPT_CASES = [
    (b"eval(atob('" + BLOB + b"'))", {"script.exec-encoded-blob"}),
    (b"const img = 'data:image/png;base64," + BLOB + b"';", set()),     # data URI without exec: benign
    (b" ".join(b"_0x%04x" % i for i in range(60)), {"script.js-obfuscator"}),
    (b" ".join(b"_0x%04x" % i for i in range(10)), set()),
    (b"eval(String.fromCharCode(" + b",".join(b"%d" % (65 + i % 26) for i in range(40)) + b"))",
     {"script.charcode-exec"}),
    (b"String.fromCharCode(" + b",".join(b"65" for _ in range(40)) + b")", set()),
    (b"\\x41" * 400, {"script.hex-escaped"}),
    (b"\\x41" * 400 + b"A" * 10000, set()),
    (b"powershell -enc " + b"A" * 120, {"ps.encoded-command"}),
    (b"powershell -w hidden -EncodedCommand " + b"A" * 120, {"ps.encoded-command", "ps.hidden-window"}),
    (b"powershell -w hidden -c Get-Date", set()),
    (b"I|~|EX ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64|~|String($p)))", {"ps.decode-exec"}),
    (b"[Convert]::FromBase64String($p)", set()),
    (b"x = 'Amsi' + 'ScanBuffer'; Amsi|~|ScanBuffer", {"ps.amsi-bypass"}),
    (b"print('hello world')", set()),
]


# opaque ids: pytest would otherwise write these payloads into .pytest_cache
@pytest.mark.parametrize("data,expect", SCRIPT_CASES, ids=[f"case{i}" for i in range(len(SCRIPT_CASES))])
def test_script_indicators(data, expect):
    data = data.replace(b"|~|", b"")    # split markers keep live strings out of this file
    assert ids(H.script_indicators(data)) == expect


@pytest.mark.parametrize("tag,fn", [("pe", "pe_indicators"), ("elf", "elf_indicators"),
                                    ("macho", "macho_indicators"), ("macho-fat", "macho_indicators"),
                                    ("python", "script_indicators"), ("text", "script_indicators"),
                                    ("script", "script_indicators")])
def test_analyze_dispatch(monkeypatch, tag, fn):
    called = []
    monkeypatch.setattr(H, fn, lambda data: called.append(fn) or [H.Indicator("x", 1, "d")])
    assert ids(H.analyze(b"", "f", tag)) == {"x"} and called == [fn]


def test_analyze_other_types_only_check_names():
    assert H.analyze(b"%PDF", "a.pdf", "pdf") == []


# ----------------------------------------------------------------- archive
LIM = A.ArchiveLimits(max_members=3, max_member_size=1000, max_total_size=1500, max_ratio=50)


def test_zip_members_and_dirs():
    import io
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("d/", b"")
        zf.writestr("d/a.txt", b"hello")
    ex = A.extract(buf.getvalue(), "zip", "x.zip")
    assert [(m.name, m.data) for m in ex.members] == [("d/a.txt", b"hello")]
    assert not ex.notes and not ex.bomb


def test_zip_limits():
    ex = A.extract_zip(make_zip({f"f{i}": b"x" * 600 for i in range(5)}), LIM)
    assert len(ex.members) == 3
    assert any("scanned first 3" in n for n in ex.notes)
    assert any("truncated" in n for n in ex.notes)          # third member gets only 300 bytes
    assert sum(len(m.data) for m in ex.members) == 1500


def test_zip_budget_exhausted():
    lim = A.ArchiveLimits(max_members=10, max_member_size=1000, max_total_size=1000)
    ex = A.extract_zip(make_zip({"a": b"x" * 1000, "b": b"y"}), lim)
    assert [m.name for m in ex.members] == ["a"] and "total size budget exhausted" in ex.notes


def test_zip_bomb_and_encrypted():
    data = make_zip({"bomb.bin": b"\0" * (2 * 1024 * 1024), "secret.txt": b"s", "ok.txt": b"fine"},
                    encrypt_flag={"secret.txt"})
    ex = A.extract_zip(data, A.ArchiveLimits())
    assert ex.bomb and ex.encrypted
    assert [m.name for m in ex.members] == ["ok.txt"]


def test_zip_bad_and_unreadable():
    assert A.extract(b"PK\x03\x04garbage", "zip", "x").notes[0].startswith("bad zip")
    data = bytearray(make_zip({"a.txt": b"hello world" * 50}))
    i = data.find(b"PK\x03\x04") + 30 + len("a.txt")
    data[i:i + 8] = b"\xff" * 8                              # corrupt the deflate stream
    ex = A.extract_zip(bytes(data), A.ArchiveLimits())
    assert ex.members == [] and ex.notes[0].startswith("cannot read a.txt")


def test_tar_variants():
    files = {"a.sh": b"echo hi", "b.txt": b"x" * 600}
    for mode, tag in (("w", "tar"), ("w:gz", "gzip"), ("w:bz2", "bzip2"), ("w:xz", "xz")):
        ex = A.extract(make_tar(files, mode), tag, "t")
        assert {m.name for m in ex.members} == {"a.sh", "b.txt"}, mode


def test_tar_limits():
    ex = A.extract_tar(make_tar({f"f{i}": b"x" * 600 for i in range(5)}), LIM)
    assert len(ex.members) == 3 and any("more than 3" in n for n in ex.notes)
    assert any("truncated" in n for n in ex.notes)
    lim = A.ArchiveLimits(max_members=10, max_member_size=1000, max_total_size=1000)
    ex = A.extract_tar(make_tar({"a": b"x" * 1000, "b": b"y"}), lim)
    assert [m.name for m in ex.members] == ["a"] and "total size budget exhausted" in ex.notes


def test_tar_errors():
    assert A.extract(b"\0" * 10, "tar", "t").notes[0].startswith("bad tar")
    good = make_tar({"a": b"x" * 2000})
    ex = A.extract_tar(good[:1024], A.ArchiveLimits())       # header ok, body truncated
    assert any("tar read error" in n for n in ex.notes)


def test_compressed_single_streams():
    ex = A.extract(gz(b"payload"), "gzip", "evil.js.gz")
    assert [(m.name, m.data) for m in ex.members] == [("evil.js", b"payload")]
    ex = A.extract(bz2.compress(b"p"), "bzip2", "a.bz2")
    assert ex.members[0].name == "a"
    ex = A.extract(lzma.compress(b"p"), "xz", "noext")
    assert ex.members[0].name == "noext.out"
    ex = A.extract(gz(b"p"), "gzip", ".gz")
    assert ex.members[0].name == "payload"


def test_compressed_stream_limits_and_errors():
    lim = A.ArchiveLimits(max_member_size=1000, max_ratio=5)
    ex = A.extract(gz(b"\0" * 100000), "gzip", "b.gz", lim)
    assert ex.bomb and len(ex.members[0].data) == 1000
    ex = A.extract(gz(random_bytes(3000)), "gzip", "r.gz", lim)
    assert not ex.bomb and any("truncated" in n for n in ex.notes)
    ex = A.extract(b"\x1f\x8b\x08garbage", "gzip", "bad.gz")
    assert ex.members == [] and any(n.startswith("bad stream") for n in ex.notes)


def test_unsupported_archive():
    ex = A.extract(b"Rar!\x1a\x07", "rar", "x.rar")
    assert ex.members == [] and "not unpacked" in ex.notes[0]


def test_tarfile_symlink_members_are_skipped():
    import io
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        link = tarfile.TarInfo("link")
        link.type = tarfile.SYMTYPE
        link.linkname = "/etc/passwd"
        tf.addfile(link)
    assert A.extract_tar(buf.getvalue(), A.ArchiveLimits()).members == []
