"""
heuristics.py - static, behaviour-free analysis that scores how malware-like a
file looks when no signature matches.

Every check yields an Indicator with a weight. Weights are deliberately
conservative: single weak traits (a packer, an anti-debug API, an encoded
PowerShell switch) are common in legitimate software and stay well below the
SUSPICIOUS threshold on their own. The engine only escalates when several
independent indicators stack up (see engine.EngineConfig).
"""

from __future__ import annotations

import re
import struct
import unicodedata
from dataclasses import dataclass
from pathlib import PurePath

from . import filetype as ft
from .hashing import shannon_entropy


@dataclass(frozen=True)
class Indicator:
    id: str
    score: int
    description: str

    def __str__(self) -> str:
        return f"{self.id}(+{self.score})"


# Strong indicators are the ones allowed to count towards a MALICIOUS heuristic
# verdict; anything lighter only ever contributes to SUSPICIOUS.
STRONG = 30

# ------------------------------------------------------------------ filenames
_EXEC_EXTS = frozenset({
    ".exe", ".scr", ".pif", ".com", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse",
    ".wsf", ".wsh", ".hta", ".ps1", ".msi", ".jar", ".lnk", ".cpl",
})
_BIDI_OVERRIDES = {"‮", "‭", "⁦", "⁧", "⁨"}


def filename_indicators(name: str, tag: str) -> list[Indicator]:
    out: list[Indicator] = []
    base = PurePath(name.replace("\\", "/")).name
    if any(ch in _BIDI_OVERRIDES for ch in base):
        out.append(Indicator("name.bidi-override", 60,
                             "filename uses a Unicode bidi override to fake its extension"))
    suffixes = [s.lower() for s in PurePath(base).suffixes]
    if len(suffixes) >= 2 and suffixes[-1] in _EXEC_EXTS and suffixes[-2] in ft.DOCUMENT_EXTS:
        out.append(Indicator("name.double-extension", 40,
                             f"executable hiding behind a document extension ({''.join(suffixes[-2:])})"))
    elif re.search(r"\s{5,}\.[A-Za-z0-9]{2,4}$", base) and suffixes and suffixes[-1] in _EXEC_EXTS:
        out.append(Indicator("name.padded-extension", 40,
                             "whitespace padding pushes the real extension out of view"))
    ext = suffixes[-1] if suffixes else ""
    if ft.is_executable(tag) and ext in ft.DOCUMENT_EXTS:
        out.append(Indicator("name.masquerade", 50,
                             f"{tag.upper()} executable disguised with a {ext} extension"))
    for ch in base:
        if unicodedata.category(ch) == "Cf" and ch not in _BIDI_OVERRIDES and ch != "﻿":
            out.append(Indicator("name.invisible-char", 15, "filename contains invisible format characters"))
            break
    return out


# ------------------------------------------------------------------------ PE
_PACKER_SECTIONS = {
    b"UPX0": "UPX", b"UPX1": "UPX", b"UPX2": "UPX", b".aspack": "ASPack", b".adata": "ASPack",
    b".petite": "Petite", b".MPRESS1": "MPRESS", b".MPRESS2": "MPRESS", b".themida": "Themida",
    b".vmp0": "VMProtect", b".vmp1": "VMProtect", b".enigma1": "Enigma", b"nsp0": "NsPack",
}
_IMAGE_SCN_MEM_EXECUTE = 0x20000000
_IMAGE_SCN_MEM_WRITE = 0x80000000
_IMAGE_SCN_CNT_CODE = 0x00000020

_API_GROUPS = [
    ("pe.api.process-injection", 45, "classic remote-process injection API set",
     [b"VirtualAllocEx", b"WriteProcessMemory", b"CreateRemoteThread"]),
    ("pe.api.process-hollowing", 45, "process-hollowing API set",
     [b"NtUnmapViewOfSection", b"SetThreadContext", b"ResumeThread"]),
    ("pe.api.keylogger", 30, "global keyboard hook + key-state polling",
     [b"SetWindowsHookEx", b"GetAsyncKeyState"]),
    ("pe.api.anti-debug", 10, "debugger-detection APIs",
     [b"IsDebuggerPresent", b"CheckRemoteDebuggerPresent"]),
]


@dataclass
class Section:
    name: bytes
    vaddr: int
    vsize: int
    raw_ptr: int
    raw_size: int
    flags: int


@dataclass
class PEInfo:
    machine: int
    timestamp: int
    entry_point: int
    sections: list[Section]
    is_dll: bool


def parse_pe(data: bytes) -> PEInfo | None:
    """Parse just enough of a PE to reason about it; None if malformed."""
    try:
        if data[:2] != b"MZ":
            return None
        (e_lfanew,) = struct.unpack_from("<I", data, 0x3C)
        if data[e_lfanew:e_lfanew + 4] != b"PE\0\0":
            return None
        coff = e_lfanew + 4
        machine, nsects, timestamp, _, _, opt_size, chars = struct.unpack_from("<HHIIIHH", data, coff)
        opt = coff + 20
        (magic,) = struct.unpack_from("<H", data, opt)
        if magic not in (0x10B, 0x20B):
            return None
        (entry,) = struct.unpack_from("<I", data, opt + 16)
        sec_off = opt + opt_size
        sections = []
        for i in range(min(nsects, 96)):
            o = sec_off + 40 * i
            name = data[o:o + 8].rstrip(b"\0")
            vsize, vaddr, raw_size, raw_ptr = struct.unpack_from("<IIII", data, o + 8)
            (flags,) = struct.unpack_from("<I", data, o + 36)
            sections.append(Section(name, vaddr, vsize, raw_ptr, raw_size, flags))
    except struct.error:
        return None
    return PEInfo(machine, timestamp, entry, sections, bool(chars & 0x2000))


def pe_indicators(data: bytes) -> list[Indicator]:
    info = parse_pe(data)
    if info is None:
        return [Indicator("pe.malformed", 15, "MZ header without a valid PE structure")]
    out: list[Indicator] = []
    packers = sorted({_PACKER_SECTIONS[s.name] for s in info.sections if s.name in _PACKER_SECTIONS})
    if packers:
        out.append(Indicator("pe.packer", 25, f"packed with {', '.join(packers)}"))
    for s in info.sections:
        if not (s.flags & _IMAGE_SCN_MEM_EXECUTE):
            continue
        body = data[s.raw_ptr:s.raw_ptr + s.raw_size]
        if len(body) >= 1024 and shannon_entropy(body) > 7.2:
            out.append(Indicator("pe.section.high-entropy", 35,
                                 f"executable section {s.name.decode('latin-1')!r} is encrypted/compressed"))
            break
    if any(s.flags & _IMAGE_SCN_MEM_EXECUTE and s.flags & _IMAGE_SCN_MEM_WRITE for s in info.sections):
        out.append(Indicator("pe.section.wx", 20, "section is both writable and executable"))
    if info.sections and info.entry_point:
        inside = [s for s in info.sections if s.vaddr <= info.entry_point < s.vaddr + max(s.vsize, s.raw_size)]
        if not inside:
            out.append(Indicator("pe.entry.outside", 30, "entry point lies outside every section"))
        elif not (inside[0].flags & (_IMAGE_SCN_CNT_CODE | _IMAGE_SCN_MEM_EXECUTE)):
            out.append(Indicator("pe.entry.non-code", 30, "entry point is in a non-executable section"))
    for ind_id, score, desc, apis in _API_GROUPS:
        if all(a in data for a in apis):
            out.append(Indicator(ind_id, score, desc))
    return out


# ----------------------------------------------------------------------- ELF
def elf_indicators(data: bytes) -> list[Indicator]:
    out: list[Indicator] = []
    if b"UPX!" in data[:4096] or b"UPX!" in data[-4096:]:
        out.append(Indicator("elf.packer", 25, "packed with UPX"))
    if len(data) >= 4096 and shannon_entropy(data) > 7.4:
        out.append(Indicator("elf.high-entropy", 30, "body is encrypted/compressed"))
    if b"/etc/ld.so.preload" in data:
        out.append(Indicator("elf.ld-preload", 40, "writes the system-wide LD preload list (rootkit persistence)"))
    return out


def macho_indicators(data: bytes) -> list[Indicator]:
    if len(data) >= 4096 and shannon_entropy(data) > 7.4:
        return [Indicator("macho.high-entropy", 30, "body is encrypted/compressed")]
    return []


# -------------------------------------------------------------------- scripts
_B64_BLOB = re.compile(rb"[A-Za-z0-9+/]{2000,}={0,2}")
_DYNAMIC_EXEC = re.compile(
    rb"\beval\s*\(|\bexec\s*\(|new\s+Function\s*\(|Invoke-Expression|\bIEX\b|\bexecute\s*\(", re.I)
_JSOBF_ID = re.compile(rb"\b_0x[0-9a-f]{4,6}\b")
_CHARCODE = re.compile(rb"fromCharCode\s*\(\s*(?:\d+\s*,\s*){29,}\d+")
_HEX_ESC = re.compile(rb"\\x[0-9a-fA-F]{2}")
_PS_ENC = re.compile(rb"-(?:e|ec|enc|encodedcommand)\s+[A-Za-z0-9+/]{100,}={0,2}", re.I)
_PS_HIDDEN = re.compile(rb"-(?:w|win|window|windowstyle)\s+hidden", re.I)
_PS_FROMB64 = re.compile(rb"FromBase64String", re.I)
# split so this source file never contains the literal bypass strings it hunts
_AMSI = re.compile(rb"Amsi(?:Utils|ScanBuffer)|amsi(?:Init)Failed", re.I)


def script_indicators(data: bytes) -> list[Indicator]:
    out: list[Indicator] = []
    dyn = _DYNAMIC_EXEC.search(data) is not None
    if dyn and _B64_BLOB.search(data):
        out.append(Indicator("script.exec-encoded-blob", 50,
                             "dynamically executes code next to a large encoded blob"))
    if len(_JSOBF_ID.findall(data)) >= 50:
        out.append(Indicator("script.js-obfuscator", 35, "javascript-obfuscator style _0x identifiers"))
    if dyn and _CHARCODE.search(data):
        out.append(Indicator("script.charcode-exec", 40, "builds code from character codes and executes it"))
    n_hex = len(_HEX_ESC.findall(data))
    if n_hex >= 300 and n_hex * 4 > len(data) // 3:
        out.append(Indicator("script.hex-escaped", 25, "body is mostly hex-escaped bytes"))
    if _PS_ENC.search(data):
        out.append(Indicator("ps.encoded-command", 30, "PowerShell launched with an encoded command"))
        if _PS_HIDDEN.search(data):
            out.append(Indicator("ps.hidden-window", 20, "PowerShell window hidden from the user"))
    if dyn and _PS_FROMB64.search(data) and re.search(rb"Invoke-Expression|\bIEX\b", data, re.I):
        out.append(Indicator("ps.decode-exec", 30, "decodes base64 and pipes it to Invoke-Expression"))
    if _AMSI.search(data):
        out.append(Indicator("ps.amsi-bypass", 60, "tampers with the Antimalware Scan Interface"))
    return out


# ------------------------------------------------------------------ dispatch
def analyze(data: bytes, name: str, tag: str) -> list[Indicator]:
    out = filename_indicators(name, tag)
    if tag == "pe":
        out += pe_indicators(data)
    elif tag == "elf":
        out += elf_indicators(data)
    elif tag in ("macho", "macho-fat"):
        out += macho_indicators(data)
    elif ft.is_script(tag) or tag in ("text", "script"):
        out += script_indicators(data)
    return out
