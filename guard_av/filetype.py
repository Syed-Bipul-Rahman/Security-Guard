"""
filetype.py - identify a file by CONTENT (magic bytes / shebang), not extension.

Malware routinely lies about its extension, so every engine decision is keyed on
what the bytes actually are. Returns a short type tag; see TYPES.
"""

from __future__ import annotations

from pathlib import PurePath

# (prefix bytes, offset, tag) - checked in order, first match wins.
_MAGIC: list[tuple[bytes, int, str]] = [
    (b"MZ", 0, "pe"),
    (b"\x7fELF", 0, "elf"),
    (b"\xfe\xed\xfa\xce", 0, "macho"),
    (b"\xfe\xed\xfa\xcf", 0, "macho"),
    (b"\xce\xfa\xed\xfe", 0, "macho"),
    (b"\xcf\xfa\xed\xfe", 0, "macho"),
    (b"\xca\xfe\xba\xbe", 0, "macho-fat"),   # also Java .class; disambiguated below
    (b"PK\x03\x04", 0, "zip"),
    (b"PK\x05\x06", 0, "zip"),               # empty archive
    (b"\x1f\x8b", 0, "gzip"),
    (b"BZh", 0, "bzip2"),
    (b"\xfd7zXZ\x00", 0, "xz"),
    (b"7z\xbc\xaf\x27\x1c", 0, "7z"),
    (b"Rar!\x1a\x07", 0, "rar"),
    (b"ustar", 257, "tar"),
    (b"%PDF-", 0, "pdf"),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", 0, "ole"),   # legacy Office (doc/xls/ppt/msi)
    (b"{\\rtf", 0, "rtf"),
    (b"\x89PNG\r\n\x1a\n", 0, "png"),
    (b"\xff\xd8\xff", 0, "jpeg"),
    (b"GIF87a", 0, "gif"),
    (b"GIF89a", 0, "gif"),
    (b"wOF2", 0, "woff2"),
    (b"wOFF", 0, "woff"),
    (b"\x00asm", 0, "wasm"),
    (b"dex\n", 0, "dex"),
    (b"L\x00\x00\x00\x01\x14\x02\x00", 0, "lnk"),
    (b"SQLite format 3\x00", 0, "sqlite"),
]

_SHEBANGS = {
    "sh": "shell", "bash": "shell", "zsh": "shell", "dash": "shell", "ksh": "shell",
    "python": "python", "python2": "python", "python3": "python",
    "node": "javascript", "perl": "perl", "ruby": "ruby", "php": "php",
    "pwsh": "powershell", "powershell": "powershell",
}

_EXT_SCRIPTS = {
    ".js": "javascript", ".mjs": "javascript", ".cjs": "javascript", ".jsx": "javascript",
    ".ts": "javascript", ".tsx": "javascript",
    ".py": "python", ".pyw": "python",
    ".sh": "shell", ".bash": "shell", ".zsh": "shell",
    ".ps1": "powershell", ".psm1": "powershell", ".psd1": "powershell",
    ".bat": "batch", ".cmd": "batch",
    ".vbs": "vbscript", ".vbe": "vbscript", ".vba": "vbscript", ".bas": "vbscript",
    ".php": "php", ".phtml": "php",
    ".pl": "perl", ".rb": "ruby",
    ".hta": "html", ".html": "html", ".htm": "html",
}

EXECUTABLE_TYPES = frozenset({"pe", "elf", "macho", "macho-fat", "dex"})
ARCHIVE_TYPES = frozenset({"zip", "gzip", "tar", "bzip2", "xz", "7z", "rar"})
SCRIPT_TYPES = frozenset(set(_EXT_SCRIPTS.values()) | set(_SHEBANGS.values()))
DOCUMENT_EXTS = frozenset({
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".txt", ".rtf",
    ".jpg", ".jpeg", ".png", ".gif", ".mp3", ".mp4", ".avi", ".mov", ".csv", ".odt",
})


def _is_text(head: bytes) -> bool:
    if not head:
        return True
    if b"\x00" in head:
        # UTF-16 text has NULs; treat a BOM-prefixed buffer as text
        return head[:2] in (b"\xff\xfe", b"\xfe\xff")
    try:
        head.decode("utf-8")
        return True
    except UnicodeDecodeError as exc:
        # a multi-byte char cut at the end of the sniff window is still text
        return exc.start >= len(head) - 3


def identify(head: bytes, name: str = "") -> str:
    """Return a type tag for a buffer (pass at least the first 512 bytes)."""
    for magic, off, tag in _MAGIC:
        if head[off:off + len(magic)] == magic:
            if tag == "macho-fat" and len(head) >= 8:
                # Java .class shares CAFEBABE; its bytes 4-8 are a version >= 45,
                # a fat Mach-O has a small arch count there.
                if int.from_bytes(head[4:8], "big") >= 45:
                    return "java-class"
            return tag
    if head.startswith(b"#!"):
        line = head[2:120].split(b"\n", 1)[0].decode("latin-1").strip()
        parts = line.split()
        prog = ""
        if parts:
            prog = PurePath(parts[0]).name
            if prog == "env" and len(parts) > 1:
                prog = parts[1]
        for key in sorted(_SHEBANGS, key=len, reverse=True):
            if prog.startswith(key):
                return _SHEBANGS[key]
        return "script"
    if _is_text(head):
        ext = PurePath(name).suffix.lower() if name else ""
        return _EXT_SCRIPTS.get(ext, "text")
    return "binary"


def is_executable(tag: str) -> bool:
    return tag in EXECUTABLE_TYPES


def is_archive(tag: str) -> bool:
    return tag in ARCHIVE_TYPES


def is_script(tag: str) -> bool:
    return tag in SCRIPT_TYPES
