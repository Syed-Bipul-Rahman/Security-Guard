#!/usr/bin/env python3
"""
magic_bytes.py — detect JS/text droppers disguised with a binary extension.

Attack observed in the sparktechagency incident: a Node.js dropper was saved as
`public/fonts/fa-solid-400.woff2` (a real FontAwesome font name) so it would pass
code review as a "binary asset". A genuine .woff2 begins with the bytes "wOF2";
the dropper did not.

Rule: for a file whose extension is normally binary, if it does NOT start with the
expected magic bytes AND its body looks like source text (UTF-8 decodable with
JS-ish indicators), flag it as a disguised dropper.
"""

from __future__ import annotations

import binascii
from dataclasses import dataclass, field
from pathlib import Path


# Loaded from signatures.json["magic_bytes"] in production; inlined defaults here
# so this module also runs standalone.
DEFAULT_MAGIC = {
    ".woff2": ["774f4632"],                 # wOF2
    ".woff":  ["774f4646"],                 # wOFF
    ".ttf":   ["00010000", "74727565"],     # \x00\x01\x00\x00 or "true"
    ".otf":   ["4f54544f"],                 # OTTO
    ".eot":   [],                           # no reliable single magic; rely on text check
    ".png":   ["89504e470d0a1a0a"],
    ".jpg":   ["ffd8ff"],
    ".jpeg":  ["ffd8ff"],
    ".gif":   ["474946383761", "474946383961"],
    ".ico":   ["00000100"],
}

DEFAULT_TEXT_INDICATORS = [
    "require(", "global[", "process.env", "eval(", "function",
    "=>", "var _$_", "module.exports", "import ",
]


@dataclass
class MagicFinding:
    path: str
    severity: str
    reason: str
    detail: str = ""

    def __str__(self) -> str:
        return f"[{self.severity.upper()}] {self.path}: {self.reason}" + (f" ({self.detail})" if self.detail else "")


class MagicByteChecker:
    def __init__(self, magic_by_ext: dict | None = None, text_indicators: list[str] | None = None,
                 read_bytes: int = 16, sniff_bytes: int = 4096) -> None:
        self.magic = {k.lower(): [m.lower() for m in v] for k, v in (magic_by_ext or DEFAULT_MAGIC).items()}
        self.text_indicators = text_indicators or DEFAULT_TEXT_INDICATORS
        self.read_bytes = read_bytes
        self.sniff_bytes = sniff_bytes

    @classmethod
    def from_signatures(cls, sig: dict) -> "MagicByteChecker":
        mb = sig.get("magic_bytes", {})
        return cls(magic_by_ext=mb.get("by_ext"), text_indicators=mb.get("text_body_indicators"))

    def _header_hex(self, data: bytes) -> str:
        return binascii.hexlify(data[: self.read_bytes]).decode("ascii")

    def _looks_like_text(self, data: bytes) -> tuple[bool, str]:
        """True if the head decodes as UTF-8 and contains source-code indicators."""
        try:
            text = data[: self.sniff_bytes].decode("utf-8")
        except UnicodeDecodeError:
            return False, ""
        hits = [ind for ind in self.text_indicators if ind in text]
        return (bool(hits), ", ".join(hits[:4]))

    def check_bytes(self, path: str, data: bytes) -> list[MagicFinding]:
        ext = Path(path).suffix.lower()
        if ext not in self.magic:
            return []  # not a binary-extension we police

        header = self._header_hex(data)
        expected = self.magic[ext]
        magic_ok = any(header.startswith(m) for m in expected) if expected else False

        findings: list[MagicFinding] = []
        is_text, indicators = self._looks_like_text(data)

        if expected and not magic_ok and is_text:
            findings.append(MagicFinding(
                path=path, severity="critical",
                reason=f"binary-disguised dropper: {ext} file contains source text, not {ext} data",
                detail=f"header={header[:16]} expected~{expected[0]} indicators=[{indicators}]",
            ))
        elif not expected and is_text:
            # extension has no reliable magic (e.g. .eot) but body is clearly code
            findings.append(MagicFinding(
                path=path, severity="high",
                reason=f"suspicious: {ext} asset contains source text",
                detail=f"indicators=[{indicators}]",
            ))
        elif expected and not magic_ok and not is_text:
            # wrong magic but not obviously text — corrupt or unknown; low signal
            findings.append(MagicFinding(
                path=path, severity="low",
                reason=f"{ext} file has unexpected header (not disguised text, but not valid {ext})",
                detail=f"header={header[:16]}",
            ))
        return findings

    def check_file(self, path: str | Path) -> list[MagicFinding]:
        p = Path(path)
        try:
            # Read only the prefix we need (header + sniff window), NOT the whole
            # file — a disguised dropper reveals itself in the first few KB, and
            # this keeps memory flat regardless of file size.
            with p.open("rb") as fh:
                data = fh.read(max(self.read_bytes, self.sniff_bytes))
        except OSError as exc:
            return [MagicFinding(path=str(p), severity="info", reason="unreadable", detail=str(exc))]
        return self.check_bytes(str(p), data)


if __name__ == "__main__":
    import sys
    checker = MagicByteChecker()
    if len(sys.argv) < 2:
        print("usage: magic_bytes.py <file> [file ...]")
        raise SystemExit(2)
    exit_code = 0
    for arg in sys.argv[1:]:
        for f in checker.check_file(arg):
            print(f)
            if f.severity in ("critical", "high"):
                exit_code = 1
    raise SystemExit(exit_code)
