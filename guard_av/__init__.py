"""
guard_av - Guard's general-purpose antivirus / anti-malware engine.

The original Guard engines (fingerprint_matcher, magic_bytes, vscode_guard) hunt
one supply-chain malware family. This package adds a layered, signature +
heuristic engine that recognises malware generally:

  hashdb      exact-match hash database (MD5 / SHA-1 / SHA-256)
  rules       YARA-style pattern rules (text / hex-with-wildcards / regex strings
              combined by boolean conditions)
  heuristics  static analysis: PE / ELF / Mach-O structure, entropy, packers,
              process-injection imports, script obfuscation, masquerading names
  archive     bounded recursive scanning of zip / tar / gzip (bomb-safe)
  allowlist   false-positive suppression (known-good hashes, paths, rule ids)
  quarantine  neutered, reversible quarantine vault
  engine      the pipeline that ties it together and produces a Verdict

False-positive policy: only exact hashes and high-confidence rules can produce a
MALICIOUS verdict. Heuristics on their own top out at SUSPICIOUS unless several
independent strong indicators agree. Scanning never modifies files.
"""

from __future__ import annotations

from .model import Detection, ScanResult, Verdict
from .engine import EngineConfig, ScanEngine

__all__ = ["Detection", "ScanResult", "Verdict", "EngineConfig", "ScanEngine"]
__version__ = "2.0.0"
