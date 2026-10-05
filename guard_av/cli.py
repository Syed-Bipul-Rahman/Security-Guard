"""
cli.py - command line front-end for the av engine.

    guard av scan <path> [<path> ...] [--json] [--quarantine] [--fail-on-suspicious]
                  [--no-archives] [--no-heuristics] [--signatures DIR ...]
    guard av quarantine list
    guard av quarantine restore <id> [--to PATH] [--overwrite]
    guard av quarantine delete <id>
    guard av rules [--validate FILE ...]
    guard av hash <file> [...]

Exit codes: 0 clean, 1 malicious found (or suspicious with --fail-on-suspicious),
2 usage / error.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from .engine import EngineConfig, ScanEngine, action_hint
from .hashing import hash_file
from .model import Verdict
from .quarantine import QuarantineError, QuarantineVault
from .rules import RuleError, RuleSet
from .yara_rules import YARA_SUFFIXES, YaraRuleSet


def guard_home() -> Path:
    return Path(os.environ.get("GUARD_HOME", str(Path.home() / ".guard")))


def _vault(args) -> QuarantineVault:
    return QuarantineVault(Path(args.vault) if args.vault else guard_home() / "av-quarantine")


def _build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="guard av", description="Guard antivirus engine")
    ap.add_argument("--vault", default=None, help="quarantine vault directory")
    sub = ap.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan", help="scan files / directories")
    s.add_argument("paths", nargs="+")
    s.add_argument("--json", action="store_true")
    s.add_argument("--quarantine", action="store_true",
                   help="move whole-file threats into the neutered vault")
    s.add_argument("--fail-on-suspicious", action="store_true")
    s.add_argument("--no-archives", action="store_true")
    s.add_argument("--no-heuristics", action="store_true")
    s.add_argument("--signatures", action="append", default=[],
                   help="extra directory of *.yar / rules*.json / hashes*.{json,txt} / allowlist*.json")

    q = sub.add_parser("quarantine", help="manage the quarantine vault")
    qs = q.add_subparsers(dest="qcmd", required=True)
    qs.add_parser("list")
    r = qs.add_parser("restore")
    r.add_argument("id")
    r.add_argument("--to", default=None)
    r.add_argument("--overwrite", action="store_true")
    d = qs.add_parser("delete")
    d.add_argument("id")

    ru = sub.add_parser("rules", help="list or validate rules")
    ru.add_argument("--validate", nargs="+", default=None, metavar="FILE",
                    help="check rules*.json or *.yar files")

    h = sub.add_parser("hash", help="print md5/sha1/sha256 of files")
    h.add_argument("files", nargs="+")
    return ap


def _print_result(r) -> None:
    hint = action_hint(r)
    tag = r.verdict.label.upper() if not r.error else "ERROR"
    print(f"[{tag}] {r.path}" + (f"  {r.threat_name}" if r.threat_name else "")
          + (f"  -> {hint}" if hint else "") + (f"  ({r.error})" if r.error else ""))
    for d in r.iter_detections():
        print(f"    - {d.engine}: {d.name} [{d.verdict.label}] {d.description}".rstrip())


def cmd_scan(args) -> int:
    cfg = EngineConfig(scan_archives=not args.no_archives, heuristics=not args.no_heuristics)
    extra = [guard_home() / "av"] + [Path(p) for p in args.signatures]
    engine = ScanEngine.default(cfg, extra_dirs=[d for d in extra if d.is_dir()])
    vault = _vault(args) if args.quarantine else None

    missing = [p for p in args.paths if not Path(p).exists()]
    if missing:
        print(f"no such file or directory: {', '.join(missing)}", file=sys.stderr)
        return 2

    totals = {"scanned": 0, "malicious": 0, "suspicious": 0, "errors": 0, "elapsed_sec": 0.0}
    report = []
    quarantined = []
    for target in args.paths:
        summary = engine.scan_path(target, on_result=None if args.json else
                                   (lambda r: _print_result(r) if r.error or r.verdict else None))
        for k in ("scanned", "malicious", "suspicious", "errors"):
            totals[k] += getattr(summary, k)
        totals["elapsed_sec"] += round(summary.elapsed, 3)
        for r in summary.results:
            entry = r.to_dict()
            entry["action"] = action_hint(r)
            if vault is not None and entry["action"] == "quarantine":
                try:
                    rec = vault.quarantine(r.path, threat=r.threat_name)
                    entry["quarantine_id"] = rec["id"]
                    quarantined.append(rec)
                except QuarantineError as exc:
                    entry["quarantine_error"] = str(exc)
            report.append(entry)

    if args.json:
        print(json.dumps({"summary": totals, "results": report}, indent=2))
    else:
        for rec in quarantined:
            print(f"quarantined {rec['original_path']} as {rec['id']}")
        print(f"\nscanned {totals['scanned']} file(s): {totals['malicious']} malicious, "
              f"{totals['suspicious']} suspicious, {totals['errors']} error(s)")
    if totals["malicious"] or (args.fail_on_suspicious and totals["suspicious"]):
        return 1
    return 0


def cmd_quarantine(args) -> int:
    vault = _vault(args)
    try:
        if args.qcmd == "list":
            items = vault.list()
            print(json.dumps(items, indent=2))
            return 0
        if args.qcmd == "restore":
            print(f"restored {vault.restore(args.id, dest=args.to, overwrite=args.overwrite)}")
            return 0
        vault.delete(args.id)
        print(f"deleted {args.id}")
        return 0
    except QuarantineError as exc:
        print(f"quarantine: {exc}", file=sys.stderr)
        return 2


def _validate(f: str) -> int:
    if Path(f).suffix.lower() not in YARA_SUFFIXES:
        return RuleSet().load(f)
    y = YaraRuleSet()
    y.load(f)
    if y.unavailable:
        raise RuntimeError("cannot check YARA rules: this build has no Rust core (guard_core)")
    for w in y.warnings:
        print(f"WARN {f}: {w}")
    return len(y)


def cmd_rules(args) -> int:
    if args.validate:
        rc = 0
        for f in args.validate:
            try:
                n = _validate(f)
                print(f"OK   {f}: {n} rule(s)")
            except (RuleError, OSError, ValueError, RuntimeError) as exc:
                print(f"FAIL {f}: {exc}")
                rc = 2
        return rc
    home = guard_home() / "av"
    engine = ScanEngine.default(extra_dirs=[home] if home.is_dir() else [])
    for r in engine.rules.rules:
        print(f"{r.id:45} {r.verdict.label:10} {r.name}")
    print(f"\n{len(engine.rules)} rule(s), {len(engine.yara)} YARA rule(s), "
          f"{len(engine.hashdb)} hash signature(s)")
    if engine.yara.unavailable:
        print("YARA rules were found but not loaded: this build has no Rust core (guard_core)")
    return 0


def cmd_hash(args) -> int:
    rc = 0
    for f in args.files:
        try:
            h = hash_file(f)
        except OSError as exc:
            print(f"{f}: {exc}", file=sys.stderr)
            rc = 2
            continue
        print(f"{h['sha256']}  {h['sha1']}  {h['md5']}  {f}")
    return rc


def main(argv: list[str] | None = None) -> int:
    ap = _build_parser()
    try:
        args = ap.parse_args(argv)
    except SystemExit as exc:
        return int(exc.code or 0)
    handlers = {"scan": cmd_scan, "quarantine": cmd_quarantine, "rules": cmd_rules, "hash": cmd_hash}
    return handlers[args.cmd](args)

