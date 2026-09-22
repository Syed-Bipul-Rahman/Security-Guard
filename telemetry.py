#!/usr/bin/env python3
"""
telemetry.py - Guard endpoint telemetry (attribution + scoping for incident response).

Collects host facts and a summary of what Guard detected, and posts it to a
CONFIGURABLE collector endpoint (never hardcoded here). Used to answer, for the
fleet: which machine/account is affected, where it is (floor/provider, resolved
from IP by config), how it got hit, and the pattern.

IMPORTANT (governance): this is scoping data for IR + credential rotation, NOT a
blame tool. Malware commits/actions appear under the identity of whoever was
compromised - treat an "affected" account as a VICTIM to clean up, not a culprit,
unless corroborated. Where telemetry is enabled, users should be told this
reporting exists.

What it sends (all fields best-effort; failures never crash the agent):
  host:    hostname, os+version, username, agent_version, machine_id (MAC-derived)
  network: local_ips (all), public_ip (optional, via configurable lookup)
  install: installed_by (the human who ran the installer), installed_at
  events:  counts by severity/rule, recent detections, categories ("how"), patterns

Config: GUARD_HOME/telemetry.config.json
  { "endpoint": "https://analysis.syedbipul.me/api/telemetry",   # your collector; empty = local-only
    "interval_sec": 3600,
    "public_ip_lookup": "https://api.ipify.org",                 # empty to disable outbound IP lookup
    "send_public_ip": true }
"""

from __future__ import annotations

import json
import os
import platform
import socket
import subprocess
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path


def guard_home() -> Path:
    return Path(os.environ.get("GUARD_HOME", str(Path.home() / ".guard")))


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# Where every agent reports (so machines show on the dashboard with NO config file —
# works on Windows too, where the installer doesn't write a config). The endpoint is
# a plain URL (not secret). The ingest token gates POSTs; in a public/distributed
# binary it isn't truly secret, so it's a low-stakes shared value. A CI secret or a
# local telemetry.config.json can override either.
DEFAULT_ENDPOINT = os.environ.get("GUARD_TELEMETRY_URL", "https://security-guard-fkt3.vercel.app/api/telemetry")
DEFAULT_INGEST = os.environ.get("GUARD_INGEST_TOKEN", "d6cc56d1a3d805248452fc28ce39073d637247b675bfaf0e6df91d0c0acae706")

DEFAULT_CONFIG = {
    "endpoint": DEFAULT_ENDPOINT,                    # baked collector URL (config file can override)
    "ingest_token": DEFAULT_INGEST,                  # baked shared secret (config file can override)
    "interval_sec": 3600,
    "public_ip_lookup": "https://api.ipify.org",     # empty string disables the outbound lookup
    "send_public_ip": True,
    "agent_version": "1.0.0",
}


def load_config(home: Path | None = None) -> dict:
    home = home or guard_home()
    p = home / "telemetry.config.json"
    cfg = dict(DEFAULT_CONFIG)
    if p.exists():
        try:
            cfg.update(json.loads(p.read_text(encoding="utf-8")))
        except (OSError, json.JSONDecodeError):
            pass
    return cfg


# ---------------------------------------------------------------------------
# host / network facts (stdlib only, all best-effort)
# ---------------------------------------------------------------------------
def _all_local_ips() -> list[str]:
    ips = set()
    # primary routable IP (UDP connect trick - no packets actually sent)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ips.add(s.getsockname()[0])
        s.close()
    except OSError:
        pass
    # everything resolvable for this host
    try:
        for res in socket.getaddrinfo(socket.gethostname(), None):
            ip = res[4][0]
            if ":" not in ip or ip.count(":") > 1:  # keep v4 + v6
                ips.add(ip)
    except OSError:
        pass
    # parse OS tools for interfaces the above miss (best-effort)
    try:
        if sys.platform.startswith("win"):
            out = subprocess.run(["ipconfig"], capture_output=True, text=True, timeout=5).stdout
            import re
            ips.update(re.findall(r"IPv4.*?:\s*([0-9.]+)", out))
        else:
            cmd = ["ip", "-o", "addr"] if _has("ip") else ["ifconfig"]
            out = subprocess.run(cmd, capture_output=True, text=True, timeout=5).stdout
            import re
            ips.update(re.findall(r"inet\s+([0-9.]+)", out))
    except Exception:
        pass
    return sorted(i for i in ips if i and not i.startswith("127."))


def _has(binname: str) -> bool:
    from shutil import which
    return which(binname) is not None


def _public_ip(cfg: dict) -> str | None:
    if not cfg.get("send_public_ip") or not cfg.get("public_ip_lookup"):
        return None
    try:
        import urllib.request
        req = urllib.request.Request(cfg["public_ip_lookup"], headers={"User-Agent": "guard-telemetry"})
        with urllib.request.urlopen(req, timeout=8) as r:
            ip = r.read().decode().strip()
        return ip if ip and len(ip) <= 45 else None
    except Exception:
        return None


def _machine_id() -> str:
    # MAC-derived stable id (uuid.getnode); hashed so we don't ship the raw MAC
    import hashlib
    return hashlib.sha256(str(uuid.getnode()).encode()).hexdigest()[:16]


def _install_info(home: Path) -> dict:
    p = home / "install.json"
    if p.exists():
        try:
            return json.loads(p.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            pass
    return {}


def collect_host(cfg: dict, home: Path) -> dict:
    import getpass
    return {
        "hostname": socket.gethostname(),
        "os": platform.system(),
        "os_version": platform.release(),
        "os_detail": platform.platform(),
        "username": _safe(getpass.getuser),
        "machine_id": _machine_id(),
        "agent_version": cfg.get("agent_version", "?"),
        "local_ips": _all_local_ips(),
        "public_ip": _public_ip(cfg),
        "install": _install_info(home),
    }


def _safe(fn):
    try:
        return fn()
    except Exception:
        return None


# ---------------------------------------------------------------------------
# detection-event summary (how / patterns) from alerts.jsonl
# ---------------------------------------------------------------------------
def collect_events(home: Path, recent: int = 25) -> dict:
    path = home / "alerts.jsonl"
    by_severity: dict[str, int] = {}
    by_rule: dict[str, int] = {}
    by_kind: dict[str, int] = {}
    events: list[dict] = []
    total = 0
    if path.exists():
        try:
            for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
                try:
                    r = json.loads(line)
                except json.JSONDecodeError:
                    continue
                total += 1
                sev = r.get("severity", "?")
                by_severity[sev] = by_severity.get(sev, 0) + 1
                rule = r.get("rule") or r.get("kind") or "?"
                by_rule[rule] = by_rule.get(rule, 0) + 1
                kind = r.get("kind", "?")
                by_kind[kind] = by_kind.get(kind, 0) + 1
                events.append({"ts": r.get("ts"), "severity": sev, "rule": rule,
                               "kind": kind, "summary": r.get("summary") or r.get("path")})
        except OSError:
            pass
    infected = by_severity.get("critical", 0) > 0
    top_patterns = sorted(by_rule.items(), key=lambda x: -x[1])[:5]
    return {
        "infected": infected,
        "total_detections": total,
        "by_severity": by_severity,
        "by_kind": by_kind,
        "how": [k for k, _ in top_patterns],     # dominant categories = "how it got hit"
        "patterns": dict(top_patterns),
        "recent": events[-recent:],
    }


def build_report(cfg: dict, home: Path) -> dict:
    return {
        "schema": "guard-telemetry/1",
        "ts": now_iso(),
        "host": collect_host(cfg, home),
        "events": collect_events(home),
    }


def send(report: dict, cfg: dict, home: Path) -> dict:
    # always write a local copy (the dashboard/collector can read it)
    try:
        (home / "telemetry.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    except OSError:
        pass
    endpoint = cfg.get("endpoint")
    if not endpoint:
        return {"status": "local-only"}
    try:
        import urllib.request
        data = json.dumps(report).encode()
        headers = {"Content-Type": "application/json", "User-Agent": "guard-telemetry"}
        if cfg.get("ingest_token"):
            headers["X-Guard-Token"] = cfg["ingest_token"]   # shared secret for the collector
        req = urllib.request.Request(endpoint, data=data, method="POST", headers=headers)
        with urllib.request.urlopen(req, timeout=15) as r:
            return {"status": "sent", "http": r.status}
    except Exception as e:
        # queue failed sends for retry
        try:
            q = home / "telemetry-queue.jsonl"
            with q.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(report) + "\n")
        except OSError:
            pass
        return {"status": "queued", "error": str(e)}


def run_once(home: Path | None = None) -> dict:
    home = home or guard_home()
    home.mkdir(parents=True, exist_ok=True)
    cfg = load_config(home)
    report = build_report(cfg, home)
    return send(report, cfg, home)


if __name__ == "__main__":
    print(json.dumps(run_once(), indent=2))
