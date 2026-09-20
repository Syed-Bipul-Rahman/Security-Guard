#!/usr/bin/env python3
"""
windows_sensor.py — Guard Windows endpoint sensor (Tier 1: ETW + Sysmon + EventLog).

Covers the three Windows behaviors from the investigation:
  A. python/script files staged in TEMP        -> Sysmon FileCreate (ID 11)
  B. registry persistence modifications         -> Sysmon RegistryEvent (12/13/14)
  C. repeated forced reboots during work hours   -> System log 1074 / 41 / 6008

DESIGN
------
Two layers, deliberately separated:

  * WindowsDetector  — PURE LOGIC. Takes NORMALIZED event dicts and returns
    findings by matching signatures.json["windows"]. Has no Windows dependency,
    so it is unit-testable on any OS (see selftest at bottom).

  * Event sources    — WINDOWS ONLY. Read real events and normalize them:
      - SysmonSource    : Microsoft-Windows-Sysmon/Operational  (kernel driver)
      - RebootSource    : System log (Event IDs 1074/41/6008/6006)
      - EtwProcessSource: optional pure-ETW process/file/registry (no Sysmon)
    These import pywin32 lazily and degrade gracefully if unavailable.

WHY NOT A CUSTOM KERNEL DRIVER (yet): Sysmon IS a Microsoft-signed kernel-mode
driver; consuming it gives kernel-sourced file/registry/process events without
shipping/signing our own driver. A custom minifilter is Tier 2, scoped separately
(needs EV cert + attestation signing + BSOD risk). See README-windows-sensor.md.

Alerts are written to <GUARD_HOME>/alerts.jsonl, same schema as the watcher.
"""

from __future__ import annotations

import json
import ntpath
import os
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from pathlib import Path


def guard_home() -> Path:
    return Path(os.environ.get("GUARD_HOME", str(Path.home() / ".guard")))


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def load_signatures() -> dict:
    # sensor lives in windows/, signatures.json is one level up (or alongside once bundled)
    here = Path(__file__).resolve().parent
    for cand in (here / "signatures.json", here.parent / "signatures.json"):
        if cand.exists():
            return json.loads(cand.read_text(encoding="utf-8"))
    raise FileNotFoundError("signatures.json not found next to sensor or in parent dir")


@dataclass
class WinFinding:
    rule: str
    severity: str
    event_type: str
    summary: str
    evidence: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {"rule": self.rule, "severity": self.severity,
                "event_type": self.event_type, "summary": self.summary,
                "evidence": self.evidence}


# ---------------------------------------------------------------------------
# PORTABLE detection layer (testable anywhere)
# ---------------------------------------------------------------------------

class WindowsDetector:
    """Match NORMALIZED Windows events against signatures.json['windows']."""

    def __init__(self, sig: dict) -> None:
        w = sig.get("windows", {})
        self.temp_markers = [m.lower() for m in w.get("temp_dir_markers", [])]
        self.temp_exts = set(e.lower() for e in w.get("suspicious_temp_ext", []))
        self.interpreters = set(p.lower() for p in w.get("interpreter_procs", []))
        self.reg_keys = [k.lower() for k in w.get("registry_persistence_keys", [])]
        self.reg_value_ind = [v.lower() for v in w.get("registry_value_indicators", [])]
        self.reboot_ids = {int(k): v for k, v in w.get("reboot_event_ids", {}).items()}
        self.reboot_initiators = set(p.lower() for p in w.get("reboot_initiator_procs", []))
        rb = w.get("reboot_burst", {})
        self.burst_count = int(rb.get("count", 2))
        self.burst_window = timedelta(minutes=int(rb.get("window_minutes", 180)))
        self.parent_child = {(a.lower(), b.lower()) for a, b in w.get("suspicious_parent_child", [])}
        # shared C2/payload indicators reused from the top-level literals
        self.payload_indicators = [l["value"].lower() for l in sig.get("literals", [])
                                   if l.get("category") in ("obfuscated-c2", "dropper-cmd")]
        self.net_iocs = [i["value"].lower() for i in sig.get("network_iocs", [])]

        # stateful reboot history (per host process lifetime); persisted by caller
        self._reboot_times: list[datetime] = []

    # ---- individual event handlers ----
    def on_file_create(self, ev: dict) -> list[WinFinding]:
        path = str(ev.get("path", ""))
        low = path.lower()
        ext = ntpath.splitext(low)[1]
        in_temp = any(m in low for m in self.temp_markers)
        findings = []
        if in_temp and ext in self.temp_exts:
            findings.append(WinFinding(
                "win.temp.script_drop", "critical", "file_create",
                f"script/dropper staged in temp: {path}",
                {"path": path, "image": ev.get("image", ""), "ext": ext}))
        # a fake-font dropper anywhere is critical (reuse cross-platform IOC)
        if low.endswith(".woff2") and ev.get("looks_like_text"):
            findings.append(WinFinding(
                "win.fake_font_drop", "critical", "file_create",
                f"binary-disguised dropper written: {path}", {"path": path}))
        return findings

    def on_process_create(self, ev: dict) -> list[WinFinding]:
        # Windows event data always carries Windows paths; use ntpath so basename
        # works correctly regardless of the host OS running the sensor/tests.
        image = ntpath.basename(str(ev.get("image", ""))).lower()
        parent = ntpath.basename(str(ev.get("parent_image", ""))).lower()
        cmd = str(ev.get("cmdline", "")).lower()
        findings = []

        if (parent, image) in self.parent_child:
            findings.append(WinFinding(
                "win.suspicious_spawn", "high", "process_create",
                f"suspicious parent/child: {parent} -> {image}",
                {"parent": parent, "image": image, "cmdline": ev.get("cmdline", "")}))

        # interpreter running something from temp
        if image in self.interpreters and any(m in cmd for m in self.temp_markers):
            findings.append(WinFinding(
                "win.interp_from_temp", "critical", "process_create",
                f"{image} executing from temp: {ev.get('cmdline','')}",
                {"image": image, "cmdline": ev.get("cmdline", "")}))

        # shutdown/reboot initiated by a script/dev tool
        if image in self.reboot_initiators or "shutdown" in cmd:
            if parent in self.interpreters or (parent, image) in self.parent_child:
                findings.append(WinFinding(
                    "win.script_initiated_reboot", "critical", "process_create",
                    f"reboot initiated by {parent}: {ev.get('cmdline','')}",
                    {"parent": parent, "cmdline": ev.get("cmdline", "")}))

        # known payload/C2 strings in a command line
        hits = [s for s in (self.payload_indicators + self.net_iocs) if s in cmd]
        if hits:
            findings.append(WinFinding(
                "win.cmdline_ioc", "critical", "process_create",
                f"command line matches incident IOCs: {', '.join(hits[:3])}",
                {"cmdline": ev.get("cmdline", ""), "iocs": hits[:5]}))
        return findings

    def on_registry_set(self, ev: dict) -> list[WinFinding]:
        key = str(ev.get("key", "")).lower()
        data = str(ev.get("value_data", "")).lower()
        findings = []
        in_persist = any(k in key for k in self.reg_keys)
        if in_persist:
            ind = [v for v in self.reg_value_ind if v in data or v in key]
            sev = "critical" if ind else "high"
            findings.append(WinFinding(
                "win.registry_persistence", sev, "registry_set",
                f"write to persistence key: {ev.get('key','')}",
                {"key": ev.get("key", ""), "value_name": ev.get("value_name", ""),
                 "value_data": ev.get("value_data", ""), "indicators": ind}))
        return findings

    def on_reboot(self, ev: dict) -> list[WinFinding]:
        eid = int(ev.get("event_id", 0))
        ts = ev.get("ts_dt") or datetime.now(timezone.utc)
        findings = []
        initiator = str(ev.get("initiator", "")).lower()

        # record and evaluate burst
        self._reboot_times.append(ts)
        cutoff = ts - self.burst_window
        self._reboot_times = [t for t in self._reboot_times if t >= cutoff]
        if len(self._reboot_times) >= self.burst_count:
            findings.append(WinFinding(
                "win.reboot_burst", "critical", "reboot",
                f"{len(self._reboot_times)} reboots within {self.burst_window} "
                f"(latest EID {eid}: {self.reboot_ids.get(eid,'?')})",
                {"event_id": eid, "count": len(self._reboot_times),
                 "initiator": ev.get("initiator", "")}))

        if any(p in initiator for p in self.reboot_initiators) and eid in (1074,):
            findings.append(WinFinding(
                "win.forced_reboot", "high", "reboot",
                f"reboot initiated by {ev.get('initiator','?')} (EID {eid})",
                {"event_id": eid, "initiator": ev.get("initiator", "")}))
        elif eid in (41, 6008):
            findings.append(WinFinding(
                "win.unexpected_reboot", "high", "reboot",
                f"unexpected/unclean reboot (EID {eid}: {self.reboot_ids.get(eid,'?')})",
                {"event_id": eid}))
        return findings

    def dispatch(self, ev: dict) -> list[WinFinding]:
        t = ev.get("type")
        if t == "file_create":
            return self.on_file_create(ev)
        if t == "process_create":
            return self.on_process_create(ev)
        if t == "registry_set":
            return self.on_registry_set(ev)
        if t == "reboot":
            return self.on_reboot(ev)
        return []


# ---------------------------------------------------------------------------
# WINDOWS-ONLY event sources (require pywin32 / a Windows host)
# ---------------------------------------------------------------------------

def _require_windows():
    if not sys.platform.startswith("win"):
        raise RuntimeError("event sources run on Windows only; use WindowsDetector for logic/tests")


class SysmonSource:
    """Tail Microsoft-Windows-Sysmon/Operational and normalize events.

    Sysmon (Microsoft Sysinternals) is a signed KERNEL-MODE driver; deploy it with
    windows/sysmon-config.xml. This reader consumes its event log. Requires pywin32.
    """
    CHANNEL = "Microsoft-Windows-Sysmon/Operational"

    def __init__(self):
        _require_windows()
        import win32evtlog  # noqa: F401  (validated present)
        self.win32evtlog = win32evtlog

    def stream(self):
        """Yield normalized event dicts. Uses EvtSubscribe for a live tail."""
        import win32evtlog
        # Map Sysmon Event IDs -> normalized types
        # 1=ProcessCreate, 11=FileCreate, 12/13/14=RegistryEvent
        query = "*"
        h = win32evtlog.EvtSubscribe(
            self.CHANNEL, win32evtlog.EvtSubscribeToFutureEvents, Query=query)
        while True:
            events = win32evtlog.EvtNext(h, 10, 1000)
            for e in events:
                xml = win32evtlog.EvtRender(e, win32evtlog.EvtRenderEventXml)
                norm = self._normalize(xml)
                if norm:
                    yield norm

    @staticmethod
    def _normalize(xml: str) -> dict | None:
        import xml.etree.ElementTree as ET
        try:
            root = ET.fromstring(xml)
        except ET.ParseError:
            return None
        ns = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
        eid = root.findtext(".//e:System/e:EventID", default="", namespaces=ns)
        data = {d.get("Name"): (d.text or "")
                for d in root.findall(".//e:EventData/e:Data", ns)}
        if eid == "1":
            return {"type": "process_create", "image": data.get("Image", ""),
                    "parent_image": data.get("ParentImage", ""),
                    "cmdline": data.get("CommandLine", ""), "ts": now_iso()}
        if eid == "11":
            return {"type": "file_create", "path": data.get("TargetFilename", ""),
                    "image": data.get("Image", ""), "ts": now_iso()}
        if eid in ("12", "13", "14"):
            return {"type": "registry_set",
                    "key": data.get("TargetObject", ""),
                    "value_data": data.get("Details", ""),
                    "image": data.get("Image", ""), "ts": now_iso()}
        return None


class RebootSource:
    """Read reboot-related events from the System log (1074/41/6008/6006)."""
    CHANNEL = "System"

    def __init__(self):
        _require_windows()

    def stream(self):
        import win32evtlog
        import xml.etree.ElementTree as ET
        ns = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
        q = ("*[System[(EventID=1074 or EventID=1075 or EventID=41 "
             "or EventID=6008 or EventID=6006)]]")
        h = win32evtlog.EvtSubscribe(
            self.CHANNEL, win32evtlog.EvtSubscribeToFutureEvents, Query=q)
        while True:
            for e in win32evtlog.EvtNext(h, 10, 1000):
                xml = win32evtlog.EvtRender(e, win32evtlog.EvtRenderEventXml)
                try:
                    root = ET.fromstring(xml)
                except ET.ParseError:
                    continue
                eid = int(root.findtext(".//e:System/e:EventID", "0", ns))
                data = {d.get("Name"): (d.text or "")
                        for d in root.findall(".//e:EventData/e:Data", ns)}
                yield {"type": "reboot", "event_id": eid,
                       "initiator": data.get("param5") or data.get("ProcessName", ""),
                       "reason": data.get("param3", ""),
                       "ts": now_iso(), "ts_dt": datetime.now(timezone.utc)}


class Sensor:
    """Glue: pull events from sources, run the detector, write alerts."""

    def __init__(self, home: Path | None = None):
        self.home = home or guard_home()
        self.home.mkdir(parents=True, exist_ok=True)
        self.alert_path = self.home / "alerts.jsonl"
        self.log_path = self.home / "windows_sensor.log"
        self.detector = WindowsDetector(load_signatures())

    def log(self, msg: str):
        line = f"{now_iso()}  {msg}"
        print(line, flush=True)
        try:
            self.log_path.open("a", encoding="utf-8").write(line + "\n")
        except OSError:
            pass

    def alert(self, findings: list[WinFinding], ev: dict):
        for f in findings:
            rec = {"ts": now_iso(), "kind": f"win:{f.event_type}",
                   "rule": f.rule, "severity": f.severity,
                   "summary": f.summary, "evidence": f.evidence}
            try:
                self.alert_path.open("a", encoding="utf-8").write(json.dumps(rec, default=str) + "\n")
            except OSError:
                pass
            self.log(f"ALERT [{f.severity}] {f.rule}: {f.summary}")

    def run(self):
        _require_windows()
        import threading
        self.log("windows sensor starting (Sysmon + System reboot sources)")
        for src in (SysmonSource(), RebootSource()):
            t = threading.Thread(target=self._pump, args=(src,), daemon=True)
            t.start()
        # keep alive
        import time
        while True:
            time.sleep(3600)

    def _pump(self, source):
        try:
            for ev in source.stream():
                findings = self.detector.dispatch(ev)
                if findings:
                    self.alert(findings, ev)
        except Exception as exc:
            self.log(f"source {type(source).__name__} error: {exc}")


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--selftest":
        # Portable: exercise the detection logic with synthetic events (no Windows).
        det = WindowsDetector(load_signatures())
        samples = [
            {"type": "file_create", "path": r"C:\Users\dev\AppData\Local\Temp\stage9.py", "image": r"C:\Program Files\nodejs\node.exe"},
            {"type": "process_create", "image": r"C:\Windows\System32\shutdown.exe", "parent_image": r"C:\Program Files\nodejs\node.exe", "cmdline": "shutdown /r /t 0"},
            {"type": "process_create", "image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", "parent_image": r"C:\Program Files\nodejs\node.exe", "cmdline": "powershell -enc ZXZpbA=="},
            {"type": "registry_set", "key": r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run", "value_name": "Updater", "value_data": r"python C:\Users\dev\AppData\Local\Temp\stage9.py", "image": r"python.exe"},
            {"type": "reboot", "event_id": 1074, "initiator": "shutdown.exe", "ts_dt": datetime.now(timezone.utc)},
            {"type": "reboot", "event_id": 1074, "initiator": "shutdown.exe", "ts_dt": datetime.now(timezone.utc)},
            {"type": "file_create", "path": r"C:\project\src\index.ts", "image": r"Code.exe"},  # clean control
        ]
        total = 0
        for ev in samples:
            fs = det.dispatch(ev)
            for f in fs:
                total += 1
                print(f"[{f.severity.upper()}] {f.rule}: {f.summary}")
        print(f"\nselftest: {total} finding(s); clean control produced none = "
              f"{'OK' if not det.dispatch(samples[-1]) else 'FAIL'}")
        raise SystemExit(0)

    Sensor().run()
