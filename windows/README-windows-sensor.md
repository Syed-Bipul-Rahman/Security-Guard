# Guard Windows sensor — kernel-level telemetry

Covers the three Windows behaviors from the investigation:
- **A.** Python/script files created in `%TEMP%`
- **B.** Registry modifications (persistence)
- **C.** Repeated forced reboots during working hours

## The decision: get kernel-level telemetry *without* writing a kernel driver (yet)

"Kernel-level" does not require *our own* kernel driver. Two mechanisms give
kernel-sourced events from user mode:

| Mechanism | What it is | Driver we must write/sign? |
|-----------|-----------|----------------------------|
| **Sysmon** | Microsoft-signed **kernel-mode** driver + service (Sysinternals) | **No** — deploy MS's driver + our config |
| **ETW** | Kernel providers (Process/File/Registry) streamed to a user-mode consumer | **No** |
| Custom **minifilter / ETW driver** | Our own kernel driver | **Yes** — Tier 2, see below |

**Tier 1 (build/deploy now):** Sysmon (kernel driver, already signed by Microsoft)
+ our `windows_sensor.py` consuming its event log, plus the System log for reboots.
This is genuinely kernel-sourced and covers A/B/C today.

**Tier 2 (only if a measured gap forces it):** a custom minifilter or ETW-based
driver. Reasons you would escalate: you need to *block* an action in-kernel (not
just observe), tamper-proofing against a local admin stopping Sysmon, or telemetry
Sysmon/ETW don't expose. Costs to accept before starting Tier 2:
- **EV code-signing cert** + **Microsoft attestation signing** for the driver
  (Windows 10+ won't load an unsigned kernel driver).
- **BSOD / boot-loop risk** on developer machines — a driver bug bricks the box.
  Requires a test ring, staged rollout, and a recovery plan.
- WDK expertise, months of work, ongoing per-Windows-build maintenance.
Do not start Tier 2 without evidence Tier 1 is insufficient.

## Behavior → event source mapping

| Behavior | Kernel source | Event | Guard rule |
|----------|---------------|-------|------------|
| A. `.py`/script dropped in temp | Sysmon **FileCreate** | ID **11** | `win.temp.script_drop` |
| A. interpreter run from temp | Sysmon **ProcessCreate** | ID **1** | `win.interp_from_temp` |
| dropper hand-off (`node`→`powershell`/`cmd`/`python`) | Sysmon ProcessCreate | ID 1 | `win.suspicious_spawn` |
| encoded/download-exec powershell | Sysmon ProcessCreate | ID 1 | `win.suspicious_spawn` / `win.cmdline_ioc` |
| B. registry persistence write | Sysmon **RegistryEvent** | ID **12/13/14** | `win.registry_persistence` |
| C. who initiated a reboot | System log | ID **1074** | `win.forced_reboot` / `win.script_initiated_reboot` |
| C. unexpected/unclean reboot | System log | ID **41 / 6008** | `win.unexpected_reboot` |
| C. **burst** of reboots in work hours | System log (stateful) | 1074×N | `win.reboot_burst` (2+ in 3h) |

All signatures live in `../signatures.json` under `"windows"`, so tuning needs no
code change.

## Components

| File | Role |
|------|------|
| `sysmon-config.xml` | Narrow Sysmon config tuned to A/B/C (low noise on dev machines) |
| `windows_sensor.py` | Consumes Sysmon + System-log events, matches signatures, writes `alerts.jsonl` |
| `reboot-forensics.ps1` | **Run-now** IR: reboot history + initiators + burst detection |
| `reboot-cause.ps1` | **Run-now** IR: root-cause of unexpected (Event 41) reboots - crash vs power vs reset |
| `temp-registry-forensics.ps1` | **Run-now** IR: temp/staging script droppers + registry persistence sweep |
| `install-service.ps1` | (in `../service/windows/`) registers the sensor as a scheduled task, AtStartup+AtLogon |

## Run-now IR scripts (no agent, read-only) - use these first

All three are ASCII-only (PS 5.1 safe) and write optional JSONL in the Guard
alerts schema. Run elevated:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\reboot-forensics.ps1          -Days 30   # WHEN/WHO restarted
.\reboot-cause.ps1              -Days 30   # WHY the unexpected reboots happened
.\temp-registry-forensics.ps1  -Days 30   # staging (temp) + persistence (registry)
```

Copy the files to the host as-is (don't paste into Notepad - PS 5.1 mis-reads
UTF-8-without-BOM). Run each on 2-3 affected machines and compare: fleet-wide
identical patterns point to a common cause; per-machine randomness points to
local hardware/power.

## Answer "who is rebooting these machines?" RIGHT NOW

Before any agent is deployed, run this read-only script on an affected workstation
(elevated PowerShell) to pull reboot history from the last N days:

```powershell
# Human-readable report
.\reboot-forensics.ps1 -Days 30

# Also emit JSONL in the Guard alerts schema for central collection
.\reboot-forensics.ps1 -Days 30 -OutFile $env:USERPROFILE\.guard\reboot-forensics.jsonl
```

It reports each 1074/41/6008/6006/6005 event with its **initiating process and
user**, flags **reboot bursts** (2+ within 3h, highlighting work-hours ones — the
incident pattern), and cross-references Sysmon `shutdown.exe` launches for reliable
attribution if Sysmon is already installed. Untested on this build's exact 1074
property layout — the raw event Message is always included as a fallback, so an
analyst sees the truth even if an insertion-string index shifted.

`windows_sensor.py` is split into:
- `WindowsDetector` — **pure logic**, unit-testable on any OS
  (`python windows_sensor.py --selftest`), and
- **event sources** (`SysmonSource`, `RebootSource`) — Windows-only, need `pywin32`.

## Deploy (per Windows workstation, elevated)

```powershell
# 1. Install Sysmon (Microsoft-signed kernel driver) with our config
.\sysmon64.exe -accepteula -i .\sysmon-config.xml

# 2. Install the Guard Windows sensor as an auto-start, keep-alive task
..\service\windows\install-service.ps1   # point it at windows_sensor.py

# 3. Verify
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 5
Get-Content $env:USERPROFILE\.guard\alerts.jsonl -Wait
```

## Status / caveats (be honest)

- The **detection logic is tested** (`--selftest`, 8 synthetic events, clean
  control produces nothing) — but on **macOS**, so the Windows **event-source
  layer is unvalidated on real hardware**. It must be run + tuned on a Windows
  box: verify the Sysmon XML field names (`Image`, `ParentImage`, `TargetObject`,
  `Details`, `TargetFilename`) render as expected and adjust `RebootSource`
  param-name mapping for 1074 (`param5` = process, varies by Windows build).
- Sysmon field/param naming shifts across versions — pin a Sysmon version in the
  fleet and validate against it.
- This is **detect + report**. Blocking a reboot or a registry write in real time
  is a Tier-2 (kernel driver) capability, deliberately out of scope here.
- Reboot-initiator attribution from 1074 is best-effort; correlate with the
  Sysmon ProcessCreate of `shutdown.exe` for a reliable culprit.
