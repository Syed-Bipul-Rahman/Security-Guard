<#
.SYNOPSIS
    Guard reboot ROOT-CAUSE analysis - explain each unexpected (Event 41) reboot.

.DESCRIPTION
    reboot-forensics.ps1 tells you WHEN/ WHO. This tells you WHY the UNCLEAN
    reboots (Kernel-Power Event 41) happened, using data already on the machine:

      * Event 41 properties  : BugcheckCode, PowerButtonTimestamp -> classify
      * BugCheck (Event 1001): the BSOD text, if a crash occurred
      * Minidumps            : C:\Windows\Minidump\*.dmp near each reboot
      * WHEA-Logger          : hardware error events (bad RAM/PSU/CPU/PCIe)

    Per Event 41 it prints a VERDICT:
      crash (bugcheck)  -> driver/hardware/software crash  (see dump)
      power-button      -> someone held the power button    (hard power-off)
      power-loss/reset  -> dirty power removal / hard reset  (no bugcheck, no button)
      unknown           -> insufficient data

    ASCII-only (safe for Windows PowerShell 5.1). Read-only. Run elevated.

.PARAMETER Days
    How many days back (default 14).

.PARAMETER OutFile
    Optional JSONL output (Guard alerts schema).

.EXAMPLE
    .\reboot-cause.ps1 -Days 30
#>

[CmdletBinding()]
param(
    [int]$Days = 14,
    [string]$OutFile
)

$ErrorActionPreference = 'Stop'
$since = (Get-Date).AddDays(-$Days)

function Get-Data {
    param($EventRecord, [string]$Name)
    try {
        $xml = [xml]$EventRecord.ToXml()
        $node = $xml.Event.EventData.Data | Where-Object { $_.Name -eq $Name }
        if ($node) { return $node.'#text' }
    } catch {}
    return $null
}

Write-Host "Guard reboot root-cause analysis - last $Days day(s), since $since" -ForegroundColor Cyan
Write-Host ("=" * 78)

# ---- 1. Collect Event 41 (unexpected reboot) --------------------------------
$e41 = @()
try {
    $e41 = @(Get-WinEvent -FilterHashtable @{ LogName='System'; Id=41; StartTime=$since } -ErrorAction Stop |
            Sort-Object TimeCreated)
} catch {
    if ($_.Exception.Message -match 'No events were found') {
        Write-Host "No unexpected (Event 41) reboots in the window - good." -ForegroundColor Green
        return
    }
    throw
}

# ---- 2. Collect corroborating sources ---------------------------------------
$bugchecks = @()
try {
    $bugchecks = @(Get-WinEvent -FilterHashtable @{ LogName='System'; Id=1001;
                    ProviderName='Microsoft-Windows-WER-SystemErrorReporting'; StartTime=$since } -ErrorAction Stop)
} catch {}

$whea = @()
try {
    $whea = @(Get-WinEvent -FilterHashtable @{ LogName='System';
               ProviderName='Microsoft-Windows-WHEA-Logger'; StartTime=$since } -ErrorAction Stop)
} catch {}

$dumps = @()
try {
    $dumps = @(Get-ChildItem -Path "$env:SystemRoot\Minidump\*.dmp" -ErrorAction Stop |
               Where-Object { $_.LastWriteTime -ge $since })
    $memDump = Get-Item "$env:SystemRoot\MEMORY.DMP" -ErrorAction SilentlyContinue
    if ($memDump -and $memDump.LastWriteTime -ge $since) { $dumps += $memDump }
} catch {}

Write-Host ("Found {0} Event-41, {1} bugcheck(1001), {2} WHEA, {3} recent minidump(s)." -f `
    $e41.Count, $bugchecks.Count, $whea.Count, $dumps.Count)

# ---- 3. Analyze each Event 41 -----------------------------------------------
$results = foreach ($e in $e41) {
    $bcCode = Get-Data $e 'BugcheckCode'
    $pbTs   = Get-Data $e 'PowerButtonTimestamp'
    $bcCodeInt = 0; [int64]$bcCodeInt = 0
    [void][int64]::TryParse(("" + $bcCode), [ref]$bcCodeInt)
    $pbInt = 0; [void][int64]::TryParse(("" + $pbTs), [ref]$pbInt)

    # nearest bugcheck / dump within 5 minutes of this reboot
    $nearBc = $bugchecks | Where-Object { [math]::Abs(($_.TimeCreated - $e.TimeCreated).TotalMinutes) -le 5 } | Select-Object -First 1
    $nearDump = $dumps | Where-Object { [math]::Abs(($_.LastWriteTime - $e.TimeCreated).TotalMinutes) -le 10 } | Select-Object -First 1
    $nearWhea = $whea | Where-Object { [math]::Abs(($_.TimeCreated - $e.TimeCreated).TotalMinutes) -le 10 } | Select-Object -First 1

    if ($bcCodeInt -ne 0 -or $nearBc -or $nearDump) {
        $verdict = 'crash (bugcheck)'
        $detail  = if ($nearBc) { ($nearBc.Message -replace '\s+',' ').Trim() }
                   elseif ($nearDump) { "dump: $($nearDump.FullName)" }
                   else { "BugcheckCode=$bcCode" }
    } elseif ($pbInt -ne 0) {
        $verdict = 'power-button (hard off)'
        $detail  = "PowerButtonTimestamp=$pbTs"
    } else {
        $verdict = 'power-loss / hard-reset'
        $detail  = 'no bugcheck, no power-button, no dump -> dirty power removal or forced reset'
    }
    if ($nearWhea) { $detail += " | WHEA hardware error near this time" }

    [pscustomobject]@{
        Time       = $e.TimeCreated
        Verdict    = $verdict
        BugcheckCode = $bcCode
        Dump       = if ($nearDump) { $nearDump.Name } else { '' }
        WHEA       = [bool]$nearWhea
        Detail     = $detail
    }
}

Write-Host "`nUnexpected-reboot causes:" -ForegroundColor Cyan
$results | Format-Table Time, Verdict, BugcheckCode, Dump, WHEA -AutoSize | Out-String -Width 200 | Write-Host

# ---- 4. Verdict rollup ------------------------------------------------------
$byVerdict = $results | Group-Object Verdict | Sort-Object Count -Descending
Write-Host "Cause breakdown:" -ForegroundColor Cyan
foreach ($g in $byVerdict) { Write-Host ("  {0,-26} {1}" -f $g.Name, $g.Count) }

Write-Host "`nInterpretation:" -ForegroundColor Yellow
if ($byVerdict | Where-Object { $_.Name -like 'crash*' }) {
    Write-Host "  - CRASH reboots present: driver/hardware/software fault. Analyze the .dmp"
    Write-Host "    files (WinDbg '!analyze -v' or BlueScreenView) to name the faulting module."
}
if ($byVerdict | Where-Object { $_.Name -like 'power-loss*' }) {
    Write-Host "  - POWER-LOSS/RESET reboots: NO crash + NO clean shutdown. Causes to rule out,"
    Write-Host "    in order: failing PSU/battery, thermal shutdown, loose power, THEN a forced"
    Write-Host "    hard-reset (which malware CAN trigger). Correlate these timestamps with"
    Write-Host "    Sysmon process activity once Sysmon is deployed."
}
if ($results | Where-Object WHEA) {
    Write-Host "  - WHEA hardware errors near reboot(s): strong hardware-fault signal (RAM/CPU/PSU)."
}
if ($whea.Count -eq 0 -and -not ($byVerdict | Where-Object { $_.Name -like 'crash*' })) {
    Write-Host "  - No crashes, no dumps, no WHEA: reboots look like DIRTY POWER / HARD RESETS."
    Write-Host "    That is consistent with power/hardware OR a deliberate forced reboot; this data"
    Write-Host "    cannot distinguish them. Next: deploy Sysmon and watch for process-driven resets."
}

# ---- 5. Optional JSONL ------------------------------------------------------
if ($OutFile) {
    $dir = Split-Path -Parent $OutFile
    if ($dir -and -not (Test-Path $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
    $sw = New-Object System.IO.StreamWriter($OutFile, $false)
    try {
        foreach ($r in $results) {
            $sev = if ($r.Verdict -like 'crash*' -or $r.WHEA) { 'high' }
                   elseif ($r.Verdict -like 'power-loss*') { 'high' } else { 'info' }
            $obj = [ordered]@{
                ts       = $r.Time.ToUniversalTime().ToString('o')
                kind     = 'win:reboot_cause'
                rule     = 'win.unexpected_reboot_cause'
                severity = $sev
                summary  = $r.Verdict
                evidence = [ordered]@{ bugcheck_code=$r.BugcheckCode; dump=$r.Dump; whea=$r.WHEA; detail=$r.Detail }
            }
            $sw.WriteLine(($obj | ConvertTo-Json -Compress -Depth 5))
        }
    } finally { $sw.Close() }
    Write-Host "`nJSONL written -> $OutFile" -ForegroundColor Green
}
