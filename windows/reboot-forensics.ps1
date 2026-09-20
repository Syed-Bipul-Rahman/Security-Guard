<#
.SYNOPSIS
    Guard reboot forensics - answer "who/what is rebooting these machines?"

.DESCRIPTION
    Run this NOW on an affected Windows workstation (no agent required). It pulls
    reboot/shutdown history from the System log and reports, per event:
      * when
      * event id + meaning
      * the INITIATING process (for 1074) and user
      * the reason / comment
      * whether it was planned or unexpected

    Then it flags BURSTS (2+ reboots within a window, default 3h) and highlights
    reboots during working hours - the pattern seen in the incident.

    Event IDs collected (System log):
      1074  planned shutdown/restart initiated (records the process + user + reason)
      1075  shutdown initiated by remote failure
      41    Kernel-Power: rebooted without a clean shutdown (UNEXPECTED)
      6008  the previous shutdown was unexpected
      6006  event log stopped  (clean shutdown marker)
      6005  event log started  (boot marker)

    If Sysmon is installed, it ALSO cross-references Sysmon ProcessCreate (ID 1)
    for shutdown.exe to attribute the culprit reliably.

.PARAMETER Days
    How many days back to search (default 14).

.PARAMETER OutFile
    Optional path to write JSONL (same schema as Guard alerts.jsonl).

.PARAMETER BurstWindowMinutes
    Reboots within this window count toward a burst (default 180 = 3h).

.PARAMETER BurstCount
    Number of reboots within the window to flag as a burst (default 2).

.PARAMETER WorkHourStart / WorkHourEnd
    Local hours (0-23) considered "working hours" for highlighting (default 9..19).

.EXAMPLE
    .\reboot-forensics.ps1 -Days 30 -OutFile $env:USERPROFILE\.guard\reboot-forensics.jsonl

.NOTES
    Read-only. Run in an elevated PowerShell for full access to the System log.
#>

[CmdletBinding()]
param(
    [int]$Days = 14,
    [string]$OutFile,
    [int]$BurstWindowMinutes = 180,
    [int]$BurstCount = 2,
    [int]$WorkHourStart = 9,
    [int]$WorkHourEnd = 19
)

$ErrorActionPreference = 'Stop'
$since = (Get-Date).AddDays(-$Days)
$targetIds = 1074, 1075, 41, 6008, 6006, 6005

function Get-Prop {
    param($EventRecord, [int]$Index)
    try { return $EventRecord.Properties[$Index].Value } catch { return $null }
}

Write-Host "Guard reboot forensics - last $Days day(s), since $since" -ForegroundColor Cyan
Write-Host ("=" * 78)

# ---- 1. Pull raw events -----------------------------------------------------
$filter = @{ LogName = 'System'; Id = $targetIds; StartTime = $since }
try {
    $events = Get-WinEvent -FilterHashtable $filter -ErrorAction Stop |
              Sort-Object TimeCreated
} catch {
    if ($_.Exception.Message -match 'No events were found') {
        Write-Host "No reboot/shutdown events in the window." -ForegroundColor Green
        return
    }
    throw
}

# ---- 2. Normalize -----------------------------------------------------------
$records = foreach ($e in $events) {
    $rec = [ordered]@{
        Time        = $e.TimeCreated
        EventId     = $e.Id
        Meaning     = switch ($e.Id) {
            1074 { 'Planned shutdown/restart initiated' }
            1075 { 'Shutdown initiated by remote failure' }
            41   { 'Kernel-Power: UNEXPECTED reboot (no clean shutdown)' }
            6008 { 'Previous shutdown was UNEXPECTED' }
            6006 { 'Event log stopped (clean shutdown)' }
            6005 { 'Event log started (boot)' }
            default { "Event $($e.Id)" }
        }
        Initiator   = $null
        User        = $null
        Reason      = $null
        ShutdownType= $null
        Comment     = $null
        Unexpected  = ($e.Id -in 41, 6008, 1075)
        Message     = ($e.Message -replace '\s+', ' ').Trim()
    }
    if ($e.Id -eq 1074) {
        # 1074 insertion strings (order is stable on Win10/11):
        #  [0]=process  [2]=reason text  [3]=reason code  [4]=shutdown type  [5]=comment  [6]=user
        $rec.Initiator    = Get-Prop $e 0
        $rec.Reason       = Get-Prop $e 2
        $rec.ShutdownType = Get-Prop $e 4
        $rec.Comment      = Get-Prop $e 5
        $rec.User         = Get-Prop $e 6
    }
    [pscustomobject]$rec
}

# ---- 3. Sysmon cross-reference (if present) ---------------------------------
$sysmonShutdowns = @()
try {
    $sysmonShutdowns = Get-WinEvent -FilterHashtable @{
        LogName = 'Microsoft-Windows-Sysmon/Operational'; Id = 1; StartTime = $since
    } -ErrorAction Stop | Where-Object {
        $_.Message -match 'shutdown\.exe' -or $_.Message -match 'InitiateSystemShutdown'
    } | ForEach-Object {
        [pscustomobject]@{
            Time    = $_.TimeCreated
            Line    = (($_.Message -split "`n" | Where-Object { $_ -match 'CommandLine|ParentImage|User' }) -join ' | ')
        }
    }
    if ($sysmonShutdowns) {
        Write-Host "`nSysmon shutdown.exe launches (culprit attribution):" -ForegroundColor Yellow
        $sysmonShutdowns | Format-Table -AutoSize | Out-String | Write-Host
    }
} catch {
    Write-Host "`n(Sysmon log not present - install sysmon-config.xml for reliable initiator attribution.)" -ForegroundColor DarkGray
}

# ---- 4. Reboot timeline -----------------------------------------------------
Write-Host "`nReboot / shutdown timeline:" -ForegroundColor Cyan
$records | Select-Object Time, EventId, Meaning, Initiator, User, Reason, Comment |
    Format-Table -AutoSize | Out-String -Width 200 | Write-Host

# ---- 5. Burst detection (the incident pattern) ------------------------------
# Count only actual reboot-causing events: 1074 (planned) + 41 (unexpected).
# @() forces arrays so .Count is always valid (even for 0 or 1 element).
$reboots = @($records | Where-Object { $_.EventId -in 1074, 41 } | Sort-Object Time)
$burstAlerts = @()
for ($i = 0; $i -lt $reboots.Count; $i++) {
    $windowEnd = $reboots[$i].Time.AddMinutes($BurstWindowMinutes)
    $inWindow = @($reboots | Where-Object { $_.Time -ge $reboots[$i].Time -and $_.Time -le $windowEnd })
    if ($inWindow.Count -ge $BurstCount) {
        $hour = $reboots[$i].Time.Hour
        $inWorkHours = ($hour -ge $WorkHourStart -and $hour -lt $WorkHourEnd)
        $initiators = @($inWindow | ForEach-Object { $_.Initiator } | Where-Object { $_ } | Select-Object -Unique)
        $burstAlerts += [pscustomobject]@{
            Start       = $reboots[$i].Time
            Count       = $inWindow.Count
            WindowMin   = $BurstWindowMinutes
            WorkHours   = $inWorkHours
            Initiators  = ($initiators -join ', ')
        }
    }
}
# de-dupe overlapping bursts by start bucket
$burstAlerts = @($burstAlerts | Sort-Object Start -Unique)

if ($burstAlerts) {
    Write-Host "`n*** REBOOT BURSTS DETECTED (>= $BurstCount within $BurstWindowMinutes min) ***" -ForegroundColor Red
    $burstAlerts | Format-Table -AutoSize | Out-String | Write-Host
} else {
    Write-Host "`nNo reboot bursts in the window." -ForegroundColor Green
}

# ---- 6. Summary -------------------------------------------------------------
$planned    = @($records | Where-Object { $_.EventId -eq 1074 }).Count
$unexpected = @($records | Where-Object { $_.EventId -in 41, 6008 }).Count
Write-Host "`nSummary:" -ForegroundColor Cyan
Write-Host ("  Planned restarts (1074) : {0}" -f $planned)
Write-Host ("  Unexpected reboots (41/6008): {0}" -f $unexpected)
Write-Host ("  Bursts flagged          : {0}" -f $burstAlerts.Count)
if ($unexpected -gt 0) {
    Write-Host "  -> Unexpected reboots present: investigate power/driver/malware-forced restarts." -ForegroundColor Yellow
}

# ---- 7. Optional JSONL output (Guard alerts schema) -------------------------
if ($OutFile) {
    $dir = Split-Path -Parent $OutFile
    if ($dir -and -not (Test-Path $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
    $sw = New-Object System.IO.StreamWriter($OutFile, $false)
    try {
        foreach ($r in $records) {
            $obj = [ordered]@{
                ts        = $r.Time.ToUniversalTime().ToString('o')
                kind      = 'win:reboot'
                rule      = if ($r.Unexpected) { 'win.unexpected_reboot' } elseif ($r.EventId -eq 1074) { 'win.forced_reboot' } else { 'win.reboot_event' }
                severity  = if ($r.Unexpected) { 'high' } else { 'info' }
                summary   = $r.Meaning
                evidence  = [ordered]@{
                    event_id = $r.EventId; initiator = $r.Initiator; user = $r.User
                    reason = $r.Reason; comment = $r.Comment
                }
            }
            $sw.WriteLine(($obj | ConvertTo-Json -Compress -Depth 5))
        }
        foreach ($b in $burstAlerts) {
            $obj = [ordered]@{
                ts       = $b.Start.ToUniversalTime().ToString('o')
                kind     = 'win:reboot'
                rule     = 'win.reboot_burst'
                severity = 'critical'
                summary  = "$($b.Count) reboots within $($b.WindowMin) min$(if($b.WorkHours){' during work hours'})"
                evidence = [ordered]@{ count = $b.Count; work_hours = $b.WorkHours; initiators = $b.Initiators }
            }
            $sw.WriteLine(($obj | ConvertTo-Json -Compress -Depth 5))
        }
    } finally { $sw.Close() }
    Write-Host "`nJSONL written -> $OutFile" -ForegroundColor Green
}
