# install-service.ps1 - register the Guard watcher (or the Windows sensor) on Windows.
#
# Two mechanisms (pick one):
#   1. Scheduled Task at logon (default here) - runs as the logged-in user, can
#      watch that user's dev folders. Survives restart (trigger = AtLogOn) and
#      restarts on failure.
#   2. Windows Service via New-Service / nssm - machine-wide, starts at boot.
#
# Run from an elevated PowerShell. Adjust $Guard to your install. The usual
# install is docs/guard.ps1, which registers the watcher itself; use this for
# the Sysmon sensor:  .\install-service.ps1 -Command sensor

param(
    [string]$Guard     = "$env:USERPROFILE\.guard\bin\guard.exe",
    [string]$GuardHome = "$env:USERPROFILE\.guard",
    [ValidateSet("watch", "sensor")]
    [string]$Command   = "watch"
)

$ErrorActionPreference = "Stop"
New-Item -ItemType Directory -Force -Path $GuardHome | Out-Null

if ($Command -eq "sensor") {
    $TaskName = "GuardSensor"
    $Desc = "Guard Windows sensor: Sysmon + reboot events (auto-start, keep-alive)"
} else {
    $TaskName = "GuardWatcher"
    $Desc = "Guard supply-chain watcher (auto-start, keep-alive)"
}

$action  = New-ScheduledTaskAction -Execute $Guard -Argument $Command
$trigger = New-ScheduledTaskTrigger -AtLogOn
# Also trigger at startup so it runs before interactive login on shared machines:
$trigger2 = New-ScheduledTaskTrigger -AtStartup

$settings = New-ScheduledTaskSettingsSet `
    -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
    -StartWhenAvailable -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1)

$principal = New-ScheduledTaskPrincipal -UserId "$env:USERDOMAIN\$env:USERNAME" `
    -LogonType Interactive -RunLevel Highest

Register-ScheduledTask -TaskName $TaskName `
    -Action $action -Trigger @($trigger, $trigger2) `
    -Settings $settings -Principal $principal -Force `
    -Description $Desc

# Set the env var the task inherits (machine scope; requires elevation)
[Environment]::SetEnvironmentVariable("GUARD_HOME", $GuardHome, "Machine")

Write-Host "Registered scheduled task '$TaskName' (AtLogOn + AtStartup, keep-alive)."
Write-Host "Start now with: Start-ScheduledTask -TaskName $TaskName"
