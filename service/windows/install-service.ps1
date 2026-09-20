# install-service.ps1 - register the Guard watcher on Windows.
#
# Two mechanisms (pick one):
#   1. Scheduled Task at logon (default here) - runs as the logged-in user, can
#      watch that user's dev folders. Survives restart (trigger = AtLogOn) and
#      restarts on failure.
#   2. Windows Service via New-Service / nssm - machine-wide, starts at boot.
#
# Run from an elevated PowerShell. Adjust $GuardApp / $Python to your install.

param(
    [string]$GuardApp  = "$env:USERPROFILE\.guard\app",
    [string]$GuardHome = "$env:USERPROFILE\.guard",
    [string]$Python    = "python"
)

$ErrorActionPreference = "Stop"
New-Item -ItemType Directory -Force -Path $GuardHome | Out-Null

$action  = New-ScheduledTaskAction -Execute $Python `
    -Argument "`"$GuardApp\watcher.py`""
$trigger = New-ScheduledTaskTrigger -AtLogOn
# Also trigger at startup so it runs before interactive login on shared machines:
$trigger2 = New-ScheduledTaskTrigger -AtStartup

$settings = New-ScheduledTaskSettingsSet `
    -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
    -StartWhenAvailable -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1)

$principal = New-ScheduledTaskPrincipal -UserId "$env:USERDOMAIN\$env:USERNAME" `
    -LogonType Interactive -RunLevel Highest

Register-ScheduledTask -TaskName "GuardWatcher" `
    -Action $action -Trigger @($trigger, $trigger2) `
    -Settings $settings -Principal $principal -Force `
    -Description "Guard supply-chain watcher (auto-start, keep-alive)"

# Set env vars the task inherits (machine scope; requires elevation)
[Environment]::SetEnvironmentVariable("GUARD_HOME", $GuardHome, "Machine")
[Environment]::SetEnvironmentVariable("GUARD_APP",  $GuardApp,  "Machine")

Write-Host "Registered scheduled task 'GuardWatcher' (AtLogOn + AtStartup, keep-alive)."
Write-Host "Start now with: Start-ScheduledTask -TaskName GuardWatcher"
