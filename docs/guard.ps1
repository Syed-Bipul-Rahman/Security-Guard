# Guard installer (Windows). Served at https://security.sparktech.agency/guard.ps1
#   Run in an ELEVATED PowerShell (Admin):
#     irm https://security.sparktech.agency/guard.ps1 | iex
#
# Downloads guard-windows-<arch>.exe from GitHub Releases, verifies its SHA-256,
# installs to C:\Program Files\Guard, adds it to PATH, and registers an auto-start
# scheduled task that runs `guard watch`. HTTPS only. ASCII-only for PS 5.1.

$ErrorActionPreference = 'Stop'
$Releases   = if ($env:GUARD_BASE_URL) { $env:GUARD_BASE_URL } else { 'https://github.com/Syed-Bipul-Rahman/Security-Guard/releases/latest/download' }
$InstallDir = 'C:\Program Files\Guard'
$Bin        = Join-Path $InstallDir 'guard.exe'

# require elevation (installs to Program Files + registers a task)
$admin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $admin) { Write-Error "Run this in an elevated PowerShell (Run as administrator)."; return }

# detect arch -> asset name
$arch = switch ($env:PROCESSOR_ARCHITECTURE) {
  'AMD64' { 'x64' } 'ARM64' { 'arm64' } 'x86' { 'x64' } default { 'x64' }
}
$asset = "guard-windows-$arch.exe"
Write-Host "Guard installer: windows-$arch"

New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
$tmp = Join-Path $env:TEMP $asset
Write-Host "Downloading $asset ..."
Invoke-WebRequest -Uri "$Releases/$asset" -OutFile $tmp -UseBasicParsing

# verify checksum (fail closed). Download the .sha256 to a file and read it as text:
# GitHub serves release assets as octet-stream, so Invoke-WebRequest's .Content is a
# byte[] and calling .Trim() on it throws. -OutFile avoids that.
$want = $null
try {
  $shaFile = "$tmp.sha256"
  Invoke-WebRequest -Uri "$Releases/$asset.sha256" -OutFile $shaFile -UseBasicParsing
  $want = ((Get-Content $shaFile -Raw).Trim() -split '\s+')[0]
  Remove-Item $shaFile -Force -ErrorAction SilentlyContinue
} catch { $want = $null }
if (-not $want) { Remove-Item $tmp -Force; Write-Error "No checksum published for $asset - refusing to install unverified binary."; return }
$have = (Get-FileHash -Path $tmp -Algorithm SHA256).Hash.ToLower()
if ($want.ToLower() -ne $have) { Remove-Item $tmp -Force; Write-Error "CHECKSUM MISMATCH (want $want, got $have) - aborting."; return }
Write-Host "checksum OK"

# stop any running instance so guard.exe isn't locked (a reinstall over a running
# service would otherwise fail to overwrite the binary)
Stop-ScheduledTask -TaskName 'GuardWatcher' -ErrorAction SilentlyContinue | Out-Null
Get-Process -Name guard -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 1
if (Test-Path $Bin) { Remove-Item $Bin -Force -ErrorAction SilentlyContinue }
Move-Item -Force $tmp $Bin
Write-Host "installed: $Bin"

# add install dir to system PATH (idempotent)
$sysPath = [Environment]::GetEnvironmentVariable('Path','Machine')
if ($sysPath -notlike "*$InstallDir*") {
  [Environment]::SetEnvironmentVariable('Path', "$sysPath;$InstallDir", 'Machine')
  $env:Path = "$env:Path;$InstallDir"
}

# register auto-start task: `guard watch`, at startup + logon, highest privileges, keep-alive
$action    = New-ScheduledTaskAction -Execute $Bin -Argument 'watch'
$trigStart = New-ScheduledTaskTrigger -AtStartup
$trigLogon = New-ScheduledTaskTrigger -AtLogOn
$settings  = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
              -StartWhenAvailable -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1)
$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
Register-ScheduledTask -TaskName 'GuardWatcher' -Action $action -Trigger @($trigStart,$trigLogon) `
  -Settings $settings -Principal $principal -Force -Description 'Guard supply-chain watcher (auto-start, keep-alive)' | Out-Null
Start-ScheduledTask -TaskName 'GuardWatcher'

Write-Host ""
Write-Host "Done. Guard is installed and the GuardWatcher task is running."
Write-Host "Open a NEW terminal, then try:  guard version   |   guard scan .   |   guard triage"
Write-Host "Tip: also install Sysmon for kernel telemetry (see windows/sysmon-config.xml)."
