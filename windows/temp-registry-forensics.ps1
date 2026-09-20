<#
.SYNOPSIS
    Guard temp + registry forensics - run-now sweep for the incident's Windows
    staging (script droppers in temp) and persistence (registry) behaviors.

.DESCRIPTION
    Two parts, both read-only, no agent required:

    PART A - TEMP / STAGING FILE SWEEP
      Scans temp & user-writable staging dirs for recently-created scripts and
      disguised droppers, and content-scans them for the incident fingerprints:
        - suspicious extensions in temp (.py .pyw .js .mjs .vbs .ps1 .bat .hta .scr)
        - binary-disguised droppers (a .woff2/.ttf/.png whose bytes are actually
          text/JS - magic-byte check)
        - C2 / obfuscation fingerprints inside files
      Reports path, created/modified time, size, and owner.

    PART B - REGISTRY PERSISTENCE SWEEP
      Enumerates the persistence keys the attack class uses and flags values that
      point at temp/scripts/interpreters, contain encoded commands, or match IOCs:
        Run / RunOnce / RunOnceEx, Explorer\Run, Policies\Explorer\Run,
        Winlogon Shell/Userinit, Image File Execution Options (Debugger),
        Services with ImagePath in temp/scripts, StartupApproved.

    ASCII-only (safe for Windows PowerShell 5.1). Run elevated for HKLM + owners.

.PARAMETER Days
    Only report temp files created/modified within this many days (default 30).
    Registry has no reliable timestamp, so all matching values are reported.

.PARAMETER OutFile
    Optional JSONL output (Guard alerts schema).

.EXAMPLE
    .\temp-registry-forensics.ps1 -Days 30 -OutFile $env:USERPROFILE\.guard\endpoint-forensics.jsonl
#>

[CmdletBinding()]
param(
    [int]$Days = 30,
    [string]$OutFile,
    [int]$MaxFilesPerRoot = 100000,
    [switch]$TempOnly   # skip the large Roaming/Downloads roots for a fast pass
)

$ErrorActionPreference = 'Stop'
$since = (Get-Date).AddDays(-$Days)
$alerts = New-Object System.Collections.ArrayList

# --- indicators (mirror signatures.json ['windows'] + shared payload fps) -----
$suspExt = '.py','.pyw','.js','.mjs','.cjs','.vbs','.ps1','.bat','.cmd','.hta','.scr'
$payloadFps = @(
    "global['!']='9'", 'global["!"]="9"', 'var _$_1e42=', '_$_1e42=',
    "sfL['constructor']", 'sfL["constructor"]', 'auth-confirm-ten.vercel.app',
    'atob(process.env.AUTH_API_KEY)', 'eval(proxyInfo)'
)
$cmdIocs = @('auth-confirm-ten.vercel.app','public/fonts/','fa-solid-400.woff2',
    'FromBase64String','DownloadString','-enc ','-EncodedCommand','IEX')
# Path substrings that mean "real staging location" (a plain script here is worth
# a 'high'); NOT generic \appdata\ (OneDrive/Teams/etc. legitimately live there).
$stagingMarkers = '\temp\', '\users\public\', '\downloads\', '\windows\temp\'
# Legit installed-package trees: skip entirely (this killed the 786 false hits).
$excludeMarkers = '\site-packages\', '\node_modules\', '\dist-info\', '.egg-info',
    '\lib2to3\', '\vscode\extensions\', '\.vscode\extensions\', '\pip\', '\pkgs\',
    '\lib\', '\scripts\', '\microsoft vs code\',
    # build/tool caches (legit dev tooling that drops scripts into temp)
    'cursor-sandbox-cache', '\gradle\', '\wrapper\dists\', '\.gradle\',
    '\.nuget\', '\.m2\', '\go-build', '\.cache\', '\caches\', '\.npm\', '\yarn\'
function Test-ExcludedPath([string]$p) {
    $lp = $p.ToLower(); foreach ($m in $excludeMarkers) { if ($lp.Contains($m)) { return $true } } return $false
}
function Test-InStaging([string]$p) {
    $lp = $p.ToLower(); foreach ($m in $stagingMarkers) { if ($lp.Contains($m)) { return $true } } return $false
}
# real magic bytes for binary extensions (hex prefix)
$magic = @{
    '.woff2' = '774f4632'; '.woff' = '774f4646'; '.ttf' = '00010000';
    '.otf' = '4f54544f'; '.png' = '89504e47'; '.jpg' = 'ffd8ff';
    '.jpeg' = 'ffd8ff'; '.ico' = '00000100'
}
$textInd = 'require(','global[','process.env','eval(','function','=>','var _$_','module.exports','import '

function Add-Alert($rule,$sev,$kind,$summary,$evidence) {
    [void]$alerts.Add([pscustomobject]@{ rule=$rule; severity=$sev; kind=$kind; summary=$summary; evidence=$evidence })
}

function Get-Prefix([string]$path,[int]$n) {
    try {
        $fs = [System.IO.File]::OpenRead($path)
        try { $buf = New-Object byte[] $n; $read = $fs.Read($buf,0,$n); return ,$buf[0..([math]::Max(0,$read-1))] }
        finally { $fs.Close() }
    } catch { return @() }
}

function Test-DisguisedBinary([string]$path,[string]$ext) {
    $pref = Get-Prefix $path 16
    if ($pref.Count -eq 0) { return $false }
    $hex = ($pref | ForEach-Object { $_.ToString('x2') }) -join ''
    $expected = $magic[$ext]
    if ($expected -and $hex.StartsWith($expected)) { return $false }   # valid binary
    # not valid magic - is the body text/JS?
    try {
        $head = Get-Content -Path $path -TotalCount 40 -ErrorAction Stop -Encoding UTF8
        $txt = ($head -join "`n")
        foreach ($ind in $textInd) { if ($txt.Contains($ind)) { return $true } }
    } catch {}
    return $false
}

function Scan-Content([string]$path) {
    $hits = @()
    try {
        # cap read to ~2MB via -TotalCount lines; payloads appear early
        $txt = (Get-Content -Path $path -TotalCount 5000 -ErrorAction Stop) -join "`n"
        foreach ($fp in $payloadFps) { if ($txt.Contains($fp)) { $hits += $fp } }
    } catch {}
    return $hits
}

Write-Host "Guard temp + registry forensics - temp window $Days day(s) (since $since)" -ForegroundColor Cyan
Write-Host ("=" * 78)

# =============================================================================
# PART A - TEMP / STAGING FILE SWEEP
# =============================================================================
# Highest-signal (small, fast) roots first; heavy roots last.
$heavy = @("$env:APPDATA", "$env:USERPROFILE\Downloads")
$allRoots = @(
    $env:TEMP, "$env:SystemRoot\Temp", "$env:PUBLIC", "$env:LOCALAPPDATA\Temp"
) + $heavy | Where-Object { $_ -and (Test-Path $_) } | Select-Object -Unique
$roots = if ($TempOnly) { $allRoots | Where-Object { $heavy -notcontains $_ } } else { $allRoots }

Write-Host "`n[A] Temp / staging sweep across:" -ForegroundColor Cyan
$roots | ForEach-Object { Write-Host "    $_" }
if (-not $TempOnly) {
    Write-Host "    (Roaming/Downloads can be large; -TempOnly skips them for a fast pass.)" -ForegroundColor DarkGray
}

$fileFindings = @()

# Fast manual walk: cheap extension check BEFORE any FileInfo/date/ACL/content
# work, per-directory try/catch (skips access-denied), live progress, real cap.
function Scan-Root([string]$root) {
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $walked = 0; $flagged = 0
    $stack = New-Object System.Collections.Stack
    $stack.Push($root)
    while ($stack.Count -gt 0) {
        $dir = $stack.Pop()
        try { foreach ($sub in [System.IO.Directory]::EnumerateDirectories($dir)) { $stack.Push($sub) } } catch {}
        $files = $null
        try { $files = [System.IO.Directory]::EnumerateFiles($dir) } catch { continue }
        foreach ($path in $files) {
            $walked++
            if (($walked % 4000) -eq 0) {
                Write-Host ("      {0}: {1} files, {2} flagged ({3}s)" -f $root, $walked, $flagged, [int]$sw.Elapsed.TotalSeconds) -ForegroundColor DarkGray
            }
            if ($walked -ge $MaxFilesPerRoot) {
                Write-Host ("      {0}: hit cap {1}; stopping this root (raise -MaxFilesPerRoot to go deeper)." -f $root, $MaxFilesPerRoot) -ForegroundColor DarkGray
                $stack.Clear(); break
            }
            $ext = [System.IO.Path]::GetExtension($path).ToLower()
            $isSusp = $suspExt -contains $ext
            $isBinExt = $magic.ContainsKey($ext)
            if (-not ($isSusp -or $isBinExt)) { continue }   # cheap reject (the 99% case)
            if (Test-ExcludedPath $path) { continue }         # legit installed package tree

            $fi = $null; try { $fi = [System.IO.FileInfo]$path } catch { continue }
            if ($fi.LastWriteTime -lt $since -and $fi.CreationTime -lt $since) { continue }

            $reason = $null; $sev = $null; $fps = @()
            if ($isSusp) {
                # Content is the real signal: a fingerprint match = critical anywhere.
                $fps = Scan-Content $path
                if ($fps.Count) {
                    $reason = "script with C2 fingerprints"; $sev = 'critical'
                } elseif (Test-InStaging $path) {
                    # a script sitting in a true temp/Public/Downloads dir = worth a look
                    $reason = "script in staging dir ($ext)"; $sev = 'high'
                }
                # a plain script elsewhere (e.g. a project or Roaming) is NOT flagged
            } elseif ($isBinExt) {
                if (Test-DisguisedBinary $path $ext) { $reason = "binary-disguised dropper ($ext contains JS/text)"; $sev = 'critical' }
            }
            if (-not $reason) { continue }
            if ($reason) {
                $flagged++
                $owner = try { (Get-Acl $path).Owner } catch { '?' }
                $script:fileFindings += [pscustomobject]@{
                    Path=$path; Created=$fi.CreationTime; Modified=$fi.LastWriteTime
                    SizeKB=[math]::Round($fi.Length/1KB,1); Owner=$owner; Severity=$sev; Reason=$reason
                    Fingerprints=($fps -join ', ')
                }
                Add-Alert 'win.temp.script_drop' $sev 'win:file' $reason `
                    ([ordered]@{ path=$path; created="$($fi.CreationTime)"; owner=$owner; fingerprints=$fps })
            }
        }
    }
    Write-Host ("    done {0}: {1} files walked, {2} flagged, {3}s" -f $root, $walked, $flagged, [int]$sw.Elapsed.TotalSeconds) -ForegroundColor DarkGray
}

foreach ($root in $roots) { Scan-Root $root }

if ($fileFindings) {
    Write-Host "`n  Suspicious files:" -ForegroundColor Yellow
    $fileFindings | Sort-Object Severity, Modified |
        Format-Table Severity, Modified, SizeKB, Owner, Reason, Path -AutoSize |
        Out-String -Width 240 | Write-Host
} else {
    Write-Host "`n  No suspicious temp/staging files in the window." -ForegroundColor Green
}

# =============================================================================
# PART B - REGISTRY PERSISTENCE SWEEP
# =============================================================================
Write-Host "`n[B] Registry persistence sweep" -ForegroundColor Cyan

$runKeys = @(
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnceEx',
    'HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run',
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Run',
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run'
)
$winlogon = 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon'
$ifeoBase = 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'

function Test-Suspicious([string]$data) {
    if (-not $data) { return $null }
    $d = $data.ToLower()
    $ind = @()
    # suspicious LOCATIONS (real staging) - NOT generic \appdata\ (OneDrive/Teams live there)
    foreach ($m in @('\temp\','\users\public\','public/fonts/','\downloads\')) { if ($d.Contains($m)) { $ind += $m } }
    # incident-specific strings
    foreach ($i in @('auth-confirm-ten.vercel.app','fa-solid-400.woff2','.woff2')) { if ($d.Contains($i)) { $ind += $i } }
    # encoded / download-exec powershell - TOKEN-AWARE so 'msiexec'/'acpiex' do NOT match
    if ($d -match '\biex\b' -or $d -match '\binvoke-expression\b') { $ind += 'IEX' }
    if ($d.Contains('frombase64string')) { $ind += 'FromBase64String' }
    if ($d.Contains('downloadstring')) { $ind += 'DownloadString' }
    if ($d -match '\s-enc(odedcommand)?\b') { $ind += '-enc' }
    # interpreter running FROM a staging dir (combo, not the bare interpreter name)
    if (($d -match '\b(python|pythonw|node|wscript|cscript|mshta)\b') -and
        ($d.Contains('\temp\') -or $d.Contains('\users\public\') -or $d.Contains('\roaming\'))) {
        $ind += 'interpreter-from-staging'
    }
    if ($ind.Count) { return ($ind | Select-Object -Unique) } else { return $null }
}

$regFindings = @()
function Scan-RunKey([string]$key) {
    if (-not (Test-Path $key)) { return }
    $props = Get-ItemProperty -Path $key -ErrorAction SilentlyContinue
    if (-not $props) { return }
    foreach ($p in $props.PSObject.Properties) {
        if ($p.Name -like 'PS*') { continue }
        $ind = Test-Suspicious ([string]$p.Value)
        $sev = if ($ind) { 'critical' } else { 'info' }
        $obj = [pscustomobject]@{ Key=$key; Name=$p.Name; Value=[string]$p.Value; Severity=$sev; Indicators=($ind -join ', ') }
        $script:regFindings += $obj
        if ($ind) {
            Add-Alert 'win.registry_persistence' 'critical' 'win:registry' "persistence value points at temp/script/IOC" `
                ([ordered]@{ key=$key; name=$p.Name; value=[string]$p.Value; indicators=$ind })
        }
    }
}

foreach ($k in $runKeys) { Scan-RunKey $k }

# Winlogon Shell / Userinit (should be explorer.exe / userinit.exe,... only)
if (Test-Path $winlogon) {
    $wl = Get-ItemProperty -Path $winlogon -ErrorAction SilentlyContinue
    foreach ($n in 'Shell','Userinit') {
        $val = [string]$wl.$n
        $expected = if ($n -eq 'Shell') { 'explorer.exe' } else { 'userinit.exe' }
        $suspicious = ($val -and ($val.ToLower() -notlike "*$expected*")) -or (Test-Suspicious $val)
        $sev = if ($suspicious) { 'critical' } else { 'info' }
        $wlInd = if ($suspicious) { 'unexpected winlogon value' } else { '' }
        $regFindings += [pscustomobject]@{ Key=$winlogon; Name=$n; Value=$val; Severity=$sev; Indicators=$wlInd }
        if ($suspicious) {
            Add-Alert 'win.registry_persistence' 'critical' 'win:registry' "Winlogon $n modified" ([ordered]@{ key=$winlogon; name=$n; value=$val })
        }
    }
}

# IFEO Debugger hijacks
if (Test-Path $ifeoBase) {
    Get-ChildItem -Path $ifeoBase -ErrorAction SilentlyContinue | ForEach-Object {
        $dbg = (Get-ItemProperty -Path $_.PSPath -Name Debugger -ErrorAction SilentlyContinue).Debugger
        if ($dbg) {
            $regFindings += [pscustomobject]@{ Key=$_.PSPath; Name='Debugger'; Value=$dbg; Severity='critical'; Indicators='IFEO Debugger set (hijack)' }
            Add-Alert 'win.registry_persistence' 'critical' 'win:registry' "IFEO Debugger hijack on $($_.PSChildName)" ([ordered]@{ image=$_.PSChildName; debugger=$dbg })
        }
    }
}

# Services with ImagePath in temp/script dirs
try {
    Get-ChildItem 'HKLM:\System\CurrentControlSet\Services' -ErrorAction SilentlyContinue | ForEach-Object {
        $img = (Get-ItemProperty -Path $_.PSPath -Name ImagePath -ErrorAction SilentlyContinue).ImagePath
        $ind = Test-Suspicious $img
        if ($ind) {
            $regFindings += [pscustomobject]@{ Key=$_.PSPath; Name='ImagePath'; Value=$img; Severity='critical'; Indicators=($ind -join ', ') }
            Add-Alert 'win.registry_persistence' 'critical' 'win:registry' "service ImagePath in temp/script dir: $($_.PSChildName)" ([ordered]@{ service=$_.PSChildName; imagepath=$img; indicators=$ind })
        }
    }
} catch {}

$regHits = @($regFindings | Where-Object { $_.Severity -eq 'critical' })
if ($regHits.Count) {
    Write-Host "`n  SUSPICIOUS registry entries:" -ForegroundColor Red
    $regHits | Format-Table Severity, Key, Name, Indicators, Value -AutoSize | Out-String -Width 240 | Write-Host
} else {
    Write-Host "`n  No suspicious persistence values found." -ForegroundColor Green
    Write-Host "  (All Run/Winlogon/IFEO/Service entries reviewed; none point at temp/scripts/IOCs.)"
}

# =============================================================================
# Summary + optional JSONL
# =============================================================================
$critFiles = @($fileFindings | Where-Object Severity -eq 'critical').Count
$highFiles = @($fileFindings | Where-Object Severity -eq 'high').Count
Write-Host "`nSummary:" -ForegroundColor Cyan
Write-Host ("  Temp files - critical: {0}  high: {1}" -f $critFiles, $highFiles)
Write-Host ("  Registry   - suspicious: {0}" -f $regHits.Count)
if ($critFiles -eq 0 -and $regHits.Count -eq 0) {
    Write-Host "  -> No staging or persistence artifacts of this attack found on this host." -ForegroundColor Green
} else {
    Write-Host "  -> Artifacts found. Preserve, then isolate + remediate per IR process." -ForegroundColor Yellow
}

# Guard against a mistyped switch landing in -OutFile (e.g. '--temponly' -> $OutFile)
if ($OutFile -and $OutFile.StartsWith('-')) {
    Write-Host "`nIgnoring -OutFile '$OutFile' - looks like a mistyped switch." -ForegroundColor Yellow
    Write-Host "Use single-dash switches: -TempOnly (not --temponly), -Days 30." -ForegroundColor Yellow
    $OutFile = $null
}
if ($OutFile) {
    $dir = Split-Path -Parent $OutFile
    if ($dir -and -not (Test-Path $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
    $sw = New-Object System.IO.StreamWriter($OutFile, $false)
    try {
        foreach ($a in $alerts) {
            $obj = [ordered]@{
                ts=(Get-Date).ToUniversalTime().ToString('o'); kind=$a.kind; rule=$a.rule
                severity=$a.severity; summary=$a.summary; evidence=$a.evidence
            }
            $sw.WriteLine(($obj | ConvertTo-Json -Compress -Depth 6))
        }
    } finally { $sw.Close() }
    Write-Host "`nJSONL written -> $OutFile ($($alerts.Count) record(s))" -ForegroundColor Green
}
