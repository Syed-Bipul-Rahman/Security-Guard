<#
.SYNOPSIS
    Guard endpoint triage - ALL checks in one run, ONE report file per machine.

.DESCRIPTION
    Combines the three run-now IR scripts into a single sweep and writes the full
    output to one auto-named .txt (via transcript) so you can run it on each
    machine and collect one file per host:

        guard-triage_<COMPUTERNAME>_<timestamp>.txt

    Sections:
      1. Reboot timeline + who initiated + burst detection      (WHEN/WHO)
      2. Unexpected-reboot ROOT CAUSE  (crash vs power vs reset) (WHY)
      3. Temp / staging file sweep (script droppers, fake fonts) (behavior A)
      4. Registry persistence sweep (Run/Winlogon/IFEO/Services) (behavior B)
      5. Overall verdict per machine

    Read-only. ASCII-only (safe for Windows PowerShell 5.1). Run elevated.

.PARAMETER Days
    Look-back window in days (default 30).

.PARAMETER OutDir
    Where to write the report (default: your Desktop).

.PARAMETER TempOnly
    Skip the large Roaming/Downloads roots in the file sweep for a fast pass.

.PARAMETER Jsonl
    Also emit a machine-readable .jsonl next to the .txt.

.EXAMPLE
    .\guard-triage.ps1 -Days 30
    .\guard-triage.ps1 -Days 30 -TempOnly -OutDir C:\Guard\reports
#>

[CmdletBinding()]
param(
    [int]$Days = 30,
    [string]$OutDir = "$env:USERPROFILE\Desktop",
    [switch]$TempOnly,
    [switch]$Jsonl,
    [int]$MaxFilesPerRoot = 100000
)

# GUARD-IR-TOOLKIT-SELF : content marker so Guard's own scripts (which embed the
# fingerprint strings as detection data) are not flagged as malware by themselves.
$selfMarker = 'GUARD-IR-TOOLKIT-SELF'

$ErrorActionPreference = 'Stop'
$since = (Get-Date).AddDays(-$Days)
$stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
if (-not (Test-Path $OutDir)) { New-Item -ItemType Directory -Force -Path $OutDir | Out-Null }
$report = Join-Path $OutDir ("guard-triage_{0}_{1}.txt" -f $env:COMPUTERNAME, $stamp)
$jsonlPath = [System.IO.Path]::ChangeExtension($report, 'jsonl')
$alerts = New-Object System.Collections.ArrayList

# ---- shared indicators ------------------------------------------------------
$suspExt = '.py','.pyw','.js','.mjs','.cjs','.vbs','.ps1','.bat','.cmd','.hta','.scr'
$payloadFps = @(
    "global['!']='9'", 'global["!"]="9"', 'var _$_1e42=', '_$_1e42=',
    "sfL['constructor']", 'sfL["constructor"]', 'auth-confirm-ten.vercel.app',
    'atob(process.env.AUTH_API_KEY)', 'eval(proxyInfo)'
)
$magic = @{ '.woff2'='774f4632';'.woff'='774f4646';'.ttf'='00010000';'.otf'='4f54544f';
           '.png'='89504e47';'.jpg'='ffd8ff';'.jpeg'='ffd8ff';'.ico'='00000100' }
$textInd = 'require(','global[','process.env','eval(','function','=>','var _$_','module.exports','import '
$stagingMarkers = '\temp\', '\users\public\', '\downloads\', '\windows\temp\'
$excludeMarkers = '\site-packages\','\node_modules\','\dist-info\','.egg-info','\lib2to3\',
    '\vscode\extensions\','\.vscode\extensions\','\pip\','\pkgs\','\lib\','\scripts\',
    '\microsoft vs code\','cursor-sandbox-cache','\gradle\','\wrapper\dists\','\.gradle\',
    '\.nuget\','\.m2\','\go-build','\.cache\','\caches\','\.npm\','\yarn\',
    '.ts-node','ts-node-dev-hook','\.pytest_cache\','\__pycache__\'
$rebootMeaning = @{ 1074='Planned shutdown/restart initiated'; 1075='Remote-failure shutdown';
    41='Kernel-Power: UNEXPECTED reboot (no clean shutdown)'; 6008='Previous shutdown was UNEXPECTED';
    6006='Event log stopped (clean shutdown)'; 6005='Event log started (boot)' }

# ---- helpers ----------------------------------------------------------------
function Add-Alert($rule,$sev,$kind,$summary,$evidence) {
    [void]$alerts.Add([pscustomobject]@{ rule=$rule; severity=$sev; kind=$kind; summary=$summary; evidence=$evidence })
}
function Get-Prop($e,[int]$i) { try { return $e.Properties[$i].Value } catch { return $null } }
function Get-Data($e,[string]$name) {
    try { $xml=[xml]$e.ToXml(); $n=$xml.Event.EventData.Data | Where-Object { $_.Name -eq $name }; if ($n){return $n.'#text'} } catch {}
    return $null
}
function Test-Excluded([string]$p){ $lp=$p.ToLower(); foreach($m in $excludeMarkers){ if($lp.Contains($m)){return $true} } return $false }
function Test-InStaging([string]$p){ $lp=$p.ToLower(); foreach($m in $stagingMarkers){ if($lp.Contains($m)){return $true} } return $false }
function Get-Prefix([string]$path,[int]$n){
    try { $fs=[System.IO.File]::OpenRead($path); try { $b=New-Object byte[] $n; $r=$fs.Read($b,0,$n); return ,$b[0..([math]::Max(0,$r-1))] } finally { $fs.Close() } } catch { return @() }
}
function Test-DisguisedBinary([string]$path,[string]$ext){
    $pref=Get-Prefix $path 16; if($pref.Count -eq 0){return $false}
    $hex=($pref | ForEach-Object { $_.ToString('x2') }) -join ''
    $exp=$magic[$ext]; if($exp -and $hex.StartsWith($exp)){return $false}
    try { $head=(Get-Content -Path $path -TotalCount 40 -ErrorAction Stop -Encoding UTF8) -join "`n"
          foreach($ind in $textInd){ if($head.Contains($ind)){return $true} } } catch {}
    return $false
}
function Scan-Content([string]$path){
    $hits=@()
    try { $txt=(Get-Content -Path $path -TotalCount 5000 -ErrorAction Stop) -join "`n"
          if($txt.Contains($selfMarker)){ return @() }   # a Guard toolkit file, not malware
          foreach($fp in $payloadFps){ if($txt.Contains($fp)){$hits+=$fp} } } catch {}
    return $hits
}
function Test-Suspicious([string]$data){
    if(-not $data){return $null}
    $d=$data.ToLower(); $ind=@()
    foreach($m in @('\temp\','\users\public\','public/fonts/','\downloads\')){ if($d.Contains($m)){$ind+=$m} }
    foreach($i in @('auth-confirm-ten.vercel.app','fa-solid-400.woff2','.woff2')){ if($d.Contains($i)){$ind+=$i} }
    if($d -match '\biex\b' -or $d -match '\binvoke-expression\b'){$ind+='IEX'}
    if($d.Contains('frombase64string')){$ind+='FromBase64String'}
    if($d.Contains('downloadstring')){$ind+='DownloadString'}
    if($d -match '\s-enc(odedcommand)?\b'){$ind+='-enc'}
    if(($d -match '\b(python|pythonw|node|wscript|cscript|mshta)\b') -and
       ($d.Contains('\temp\') -or $d.Contains('\users\public\') -or $d.Contains('\roaming\'))){ $ind+='interpreter-from-staging' }
    if($ind.Count){ return ($ind | Select-Object -Unique) } else { return $null }
}
function Show-Table($rows){ if($rows){ $rows | Format-Table -AutoSize | Out-String -Width 400 | Write-Host } }

# =============================================================================
# START REPORT
# =============================================================================
try { Stop-Transcript | Out-Null } catch {}
Start-Transcript -Path $report -Force | Out-Null

Write-Host "############################################################################"
Write-Host "#  GUARD ENDPOINT TRIAGE"
Write-Host ("#  Host    : {0}" -f $env:COMPUTERNAME)
Write-Host ("#  User    : {0}\{1}" -f $env:USERDOMAIN, $env:USERNAME)
Write-Host ("#  OS      : {0}" -f (Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue).Caption)
Write-Host ("#  Run at  : {0} (UTC {1})" -f (Get-Date), (Get-Date).ToUniversalTime().ToString('o'))
Write-Host ("#  Window  : last {0} day(s), since {1}" -f $Days, $since)
Write-Host "############################################################################"

# collectors for final verdict
$sumPlanned=0; $sumUnexpected=0; $sumBursts=0; $sumTempCrit=0; $sumTempHigh=0; $sumRegSusp=0

# =============================================================================
# SECTION 1 + 2: REBOOTS (timeline, bursts, root cause)
# =============================================================================
Write-Host "`n==================== [1] REBOOT TIMELINE + INITIATORS ====================" -ForegroundColor Cyan
$sys = @()
try {
    $sys = @(Get-WinEvent -FilterHashtable @{ LogName='System'; Id=1074,1075,41,6008,6006,6005; StartTime=$since } -ErrorAction Stop | Sort-Object TimeCreated)
} catch { if ($_.Exception.Message -notmatch 'No events were found') { Write-Host "  (System log query error: $($_.Exception.Message))" } }

$recs = foreach ($e in $sys) {
    $init=$null; $user=$null; $reason=$null
    if ($e.Id -eq 1074) { $init=Get-Prop $e 0; $reason=Get-Prop $e 2; $user=Get-Prop $e 6 }
    [pscustomobject]@{ Time=$e.TimeCreated; EventId=$e.Id; Meaning=$rebootMeaning[$e.Id];
        Initiator=$init; User=$user; Reason=$reason; Unexpected=($e.Id -in 41,6008,1075) }
}
if ($recs) { Show-Table ($recs | Select-Object Time,EventId,Meaning,Initiator,User) }
else { Write-Host "  No reboot/shutdown events in the window." -ForegroundColor Green }

# bursts (1074 + 41)
$reboots = @($recs | Where-Object { $_.EventId -in 1074,41 } | Sort-Object Time)
$bursts=@()
for($i=0;$i -lt $reboots.Count;$i++){
    $win=@($reboots | Where-Object { $_.Time -ge $reboots[$i].Time -and $_.Time -le $reboots[$i].Time.AddMinutes(180) })
    if($win.Count -ge 2){
        $bursts += [pscustomobject]@{ Start=$reboots[$i].Time; Count=$win.Count; WithinMin=180 }
    }
}
$bursts=@($bursts | Sort-Object Start -Unique)
if($bursts){ Write-Host "`n  Reboot bursts (>=2 within 180 min):" -ForegroundColor Yellow; Show-Table $bursts }

$sumPlanned    = @($recs | Where-Object { $_.EventId -eq 1074 }).Count
$sumUnexpected = @($recs | Where-Object { $_.EventId -in 41,6008 }).Count
$sumBursts     = $bursts.Count

Write-Host "`n==================== [2] UNEXPECTED-REBOOT ROOT CAUSE ====================" -ForegroundColor Cyan
$e41 = @($sys | Where-Object { $_.Id -eq 41 })
if (-not $e41) { Write-Host "  No unexpected (Event 41) reboots - good." -ForegroundColor Green }
else {
    $bugchecks=@(); $whea=@(); $dumps=@()
    try { $bugchecks=@(Get-WinEvent -FilterHashtable @{LogName='System';Id=1001;ProviderName='Microsoft-Windows-WER-SystemErrorReporting';StartTime=$since} -ErrorAction Stop) } catch {}
    try { $whea=@(Get-WinEvent -FilterHashtable @{LogName='System';ProviderName='Microsoft-Windows-WHEA-Logger';StartTime=$since} -ErrorAction Stop) } catch {}
    try { $dumps=@(Get-ChildItem "$env:SystemRoot\Minidump\*.dmp" -ErrorAction Stop | Where-Object { $_.LastWriteTime -ge $since }) } catch {}
    Write-Host ("  Event-41: {0}  bugchecks: {1}  WHEA: {2}  minidumps: {3}" -f $e41.Count,$bugchecks.Count,$whea.Count,$dumps.Count)
    $causes = foreach($e in $e41){
        $bc=Get-Data $e 'BugcheckCode'; $pb=Get-Data $e 'PowerButtonTimestamp'
        $bcI=0;[void][int64]::TryParse(("" + $bc),[ref]$bcI); $pbI=0;[void][int64]::TryParse(("" + $pb),[ref]$pbI)
        $nb=$bugchecks | Where-Object { [math]::Abs(($_.TimeCreated-$e.TimeCreated).TotalMinutes) -le 5 } | Select-Object -First 1
        $nd=$dumps | Where-Object { [math]::Abs(($_.LastWriteTime-$e.TimeCreated).TotalMinutes) -le 10 } | Select-Object -First 1
        $nw=$whea | Where-Object { [math]::Abs(($_.TimeCreated-$e.TimeCreated).TotalMinutes) -le 10 } | Select-Object -First 1
        if($bcI -ne 0 -or $nb -or $nd){ $v='crash (bugcheck)' }
        elseif($pbI -ne 0){ $v='power-button (hard off)' }
        else { $v='power-loss / hard-reset' }
        [pscustomobject]@{ Time=$e.TimeCreated; Verdict=$v; BugcheckCode=$bc; WHEA=[bool]$nw }
    }
    Show-Table $causes
    $grp = $causes | Group-Object Verdict | Sort-Object Count -Descending
    Write-Host "  Cause breakdown:"; foreach($g in $grp){ Write-Host ("    {0,-26} {1}" -f $g.Name,$g.Count) }
    if($grp | Where-Object { $_.Name -like 'power-loss*' }){
        Write-Host "  Note: power-loss/hard-reset = no crash + no clean shutdown. Rule out PSU/battery/" -ForegroundColor Yellow
        Write-Host "        thermal/loose-power FIRST; a forced reboot is possible but this data cannot prove it." -ForegroundColor Yellow
    }
}

# =============================================================================
# SECTION 3: TEMP / STAGING FILE SWEEP
# =============================================================================
Write-Host "`n==================== [3] TEMP / STAGING FILE SWEEP ====================" -ForegroundColor Cyan
$heavy = @("$env:APPDATA","$env:USERPROFILE\Downloads")
$allRoots = @($env:TEMP,"$env:SystemRoot\Temp",$env:PUBLIC,"$env:LOCALAPPDATA\Temp") + $heavy |
    Where-Object { $_ -and (Test-Path $_) } | Select-Object -Unique
$roots = if($TempOnly){ $allRoots | Where-Object { $heavy -notcontains $_ } } else { $allRoots }
$roots | ForEach-Object { Write-Host "    scan: $_" }
if(-not $TempOnly){ Write-Host "    (-TempOnly skips Roaming/Downloads for a fast pass.)" -ForegroundColor DarkGray }

$fileFindings=@()
function Scan-Root([string]$root){
    $sw=[System.Diagnostics.Stopwatch]::StartNew(); $walked=0; $flagged=0
    $stack=New-Object System.Collections.Stack; $stack.Push($root)
    while($stack.Count -gt 0){
        $dir=$stack.Pop()
        try { foreach($s in [System.IO.Directory]::EnumerateDirectories($dir)){ $stack.Push($s) } } catch {}
        $files=$null; try { $files=[System.IO.Directory]::EnumerateFiles($dir) } catch { continue }
        foreach($path in $files){
            $walked++
            if(($walked % 8000) -eq 0){ Write-Host ("      {0}: {1} files, {2} flagged ({3}s)" -f $root,$walked,$flagged,[int]$sw.Elapsed.TotalSeconds) -ForegroundColor DarkGray }
            if($walked -ge $MaxFilesPerRoot){ Write-Host ("      {0}: hit cap {1}; stopping root." -f $root,$MaxFilesPerRoot) -ForegroundColor DarkGray; $stack.Clear(); break }
            $ext=[System.IO.Path]::GetExtension($path).ToLower()
            $isSusp=$suspExt -contains $ext; $isBin=$magic.ContainsKey($ext)
            if(-not ($isSusp -or $isBin)){ continue }
            if(Test-Excluded $path){ continue }
            $fi=$null; try { $fi=[System.IO.FileInfo]$path } catch { continue }
            if($fi.LastWriteTime -lt $since -and $fi.CreationTime -lt $since){ continue }
            $reason=$null;$sev=$null;$fps=@()
            if($isSusp){
                $fps=Scan-Content $path
                if($fps.Count){ $reason="script with C2 fingerprints";$sev='critical' }
                elseif(Test-InStaging $path){ $reason="script in staging dir ($ext)";$sev='high' }
            } elseif($isBin){ if(Test-DisguisedBinary $path $ext){ $reason="binary-disguised dropper ($ext contains text)";$sev='critical' } }
            if(-not $reason){ continue }
            $flagged++
            $owner=try { (Get-Acl $path).Owner } catch { '?' }
            $hash=try { (Get-FileHash -Path $path -Algorithm SHA256 -ErrorAction Stop).Hash } catch { '?' }
            $script:fileFindings += [pscustomobject]@{ Severity=$sev; Modified=$fi.LastWriteTime; SizeKB=[math]::Round($fi.Length/1KB,1); Owner=$owner; Sha256=$hash; Reason=$reason; Path=$path; Fingerprints=($fps -join ', ') }
            Add-Alert 'win.temp.script_drop' $sev 'win:file' $reason ([ordered]@{ path=$path; owner=$owner; sha256=$hash; fingerprints=$fps })
        }
    }
    Write-Host ("    done {0}: {1} files, {2} flagged, {3}s" -f $root,$walked,$flagged,[int]$sw.Elapsed.TotalSeconds) -ForegroundColor DarkGray
}
foreach($r in $roots){ Scan-Root $r }
if($fileFindings){
    Write-Host "`n  Flagged files (judge by hash/content, NOT name - attacker may masquerade):" -ForegroundColor Yellow
    Show-Table ($fileFindings | Sort-Object Severity,Modified | Select-Object Severity,Modified,SizeKB,Owner,Reason,Path)
    # Per-file SHA256 so you can verify content and diff the same-named file across machines
    Write-Host "  SHA256 of flagged files:" -ForegroundColor DarkGray
    foreach($f in ($fileFindings | Sort-Object Severity,Path)){ Write-Host ("    {0}  {1}  {2}" -f $f.Severity.PadRight(8), $f.Sha256, $f.Path) }
}
else { Write-Host "`n  No suspicious temp/staging files." -ForegroundColor Green }
$sumTempCrit = @($fileFindings | Where-Object Severity -eq 'critical').Count
$sumTempHigh = @($fileFindings | Where-Object Severity -eq 'high').Count

# =============================================================================
# SECTION 4: REGISTRY PERSISTENCE SWEEP
# =============================================================================
Write-Host "`n==================== [4] REGISTRY PERSISTENCE SWEEP ====================" -ForegroundColor Cyan
$regFindings=@()
$runKeys=@(
 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run','HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
 'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnceEx','HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run',
 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run','HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Run','HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run')
foreach($key in $runKeys){
    if(-not (Test-Path $key)){ continue }
    $props=Get-ItemProperty -Path $key -ErrorAction SilentlyContinue; if(-not $props){ continue }
    foreach($p in $props.PSObject.Properties){
        if($p.Name -like 'PS*'){ continue }
        $ind=Test-Suspicious ([string]$p.Value)
        if($ind){ $regFindings += [pscustomobject]@{ Severity='critical';Key=$key;Name=$p.Name;Indicators=($ind -join ', ');Value=[string]$p.Value }
                  Add-Alert 'win.registry_persistence' 'critical' 'win:registry' "persistence value -> temp/script/IOC" ([ordered]@{key=$key;name=$p.Name;value=[string]$p.Value;indicators=$ind}) }
    }
}
$winlogon='HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon'
if(Test-Path $winlogon){
    $wl=Get-ItemProperty -Path $winlogon -ErrorAction SilentlyContinue
    foreach($n in 'Shell','Userinit'){
        $val=[string]$wl.$n; $exp=if($n -eq 'Shell'){'explorer.exe'}else{'userinit.exe'}
        $bad=(($val -and ($val.ToLower() -notlike "*$exp*")) -or (Test-Suspicious $val))
        if($bad){ $regFindings += [pscustomobject]@{ Severity='critical';Key=$winlogon;Name=$n;Indicators='unexpected winlogon value';Value=$val }
                  Add-Alert 'win.registry_persistence' 'critical' 'win:registry' "Winlogon $n modified" ([ordered]@{key=$winlogon;name=$n;value=$val}) }
    }
}
$ifeo='HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'
if(Test-Path $ifeo){
    Get-ChildItem $ifeo -ErrorAction SilentlyContinue | ForEach-Object {
        $dbg=(Get-ItemProperty -Path $_.PSPath -Name Debugger -ErrorAction SilentlyContinue).Debugger
        if($dbg){ $regFindings += [pscustomobject]@{ Severity='critical';Key=$_.PSChildName;Name='Debugger';Indicators='IFEO hijack';Value=$dbg }
                  Add-Alert 'win.registry_persistence' 'critical' 'win:registry' "IFEO Debugger hijack: $($_.PSChildName)" ([ordered]@{image=$_.PSChildName;debugger=$dbg}) }
    }
}
try {
    Get-ChildItem 'HKLM:\System\CurrentControlSet\Services' -ErrorAction SilentlyContinue | ForEach-Object {
        $img=(Get-ItemProperty -Path $_.PSPath -Name ImagePath -ErrorAction SilentlyContinue).ImagePath
        $ind=Test-Suspicious $img
        if($ind){ $regFindings += [pscustomobject]@{ Severity='critical';Key="Service:$($_.PSChildName)";Name='ImagePath';Indicators=($ind -join ', ');Value=$img }
                  Add-Alert 'win.registry_persistence' 'critical' 'win:registry' "service ImagePath in staging: $($_.PSChildName)" ([ordered]@{service=$_.PSChildName;imagepath=$img;indicators=$ind}) }
    }
} catch {}
$regHits=@($regFindings | Where-Object Severity -eq 'critical')
if($regHits.Count){ Write-Host "`n  SUSPICIOUS registry entries:" -ForegroundColor Red; Show-Table ($regHits | Select-Object Severity,Key,Name,Indicators,Value) }
else { Write-Host "`n  No suspicious persistence values found." -ForegroundColor Green }
$sumRegSusp=$regHits.Count

# =============================================================================
# SECTION 5: VERDICT
# =============================================================================
Write-Host "`n==================== [5] VERDICT: $env:COMPUTERNAME ====================" -ForegroundColor Cyan
Write-Host ("  Reboots     : {0} planned, {1} unexpected, {2} burst(s)" -f $sumPlanned,$sumUnexpected,$sumBursts)
Write-Host ("  Temp files  : {0} critical, {1} high" -f $sumTempCrit,$sumTempHigh)
Write-Host ("  Registry    : {0} suspicious" -f $sumRegSusp)
$attackArtifacts = ($sumTempCrit + $sumRegSusp)
if($attackArtifacts -eq 0){
    Write-Host "`n  ATTACK ARTIFACTS: NONE. No staging or persistence of this attack on this host." -ForegroundColor Green
} else {
    Write-Host "`n  ATTACK ARTIFACTS FOUND ($attackArtifacts critical). PRESERVE, ISOLATE, ESCALATE." -ForegroundColor Red
}
if($sumUnexpected -gt 0){
    Write-Host "  Unexpected reboots present - investigate hardware/power (see Section 2); not necessarily malware." -ForegroundColor Yellow
}

Stop-Transcript | Out-Null

if($Jsonl){
    $sw=New-Object System.IO.StreamWriter($jsonlPath,$false)
    try { foreach($a in $alerts){ $o=[ordered]@{ ts=(Get-Date).ToUniversalTime().ToString('o'); host=$env:COMPUTERNAME; kind=$a.kind; rule=$a.rule; severity=$a.severity; summary=$a.summary; evidence=$a.evidence }; $sw.WriteLine(($o | ConvertTo-Json -Compress -Depth 6)) } } finally { $sw.Close() }
}

Write-Host "`nReport written -> $report" -ForegroundColor Green
if($Jsonl){ Write-Host "JSONL written  -> $jsonlPath" -ForegroundColor Green }
Write-Host "Collect that .txt from each machine for comparison."
