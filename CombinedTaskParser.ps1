<#
    Combined Task Scheduler Parser
    ------------------------------
    A single screenshare tool that merges the task-scheduler detection methods
    from the guides and webinars: on-disk XML tasks, the TaskCache registry
    (Tasks + Tree), signature checks, suspicious command/host flags, logon/boot
    triggers, IFEO debugger hijacks, and a disk-vs-registry diff that surfaces
    deleted or registry-only tasks.

    Read-only. It inspects the machine and reports. It does not create, edit or
    delete any task.

    Usage (run CMD / PowerShell as administrator):
        powershell -ExecutionPolicy Bypass -File .\CombinedTaskParser.ps1

    Options:
        -SinceHours 24      Flag tasks whose file was modified within N hours (default 24)
        -OutDir <path>      Where to write the CSV/report (default C:\SSTools\TaskParser)
        -NoOpen             Don't open the output folder when done
        -IncludeMicrosoft   Also list clean tasks in the console (always in CSV)
#>

[CmdletBinding()]
param(
    [int]    $SinceHours      = 24,
    [string] $OutDir          = 'C:\SSTools\TaskParser',
    [switch] $NoOpen,
    [switch] $IncludeMicrosoft
)

$ErrorActionPreference = 'Continue'

# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------
function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p  = New-Object Security.Principal.WindowsPrincipal($id)
    return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

$IsAdmin = Test-Admin
Write-Host ''
Write-Host '==============================================' -ForegroundColor Cyan
Write-Host '       Combined Task Scheduler Parser' -ForegroundColor Cyan
Write-Host '==============================================' -ForegroundColor Cyan
if (-not $IsAdmin) {
    Write-Host '[!] Not running as administrator. TaskCache registry and IFEO' -ForegroundColor Yellow
    Write-Host '    checks may be incomplete. Re-run elevated for a full scan.' -ForegroundColor Yellow
}
Write-Host ''

if (-not (Test-Path $OutDir)) {
    New-Item -ItemType Directory -Path $OutDir -Force | Out-Null
}

$taskFileRoots = @(
    "$env:SystemRoot\System32\Tasks",
    "$env:SystemRoot\System32\Tasks_Migrated",
    "$env:SystemRoot\Tasks"
)

# Hosts that are red flags when launched from a task
$suspiciousHosts = @(
    'cmd.exe','powershell.exe','pwsh.exe','mshta.exe','wscript.exe','cscript.exe',
    'rundll32.exe','regsvr32.exe','conhost.exe','msbuild.exe','installutil.exe',
    'regasm.exe','regsvcs.exe','bitsadmin.exe','certutil.exe','curl.exe',
    'forfiles.exe','wmic.exe','explorer.exe'
)

# Argument fragments worth flagging
$suspiciousArgPatterns = @(
    '-enc\b','-e\b','-ec\b','frombase64string','iex\b','invoke-expression',
    'downloadstring','downloadfile','invoke-webrequest','invoke-restmethod',
    '-w\s+hidden','-windowstyle\s+hidden','-nop\b','-noprofile','-bypass',
    'hidden','http://','https://','\\\\','net\s+user','vssadmin','bcdedit'
)

# Standard directories a legit task action usually lives in
$standardDirs = @(
    "$env:SystemRoot\System32",
    "$env:SystemRoot\SysWOW64",
    "$env:SystemRoot",
    "$env:ProgramFiles",
    "${env:ProgramFiles(x86)}",
    "$env:ProgramData"
) | Where-Object { $_ }

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
function Expand-Path {
    param([string]$p)
    if ([string]::IsNullOrWhiteSpace($p)) { return $p }
    $p = $p.Trim().Trim('"')
    try { return [Environment]::ExpandEnvironmentVariables($p) } catch { return $p }
}

function Get-ExePaths {
    # Pull likely file paths out of a command + argument string
    param([string]$text)
    if ([string]::IsNullOrWhiteSpace($text)) { return @() }
    $hits = [System.Collections.Generic.List[string]]::new()
    foreach ($m in [regex]::Matches($text, '([a-zA-Z]:\\[^"''|<>]+?\.(?:exe|dll|bat|cmd|ps1|vbs|js|scr|com|hta))')) {
        $hits.Add($m.Groups[1].Value)
    }
    return $hits | Select-Object -Unique
}

function Test-Signature {
    param([string]$path)
    $path = Expand-Path $path
    if ([string]::IsNullOrWhiteSpace($path) -or -not (Test-Path -LiteralPath $path -PathType Leaf)) {
        return [pscustomobject]@{ Status = 'FileMissing'; Signer = ''; IsMicrosoft = $false }
    }
    try {
        $sig = Get-AuthenticodeSignature -LiteralPath $path -ErrorAction Stop
        $signer = if ($sig.SignerCertificate) { $sig.SignerCertificate.Subject } else { '' }
        $isMs = $signer -match 'CN=Microsoft (Windows|Corporation)'
        return [pscustomobject]@{ Status = "$($sig.Status)"; Signer = $signer; IsMicrosoft = [bool]$isMs }
    } catch {
        return [pscustomobject]@{ Status = 'CheckError'; Signer = ''; IsMicrosoft = $false }
    }
}

function Has-NonAscii {
    param([string]$s)
    if ([string]::IsNullOrEmpty($s)) { return $false }
    return ($s -cmatch '[^\u0000-\u007F]')
}

# ---------------------------------------------------------------------------
# 1. Collect tasks from disk (parse the XML directly)
# ---------------------------------------------------------------------------
Write-Host '[*] Reading task files from disk...' -ForegroundColor Gray
$diskTasks = @{}   # key: normalized task path  ->  object

foreach ($root in $taskFileRoots) {
    if (-not (Test-Path $root)) { continue }
    Get-ChildItem -LiteralPath $root -Recurse -File -ErrorAction SilentlyContinue | ForEach-Object {
        $file = $_
        $taskPath = $file.FullName.Substring($root.Length).Replace('\','/')
        if (-not $taskPath.StartsWith('/')) { $taskPath = '/' + $taskPath }

        $cmd = ''; $argStr = ''; $author = ''; $runAs = ''; $runLevel = ''
        $triggers = New-Object System.Collections.Generic.List[string]
        $xmlOk = $false
        try {
            [xml]$xml = Get-Content -LiteralPath $file.FullName -Raw -Encoding Unicode -ErrorAction Stop
            $xmlOk = $true
        } catch {
            try { [xml]$xml = Get-Content -LiteralPath $file.FullName -Raw -ErrorAction Stop; $xmlOk = $true } catch { }
        }
        if ($xmlOk) {
            $ns = $xml.Task
            if ($ns) {
                $author   = [string]$ns.RegistrationInfo.Author
                $exec     = $ns.Actions.Exec
                if ($exec) {
                    if ($exec -is [array]) { $exec = $exec[0] }
                    $cmd    = [string]$exec.Command
                    $argStr = [string]$exec.Arguments
                }
                $runAs    = [string]$ns.Principals.Principal.UserId
                if (-not $runAs) { $runAs = [string]$ns.Principals.Principal.GroupId }
                $runLevel = [string]$ns.Principals.Principal.RunLevel
                if ($ns.Triggers) {
                    foreach ($t in $ns.Triggers.ChildNodes) { $triggers.Add($t.Name) }
                }
            }
        }

        $diskTasks[$taskPath] = [pscustomobject]@{
            TaskPath   = $taskPath
            Name       = $file.Name
            Source     = 'Disk'
            File       = $file.FullName
            Modified   = $file.LastWriteTime
            Author     = $author
            Command    = $cmd
            Arguments  = $argStr
            RunAs      = $runAs
            RunLevel   = $runLevel
            Triggers   = ($triggers -join ', ')
            InRegistry = $false
            OnDisk     = $true
        }
    }
}
Write-Host ("    {0} task files found." -f $diskTasks.Count) -ForegroundColor Gray

# ---------------------------------------------------------------------------
# 2. Collect from the TaskCache registry (Tree maps path -> GUID; Tasks holds the blob)
# ---------------------------------------------------------------------------
Write-Host '[*] Reading TaskCache registry...' -ForegroundColor Gray
$regBase   = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache'
$regTasks  = @{}   # guid -> blob text
$treeMap   = @{}   # task path -> guid

if (Test-Path "$regBase\Tasks") {
    Get-ChildItem "$regBase\Tasks" -ErrorAction SilentlyContinue | ForEach-Object {
        $guid = $_.PSChildName
        try {
            $props = Get-ItemProperty -LiteralPath $_.PSPath -ErrorAction Stop
            $blobText = ''
            if ($props.Actions) {
                try { $blobText = [System.Text.Encoding]::Unicode.GetString([byte[]]$props.Actions) } catch { }
            }
            $regTasks[$guid] = [pscustomobject]@{
                Guid      = $guid
                Path      = [string]$props.Path
                BlobText  = $blobText
            }
        } catch { }
    }
}
if (Test-Path "$regBase\Tree") {
    Get-ChildItem "$regBase\Tree" -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
        try {
            $id = (Get-ItemProperty -LiteralPath $_.PSPath -Name Id -ErrorAction Stop).Id
            if ($id) {
                $path = $_.PSPath -replace '.*\\Tree',''
                $path = $path.Replace('\','/')
                $treeMap[$path] = $id
            }
        } catch { }
    }
}
Write-Host ("    {0} registry task entries, {1} tree entries." -f $regTasks.Count, $treeMap.Count) -ForegroundColor Gray

# Mark which disk tasks also appear in registry, and find registry-only ones
foreach ($path in @($diskTasks.Keys)) {
    $norm = $path
    if ($treeMap.ContainsKey($norm)) { $diskTasks[$path].InRegistry = $true }
}

$regOnly = @()
foreach ($path in $treeMap.Keys) {
    if (-not $diskTasks.ContainsKey($path)) {
        $guid = $treeMap[$path]
        $blob = if ($regTasks.ContainsKey($guid)) { $regTasks[$guid].BlobText } else { '' }
        # best-effort command pull from the blob
        $cmd = ''
        $phits = Get-ExePaths $blob
        if ($phits.Count -gt 0) { $cmd = $phits[0] }
        $regOnly += [pscustomobject]@{
            TaskPath   = $path
            Name       = ($path -split '/')[-1]
            Source     = 'RegistryOnly'
            File       = '(no file on disk)'
            Modified   = $null
            Author     = ''
            Command    = $cmd
            Arguments  = ''
            RunAs      = ''
            RunLevel   = ''
            Triggers   = ''
            InRegistry = $true
            OnDisk     = $false
        }
    }
}
Write-Host ("    {0} registry-only tasks (no file on disk)." -f $regOnly.Count) -ForegroundColor Gray

# ---------------------------------------------------------------------------
# 3. IFEO debugger entries (execution hijacks)
# ---------------------------------------------------------------------------
Write-Host '[*] Checking Image File Execution Options...' -ForegroundColor Gray
$ifeo = @()
$ifeoBase = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'
if (Test-Path $ifeoBase) {
    Get-ChildItem $ifeoBase -ErrorAction SilentlyContinue | ForEach-Object {
        try {
            $dbg = (Get-ItemProperty -LiteralPath $_.PSPath -Name Debugger -ErrorAction Stop).Debugger
            if ($dbg) {
                $ifeo += [pscustomobject]@{ Image = $_.PSChildName; Debugger = $dbg }
            }
        } catch { }
    }
}
Write-Host ("    {0} IFEO debugger entries." -f $ifeo.Count) -ForegroundColor Gray

# ---------------------------------------------------------------------------
# 4. Score every task
# ---------------------------------------------------------------------------
Write-Host '[*] Scoring tasks...' -ForegroundColor Gray
$cutoff  = (Get-Date).AddHours(-1 * [math]::Abs($SinceHours))
$results = New-Object System.Collections.Generic.List[object]

$allTasks = @()
$allTasks += $diskTasks.Values
$allTasks += $regOnly

foreach ($t in $allTasks) {
    $score  = 0
    $flags  = New-Object System.Collections.Generic.List[string]

    $isMsTask    = ($t.TaskPath -like '/Microsoft/*')
    $cmdExpanded = Expand-Path $t.Command
    $hostExe     = if ($cmdExpanded) { [System.IO.Path]::GetFileName($cmdExpanded).ToLower() } else { '' }

    # --- signature of the action exe ---
    $sig = Test-Signature $cmdExpanded
    if ($t.OnDisk -or $t.Command) {
        if ($sig.Status -eq 'FileMissing' -and $t.Command) {
            $score += 2; $flags.Add('Action file missing')
        } elseif ($sig.Status -eq 'Valid' -and -not $sig.IsMicrosoft) {
            # signed by a third party, mild
        } elseif ($sig.Status -ne 'Valid' -and $sig.Status -ne 'FileMissing' -and $sig.Status -ne 'CheckError' -and $t.Command) {
            $score += 3; $flags.Add("Unsigned/invalid action ($($sig.Status))")
        }
    }

    # --- registry-only / deleted-file task ---
    if ($t.Source -eq 'RegistryOnly') {
        $score += 4; $flags.Add('In registry, no file on disk (deleted?)')
    }
    # --- on disk but not registered in Tree ---
    if ($t.OnDisk -and -not $t.InRegistry) {
        $score += 2; $flags.Add('File on disk not linked in TaskCache')
    }

    # --- suspicious host ---
    if ($hostExe -and ($suspiciousHosts -contains $hostExe)) {
        $score += 3; $flags.Add("Launches $hostExe")
    }

    # --- suspicious arguments ---
    $argText = ("{0} {1}" -f $t.Command, $t.Arguments)
    foreach ($pat in $suspiciousArgPatterns) {
        if ($argText -match $pat) {
            $score += 2; $flags.Add("Arg match: $pat")
        }
    }

    # --- triggers: logon / boot on a non-Microsoft task ---
    if ($t.Triggers -match 'Logon|Boot') {
        if (-not $isMsTask) {
            $score += 2; $flags.Add("Trigger: $($t.Triggers)")
        }
    }

    # --- run level ---
    if ($t.RunLevel -match 'Highest' -and -not $isMsTask) {
        $score += 1; $flags.Add('Runs with highest privileges')
    }

    # --- path outside standard dirs ---
    if ($cmdExpanded -match '^[a-zA-Z]:\\') {
        $inStd = $false
        foreach ($d in $standardDirs) {
            if ($cmdExpanded.ToLower().StartsWith($d.ToLower())) { $inStd = $true; break }
        }
        if (-not $inStd) { $score += 1; $flags.Add('Action path outside standard dirs') }
    }

    # --- unicode / hidden chars in name or path ---
    if ((Has-NonAscii $t.Name) -or (Has-NonAscii $t.TaskPath)) {
        $score += 2; $flags.Add('Non-ASCII char in task name/path')
    }

    # --- recently modified (before the SS) ---
    if ($t.Modified -and $t.Modified -gt $cutoff) {
        $score += 2; $flags.Add("Modified within $SinceHours h ($($t.Modified.ToString('MM-dd HH:mm')))")
    }

    # --- secondary file paths inside arguments ---
    foreach ($p in (Get-ExePaths $t.Arguments)) {
        $s2 = Test-Signature $p
        if ($s2.Status -eq 'FileMissing') { $score += 1; $flags.Add("Arg file missing: $p") }
        elseif ($s2.Status -ne 'Valid' -and $s2.Status -ne 'CheckError') { $score += 2; $flags.Add("Unsigned arg file: $p") }
    }

    $sev = if ($score -ge 6) { 'HIGH' } elseif ($score -ge 3) { 'MEDIUM' } elseif ($score -ge 1) { 'LOW' } else { 'CLEAN' }

    $results.Add([pscustomobject]@{
        Severity   = $sev
        Score      = $score
        TaskPath   = $t.TaskPath
        Host       = $hostExe
        Command    = $t.Command
        Arguments  = $t.Arguments
        Triggers   = $t.Triggers
        RunAs      = $t.RunAs
        RunLevel   = $t.RunLevel
        Author     = $t.Author
        Signer     = $sig.Signer
        SigStatus  = $sig.Status
        Source     = $t.Source
        Modified   = $t.Modified
        Flags      = ($flags -join ' | ')
    })
}

$sevOrder = @{ 'HIGH'=0; 'MEDIUM'=1; 'LOW'=2; 'CLEAN'=3 }
$sorted = $results | Sort-Object @{ Expression = { $sevOrder[$_.Severity] } }, @{ Expression='Score'; Descending=$true }, TaskPath

# ---------------------------------------------------------------------------
# 5. Output
# ---------------------------------------------------------------------------
function Write-Sev {
    param($row)
    $color = switch ($row.Severity) {
        'HIGH'   { 'Red' }
        'MEDIUM' { 'Yellow' }
        'LOW'    { 'DarkYellow' }
        default  { 'DarkGray' }
    }
    Write-Host ("[{0,-6}] {1}" -f $row.Severity, $row.TaskPath) -ForegroundColor $color
    if ($row.Command)   { Write-Host ("          -> {0} {1}" -f $row.Command, $row.Arguments) -ForegroundColor Gray }
    if ($row.Triggers)  { Write-Host ("          triggers: {0}  runAs: {1}  {2}" -f $row.Triggers, $row.RunAs, $row.RunLevel) -ForegroundColor DarkGray }
    if ($row.Flags)     { Write-Host ("          !! {0}" -f $row.Flags) -ForegroundColor $color }
    Write-Host ''
}

Write-Host ''
Write-Host '================= RESULTS =================' -ForegroundColor Cyan

$flagged = @($sorted | Where-Object { $_.Severity -ne 'CLEAN' })
$clean   = @($sorted | Where-Object { $_.Severity -eq 'CLEAN' })

if ($flagged.Count -eq 0) {
    Write-Host 'No suspicious tasks flagged.' -ForegroundColor Green
} else {
    Write-Host ("{0} task(s) flagged:`n" -f $flagged.Count) -ForegroundColor White
    foreach ($row in $flagged) { Write-Sev $row }
}

if ($IncludeMicrosoft -and $clean.Count -gt 0) {
    Write-Host ("--- {0} clean tasks ---" -f $clean.Count) -ForegroundColor DarkGray
    foreach ($row in $clean) {
        Write-Host ("[CLEAN ] {0}" -f $row.TaskPath) -ForegroundColor DarkGray
    }
    Write-Host ''
}

if ($ifeo.Count -gt 0) {
    Write-Host '--- IFEO debugger hijacks (execution redirects) ---' -ForegroundColor Red
    foreach ($e in $ifeo) {
        Write-Host ("  {0}  ->  {1}" -f $e.Image, $e.Debugger) -ForegroundColor Red
    }
    Write-Host ''
}

# ---------------------------------------------------------------------------
# 6. Save CSV + report
# ---------------------------------------------------------------------------
$stamp   = Get-Date -Format 'yyyyMMdd_HHmmss'
$csvPath = Join-Path $OutDir "tasks_$stamp.csv"
$ifeoCsv = Join-Path $OutDir "ifeo_$stamp.csv"
$txtPath = Join-Path $OutDir "report_$stamp.txt"

$sorted | Export-Csv -LiteralPath $csvPath -NoTypeInformation -Encoding UTF8
if ($ifeo.Count -gt 0) { $ifeo | Export-Csv -LiteralPath $ifeoCsv -NoTypeInformation -Encoding UTF8 }

$summary = @()
$summary += "Combined Task Scheduler Parser - $stamp"
$summary += "Admin: $IsAdmin"
$summary += "Disk tasks: $($diskTasks.Count)   Registry-only: $($regOnly.Count)   IFEO: $($ifeo.Count)"
$summary += "Flagged: $($flagged.Count)   Clean: $($clean.Count)"
$summary += ''
foreach ($row in $flagged) {
    $summary += "[$($row.Severity)] ($($row.Score)) $($row.TaskPath)"
    if ($row.Command) { $summary += "    -> $($row.Command) $($row.Arguments)" }
    if ($row.Flags)   { $summary += "    !! $($row.Flags)" }
}
$summary | Set-Content -LiteralPath $txtPath -Encoding UTF8

Write-Host '==========================================' -ForegroundColor Cyan
Write-Host ("Saved:`n  {0}`n  {1}" -f $csvPath, $txtPath) -ForegroundColor Green
if ($ifeo.Count -gt 0) { Write-Host ("  {0}" -f $ifeoCsv) -ForegroundColor Green }
Write-Host ''

if (-not $NoOpen) {
    try { Start-Process explorer.exe $OutDir } catch { }
}
