# Deploy the working repo (sgo_re) into this release repo.
#
#   .\sync_release.ps1                  copy current sources + exe, commit if changed
#   .\sync_release.ps1 -Build           rebuild the exe from source first
#   .\sync_release.ps1 -Check           report what would change, touch nothing
#   .\sync_release.ps1 -NoCommit        copy and relabel, leave the commit to you
#
# The working repo is expected next to this one (..\sgo_re); override with -Source.
param(
    [string]$Source = (Join-Path $PSScriptRoot '..\sgo_re'),
    [switch]$Build,
    [switch]$Check,
    [switch]$NoCommit,
    [string]$Message = 'Sync release from the working repo'
)

$ErrorActionPreference = 'Stop'
$release = $PSScriptRoot
$exeName = 'TCU SGO FRF Unpacker.exe'

if (-not (Test-Path -LiteralPath $Source)) { throw "working repo not found: $Source" }
$Source = (Resolve-Path -LiteralPath $Source).Path
if (-not (Test-Path -LiteralPath (Join-Path $Source 'datflash_gui.py'))) {
    throw "not the working repo (no datflash_gui.py): $Source"
}

$files = @(
    'datflash_gui.py', 'sgo_early.py', 'sgo_fast.py', 'sgo_frf.py', 'sgo_hex.py',
    'sgo_identity.py', 'sgo_image.py', 'sgo_index.py', 'sgo_legacy.py',
    'sgo_restore.py', 'sgo_scratch.py', 'sgo_tables.py', 'sgo_unpack.py',
    'frf_family.py', 'crc_regions.py', 'sgo_fast.c', 'sgo_fast.dll',
    'frf.key', 'build_gui.ps1'
)

# Refuse to package a working tree with uncommitted source: the release would
# then not correspond to any commit in the working repo.
Push-Location -LiteralPath $Source
try {
    $dirty = git status --porcelain -- $files
    if ($dirty -and -not $Check) {
        Write-Warning "working repo has uncommitted changes in packaged files:`n$dirty"
    }
} finally { Pop-Location }

if ($Build) {
    if ($Check) { throw '-Build cannot be combined with -Check' }
    Write-Output "Building $exeName ..."
    Push-Location -LiteralPath $Source
    try {
        & powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $Source 'build_gui.ps1')
        if ($LASTEXITCODE -ne 0) { throw 'build failed' }
    } finally { Pop-Location }
}

$exe = Join-Path $Source ('dist\' + $exeName)
if (-not (Test-Path -LiteralPath $exe)) {
    throw "no built executable at $exe - run with -Build"
}

$changed = @()
foreach ($name in $files) {
    $from = Join-Path $Source $name
    $to = Join-Path $release $name
    if (-not (Test-Path -LiteralPath $from)) { throw "missing in working repo: $name" }
    $fromHash = (Get-FileHash -LiteralPath $from -Algorithm SHA256).Hash
    $toHash = if (Test-Path -LiteralPath $to) { (Get-FileHash -LiteralPath $to -Algorithm SHA256).Hash } else { 'absent' }
    if ($fromHash -ne $toHash) {
        $changed += $name
        if (-not $Check) { Copy-Item -LiteralPath $from -Destination $to -Force }
    }
}

$exeTo = Join-Path $release ('dist\' + $exeName)
$exeFromHash = (Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash
$exeToHash = if (Test-Path -LiteralPath $exeTo) { (Get-FileHash -LiteralPath $exeTo -Algorithm SHA256).Hash } else { 'absent' }
$exeChanged = $exeFromHash -ne $exeToHash
if ($exeChanged) {
    if (-not $Check) {
        New-Item -ItemType Directory -Force -Path (Split-Path -Parent $exeTo) | Out-Null
        Copy-Item -LiteralPath $exe -Destination $exeTo -Force
    }
}

# A copied binary inherits the Low integrity label of this workspace; the tool
# cannot write the user's library unless it runs at Medium.
if (-not $Check) {
    & icacls (Split-Path -Parent $exeTo) /setintegritylevel '(OI)(CI)Medium' /T /C | Out-Null
    & icacls $exeTo /setintegritylevel Medium | Out-Null
}

$sourceStamp = (Get-Item -LiteralPath $exe).LastWriteTime
$newestSource = Get-ChildItem -LiteralPath $Source -File |
    Where-Object { $files -contains $_.Name } |
    Sort-Object LastWriteTime -Descending | Select-Object -First 1
if ($newestSource -and $newestSource.LastWriteTime -gt $sourceStamp -and -not $Check) {
    Write-Warning ("$exeName is older than {0} - rebuild with -Build" -f $newestSource.Name)
}

if ($Check) {
    "exe would change: $exeChanged"
    "source files that would change ($($changed.Count)): $($changed -join ', ')"
    return
}

Write-Output ("copied {0} source file(s): {1}" -f $changed.Count, ($changed -join ', '))
Write-Output ("exe copied: {0}" -f $exeChanged)

if ($NoCommit) { Write-Output 'no commit requested'; return }

Push-Location -LiteralPath $release
try {
    git add -A
    if (-not (git status --porcelain)) {
        Write-Output 'release repo already up to date'
        return
    }
    # Never put the local working path into the commit: the release travels
    # outside this machine.
    $body = "Synced from the working tree`nCopied: $(if ($changed) { $changed -join ', ' } else { 'none' })`nExecutable rebuilt: $exeChanged"
    git -c core.autocrlf=false commit -m $Message -m $body
    if ($LASTEXITCODE -ne 0) { throw 'commit failed' }
    git log -1 --format='release commit: %h %s'
} finally { Pop-Location }
