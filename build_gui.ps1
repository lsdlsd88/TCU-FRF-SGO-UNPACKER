$ErrorActionPreference = 'Stop'
$sgoBuildRoot = $PSScriptRoot

# Hot loops (dsg_decrypt / lzss10 / lzz22) are compiled to sgo_fast.dll and
# loaded with ctypes; sgo_frf falls back to Python if it is ever missing.
$vcdir = 'C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat'
$dll = Join-Path $sgoBuildRoot 'sgo_fast.dll'
if (-not (Test-Path $dll)) {
    if (-not (Test-Path $vcdir)) {
        throw 'sgo_fast.dll is missing and vcvars64.bat was not found to build it'
    }
    Push-Location $sgoBuildRoot
    try {
        cmd /c "call `"$vcdir`" >nul && cl /O2 /LD /nologo /W3 sgo_fast.c /Fe:sgo_fast.dll" | Out-Host
        if ($LASTEXITCODE -ne 0 -or -not (Test-Path $dll)) { throw 'sgo_fast.dll build failed' }
    }
    finally {
        Pop-Location
    }
}

py -3 -m PyInstaller --noconfirm --onefile --windowed --name 'TCU SGO FRF Unpacker' --runtime-tmpdir "." --distpath "$sgoBuildRoot\dist" --workpath "$sgoBuildRoot\build\pyinstaller" --specpath "$sgoBuildRoot\build" --add-data "$sgoBuildRoot\frf.key;." --add-binary "$dll;." "$sgoBuildRoot\datflash_gui.py"
if ($LASTEXITCODE -ne 0) { throw 'PyInstaller build failed' }

# This checkout sits under a Low-integrity label, so everything built here
# inherits Low: a Low process cannot write the user's Medium-integrity folders
# (errno 13 on any file creation in the library). Relabel the build Medium.
$dist = Join-Path $sgoBuildRoot 'dist'
$exe = Join-Path $dist 'TCU SGO FRF Unpacker.exe'
& icacls $dist /setintegritylevel '(OI)(CI)Medium' /T /C | Out-Null
& icacls $exe /setintegritylevel Medium | Out-Null
$level = (& icacls $exe | Select-String -Pattern 'Mandatory Label').Line
Write-Output "Integrity: $($level -replace '\s+', ' ')"

Write-Output "Built: $sgoBuildRoot\dist\TCU SGO FRF Unpacker.exe"
