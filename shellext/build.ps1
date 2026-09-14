<#
.SYNOPSIS
    Builds c2paview.dll (the Explorer property-sheet shell extension) with MSVC.

.DESCRIPTION
    Runs rc.exe + cl.exe for the requested architecture. If you are not already in a
    Visual Studio developer shell, the script locates vcvarsall.bat via vswhere and
    sets up the environment itself. Output: <repo>\build\<arch>\c2paview.dll

.EXAMPLE
    .\shellext\build.ps1 -Arch x64
    .\shellext\build.ps1 -Arch arm64
#>
[CmdletBinding()]
param(
    [ValidateSet('x64', 'arm64')]
    [string]$Arch = 'x64',
    [string]$OutDir
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$src  = $PSScriptRoot
$root = Split-Path -Parent $src
if (-not $OutDir) { $OutDir = Join-Path $root "build\$Arch" }
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$OutDir = (Resolve-Path $OutDir).Path

$vcArch = if ($Arch -eq 'arm64') { 'amd64_arm64' } else { 'x64' }
$cet    = if ($Arch -eq 'x64') { '/CETCOMPAT' } else { '' }

$libs = 'user32.lib gdi32.lib shell32.lib shlwapi.lib comctl32.lib ole32.lib advapi32.lib uxtheme.lib uuid.lib'
$rcCmd = "rc.exe /nologo /fo `"$OutDir\c2paview.res`" `"$src\c2paview.rc`""
$clCmd = "cl.exe /nologo /W4 /permissive- /std:c++17 /O2 /Oi /GL /MT /EHsc /GS /guard:cf /sdl /utf-8 " +
         "/DNDEBUG /DUNICODE /D_UNICODE /Fo`"$OutDir\\`" /Fe`"$OutDir\c2paview.dll`" /LD " +
         "`"$src\dllmain.cpp`" `"$OutDir\c2paview.res`" " +
         "/link /DEF:`"$src\c2paview.def`" /LTCG /DYNAMICBASE /NXCOMPAT /GUARD:CF /OPT:REF /OPT:ICF /RELEASE $cet " +
         "/SUBSYSTEM:WINDOWS,6.1 $libs"

# Already inside a matching developer shell?
$inDevShell = (Get-Command cl.exe -ErrorAction SilentlyContinue) -and
              ($env:VSCMD_ARG_TGT_ARCH -eq $Arch)

$cmdFile = Join-Path $OutDir 'build.cmd'
if ($inDevShell) {
    @("@echo off", $rcCmd, "if errorlevel 1 exit /b 1", $clCmd) | Set-Content -Path $cmdFile -Encoding ASCII
} else {
    $vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
    if (-not (Test-Path $vswhere)) { throw "Visual Studio / Build Tools not found (no vswhere.exe). Install the 'Desktop development with C++' workload." }
    $vs = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
    if (-not $vs) { throw "No Visual Studio installation with the C++ toolset was found." }
    $vcvars = Join-Path $vs 'VC\Auxiliary\Build\vcvarsall.bat'
    if (-not (Test-Path $vcvars)) { throw "vcvarsall.bat not found under $vs" }
    @("@echo off", "call `"$vcvars`" $vcArch >nul", "if errorlevel 1 exit /b 1", $rcCmd, "if errorlevel 1 exit /b 1", $clCmd) |
        Set-Content -Path $cmdFile -Encoding ASCII
}

Write-Host "Building c2paview.dll ($Arch) -> $OutDir"
& cmd.exe /c "`"$cmdFile`""
if ($LASTEXITCODE -ne 0) { throw "Build failed (exit $LASTEXITCODE)" }

$dll = Join-Path $OutDir 'c2paview.dll'
if (-not (Test-Path $dll)) { throw "Build finished but $dll is missing" }
Write-Host "OK: $dll ($((Get-Item $dll).Length) bytes)"
