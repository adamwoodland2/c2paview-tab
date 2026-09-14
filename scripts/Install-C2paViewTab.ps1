<#
.SYNOPSIS
    Adds (or removes) the "Content Credentials" tab in Explorer's file Properties dialog.

.DESCRIPTION
    Per-user install: copies c2paview.dll, c2paview-helper.exe and the trust lists to
    %LOCALAPPDATA%\C2PAView and registers the property-sheet handler under HKCU only.
    No administrator rights, no UAC prompt, no changes for other accounts on the PC.

    Nothing here contacts the network. (Update-TrustLists.ps1 is the only script that does,
    and only when you run it.)

.PARAMETER Uninstall
    Remove the registration and the installed files.

.PARAMETER RestartExplorer
    Restart explorer.exe afterwards. Not required for install (the tab appears on the next
    Properties dialog), but needed to release the DLL when uninstalling or upgrading.

.PARAMETER InstallDir
    Where to install. Default: %LOCALAPPDATA%\C2PAView

.PARAMETER SourceDir
    Folder containing bin\<arch>\ and trust\. Default: the folder this script is in, or its parent.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\Install-C2paViewTab.ps1
    powershell -ExecutionPolicy Bypass -File .\Install-C2paViewTab.ps1 -Uninstall -RestartExplorer
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [switch]$Uninstall,
    [switch]$RestartExplorer,
    [string]$InstallDir = (Join-Path $env:LOCALAPPDATA 'C2PAView'),
    [string]$SourceDir
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$Clsid       = '{5E9746CC-4EDB-460C-AA85-D2718CABC7FC}'
$HandlerName = 'C2PAView'
$Description = 'C2PA View - Content Credentials property sheet'
# Same set as c2paview.com: the formats the C2PA specification defines embeddings for.
$Extensions  = @('.jpg', '.jpeg', '.jpe', '.jfif', '.png', '.webp', '.avif', '.gif', '.tif', '.tiff', '.svg',
                 '.mp4', '.mov', '.mp3', '.wav', '.pdf', '.c2pa')
$ClassesRoot = 'HKCU:\Software\Classes'

# --- helpers -------------------------------------------------------------------------

function Get-OsArch {
    try {
        $a = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()
        if ($a -match 'arm64') { return 'arm64' }
        if ($a -match 'x64')   { return 'x64' }
    } catch { }
    if ($env:PROCESSOR_ARCHITEW6432 -eq 'ARM64' -or $env:PROCESSOR_ARCHITECTURE -eq 'ARM64') { return 'arm64' }
    return 'x64'
}

function Invoke-ShellNotify {
    # Tell Explorer that file associations changed so it re-reads the handler list.
    if (-not ('C2paView.Native' -as [type])) {
        Add-Type -Namespace C2paView -Name Native -MemberDefinition @'
[System.Runtime.InteropServices.DllImport("shell32.dll")]
public static extern void SHChangeNotify(int wEventId, uint uFlags, System.IntPtr dwItem1, System.IntPtr dwItem2);
'@
    }
    [C2paView.Native]::SHChangeNotify(0x08000000, 0, [IntPtr]::Zero, [IntPtr]::Zero)   # SHCNE_ASSOCCHANGED
}

function Restart-Explorer {
    Write-Host 'Restarting Explorer...'
    Get-Process -Name explorer -ErrorAction SilentlyContinue | Stop-Process -Force
    Start-Sleep -Seconds 2
    if (-not (Get-Process -Name explorer -ErrorAction SilentlyContinue)) { Start-Process explorer.exe }
}

function Remove-StaleFiles([string]$dir) {
    if (Test-Path $dir) {
        Get-ChildItem -Path $dir -Filter '*.old-*' -ErrorAction SilentlyContinue | ForEach-Object {
            Remove-Item $_.FullName -Force -ErrorAction SilentlyContinue
        }
    }
}

# Copy a file that Explorer may currently have loaded: rename the old one aside first.
function Copy-Replacing([string]$from, [string]$to) {
    if (Test-Path $to) {
        try { Copy-Item -Path $from -Destination $to -Force; return } catch { }
        $aside = "$to.old-$(Get-Date -Format yyyyMMddHHmmss)"
        Move-Item -Path $to -Destination $aside -Force
    }
    Copy-Item -Path $from -Destination $to -Force
}

# --- uninstall -----------------------------------------------------------------------

if ($Uninstall) {
    Write-Host "Removing the Content Credentials tab (per-user)..."
    if ($PSCmdlet.ShouldProcess('HKCU registry', 'remove property sheet handler')) {
        foreach ($ext in $Extensions) {
            $k = "$ClassesRoot\SystemFileAssociations\$ext\shellex\PropertySheetHandlers\$HandlerName"
            if (Test-Path $k) { Remove-Item -Path $k -Recurse -Force }
            # Tidy empty parents we may have created.
            foreach ($parent in @("$ClassesRoot\SystemFileAssociations\$ext\shellex\PropertySheetHandlers",
                                  "$ClassesRoot\SystemFileAssociations\$ext\shellex",
                                  "$ClassesRoot\SystemFileAssociations\$ext")) {
                if ((Test-Path $parent) -and -not (Get-ChildItem $parent -ErrorAction SilentlyContinue) -and
                    -not ((Get-Item $parent).GetValueNames() | Where-Object { $_ })) {
                    Remove-Item -Path $parent -Force -ErrorAction SilentlyContinue
                }
            }
        }
        $ck = "$ClassesRoot\CLSID\$Clsid"
        if (Test-Path $ck) { Remove-Item -Path $ck -Recurse -Force }
        Invoke-ShellNotify
    }
    if ($RestartExplorer) { Restart-Explorer }

    if (Test-Path $InstallDir) {
        if ($PSCmdlet.ShouldProcess($InstallDir, 'delete installed files')) {
            try {
                Remove-Item -Path $InstallDir -Recurse -Force
                Write-Host "Removed $InstallDir"
            } catch {
                $dll = Join-Path $InstallDir 'c2paview.dll'
                if (Test-Path $dll) {
                    $aside = "$dll.old-$(Get-Date -Format yyyyMMddHHmmss)"
                    try { Move-Item -Path $dll -Destination $aside -Force } catch { }
                }
                Write-Warning "Some files are still in use by Explorer and were left in $InstallDir."
                Write-Warning "Run again with -RestartExplorer (or sign out and back in) and re-run -Uninstall to finish."
            }
        }
    }
    Write-Host 'Done. The tab is unregistered.'
    return
}

# --- install -------------------------------------------------------------------------

$arch = Get-OsArch
if (-not $SourceDir) {
    foreach ($cand in @($PSScriptRoot, (Split-Path -Parent $PSScriptRoot))) {
        if (Test-Path (Join-Path $cand "bin\$arch\c2paview.dll")) { $SourceDir = $cand; break }
    }
}
if (-not $SourceDir) { throw "Could not find bin\$arch\c2paview.dll next to this script. Extract the whole release zip and run the script from inside it." }
$SourceDir = (Resolve-Path $SourceDir).Path
$binDir    = Join-Path $SourceDir "bin\$arch"
$trustSrc  = Join-Path $SourceDir 'trust'
foreach ($f in @('c2paview.dll', 'c2paview-helper.exe')) {
    if (-not (Test-Path (Join-Path $binDir $f))) { throw "Missing $f in $binDir" }
}
if (-not (Test-Path (Join-Path $trustSrc 'c2pa-trust-list.pem'))) { Write-Warning "No trust lists found in $trustSrc - the tab will show 'signer not checked' for every file." }

Write-Host "Installing the Content Credentials tab for the current user ($arch)"
Write-Host "  from: $SourceDir"
Write-Host "  to:   $InstallDir"

if ($PSCmdlet.ShouldProcess($InstallDir, 'copy files')) {
    New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
    New-Item -ItemType Directory -Force -Path (Join-Path $InstallDir 'trust') | Out-Null
    Remove-StaleFiles $InstallDir
    foreach ($f in @('c2paview.dll', 'c2paview-helper.exe')) {
        Copy-Replacing (Join-Path $binDir $f) (Join-Path $InstallDir $f)
    }
    if (Test-Path $trustSrc) {
        Get-ChildItem -Path $trustSrc -File | ForEach-Object { Copy-Item $_.FullName -Destination (Join-Path $InstallDir 'trust') -Force }
    }
    # Keep the scripts alongside so the tab can be removed/updated later without the zip.
    foreach ($s in @('Install-C2paViewTab.ps1', 'Update-TrustLists.ps1')) {
        $p = Join-Path $PSScriptRoot $s
        if (Test-Path $p) { Copy-Item $p -Destination (Join-Path $InstallDir $s) -Force }
    }
    if (Test-Path (Join-Path $SourceDir 'samples\signed.jpg')) {
        New-Item -ItemType Directory -Force -Path (Join-Path $InstallDir 'samples') | Out-Null
        Copy-Item (Join-Path $SourceDir 'samples\signed.jpg') -Destination (Join-Path $InstallDir 'samples\signed.jpg') -Force
    }
    Get-ChildItem -Path $InstallDir -Recurse -File | Unblock-File -ErrorAction SilentlyContinue
}

# Self-test the helper before registering anything.
$helper = Join-Path $InstallDir 'c2paview-helper.exe'
$sample = Join-Path $InstallDir 'samples\signed.jpg'
if ((Test-Path $helper) -and (Test-Path $sample) -and -not $WhatIfPreference) {
    $out = & $helper --trust-dir (Join-Path $InstallDir 'trust') -- $sample 2>$null
    $state = ($out | Where-Object { $_ -like "STATE`t*" } | Select-Object -First 1) -replace "^STATE`t", ''
    if ($state -in @('untrusted', 'unverified', 'trusted')) {
        Write-Host "  self-test: helper OK (sample file reads as '$state')"
    } else {
        throw "The helper did not run correctly on the sample file (state='$state'). Not registering. Output:`n$($out -join "`n")"
    }
}

if ($PSCmdlet.ShouldProcess('HKCU registry', 'register property sheet handler')) {
    $dllPath = Join-Path $InstallDir 'c2paview.dll'
    $ck = "$ClassesRoot\CLSID\$Clsid"
    New-Item -Path $ck -Force | Out-Null
    Set-ItemProperty -Path $ck -Name '(default)' -Value $Description
    New-Item -Path "$ck\InprocServer32" -Force | Out-Null
    Set-ItemProperty -Path "$ck\InprocServer32" -Name '(default)' -Value $dllPath
    Set-ItemProperty -Path "$ck\InprocServer32" -Name 'ThreadingModel' -Value 'Apartment'

    foreach ($ext in $Extensions) {
        $k = "$ClassesRoot\SystemFileAssociations\$ext\shellex\PropertySheetHandlers\$HandlerName"
        New-Item -Path $k -Force | Out-Null
        Set-ItemProperty -Path $k -Name '(default)' -Value $Clsid
    }
    Invoke-ShellNotify
}
if ($RestartExplorer) { Restart-Explorer }

Write-Host ''
Write-Host 'Installed. Right-click an image, video, audio or PDF file > Properties > "Content Credentials" tab.'
Write-Host "To remove:  powershell -ExecutionPolicy Bypass -File `"$InstallDir\Install-C2paViewTab.ps1`" -Uninstall -RestartExplorer"
