<#
.SYNOPSIS
    Adds (or removes) the "Content Credentials" tab in Explorer's file Properties dialog.

.DESCRIPTION
    Default (per-user) install: copies c2paview.dll, c2paview-helper.exe and the trust lists
    to %LOCALAPPDATA%\C2PAView and registers the property-sheet handler under HKCU only.
    No administrator rights, no UAC prompt, no changes for other accounts on the PC.

    With -AllUsers: installs to %ProgramFiles%\C2PAView, registers under HKLM for every
    account, and adds the handler to the "Approved" shell-extensions list (so it also works
    where the EnforceShellExtensionSecurity policy is on). Needs an elevated PowerShell.

    Nothing here contacts the network. (Update-TrustLists.ps1 is the only script that does,
    and only when you run it.)

.PARAMETER Uninstall
    Remove the registration and the installed files (combine with -AllUsers to remove a
    per-machine install).

.PARAMETER AllUsers
    Per-machine install/uninstall (HKLM + Program Files). Requires administrator rights.

.PARAMETER RestartExplorer
    Restart explorer.exe afterwards. Not required for install (the tab appears on the next
    Properties dialog), but needed to release the DLL when uninstalling or upgrading.

.PARAMETER InstallDir
    Where to install. Default: %LOCALAPPDATA%\C2PAView, or %ProgramFiles%\C2PAView with -AllUsers.

.PARAMETER SourceDir
    Folder containing bin\<arch>\ and trust\. Default: the folder this script is in, or its parent.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\Install-C2paViewTab.ps1
    powershell -ExecutionPolicy Bypass -File .\Install-C2paViewTab.ps1 -Uninstall -RestartExplorer
    # from an elevated PowerShell:
    powershell -ExecutionPolicy Bypass -File .\Install-C2paViewTab.ps1 -AllUsers
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [switch]$Uninstall,
    [switch]$AllUsers,
    [switch]$RestartExplorer,
    [string]$InstallDir,
    [string]$SourceDir
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# --- scope ----------------------------------------------------------------------------

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
if ($AllUsers -and -not $isAdmin) {
    $elevArgs = @('-ExecutionPolicy', 'Bypass', '-File', "`"$($MyInvocation.MyCommand.Path)`"", '-AllUsers')
    if ($Uninstall)       { $elevArgs += '-Uninstall' }
    if ($RestartExplorer) { $elevArgs += '-RestartExplorer' }
    if ($InstallDir)      { $elevArgs += @('-InstallDir', "`"$InstallDir`"") }
    Write-Host ''
    Write-Host '-AllUsers installs for every account on this PC (HKLM + Program Files), which needs administrator rights,' -ForegroundColor Yellow
    Write-Host 'and this PowerShell window is not elevated. Nothing has been changed.' -ForegroundColor Yellow
    Write-Host ''
    Write-Host 'Either open PowerShell with "Run as administrator" and run the same command, or paste this to elevate now:'
    Write-Host "  Start-Process powershell -Verb RunAs -ArgumentList '$($elevArgs -join ' ')'" -ForegroundColor Cyan
    Write-Host ''
    Write-Host 'Or drop -AllUsers to install just for your own account (no admin needed).'
    exit 1
}
if (-not $InstallDir) {
    $InstallDir = if ($AllUsers) { Join-Path $env:ProgramFiles 'C2PAView' } else { Join-Path $env:LOCALAPPDATA 'C2PAView' }
}
$ScopeName = if ($AllUsers) { 'all users' } else { 'the current user' }

$Clsid       = '{5E9746CC-4EDB-460C-AA85-D2718CABC7FC}'
$HandlerName = 'C2PAView'
$Description = 'C2PA View - Content Credentials property sheet'
# Same set as c2paview.com: the formats the C2PA specification defines embeddings for.
$Extensions  = @('.jpg', '.jpeg', '.jpe', '.jfif', '.png', '.webp', '.avif', '.gif', '.tif', '.tiff', '.svg',
                 '.mp4', '.mov', '.mp3', '.wav', '.pdf', '.c2pa')
$ClassesRoot = if ($AllUsers) { 'HKLM:\Software\Classes' } else { 'HKCU:\Software\Classes' }
$ApprovedKey = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Shell Extensions\Approved'

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
    # Only this user's Explorer - when elevated on a shared PC, other sessions are left alone.
    Write-Host 'Restarting Explorer (this account only)...'
    $me = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $mine = Get-CimInstance Win32_Process -Filter "Name = 'explorer.exe'" | Where-Object {
        try { (Invoke-CimMethod -InputObject $_ -MethodName GetOwnerSid).Sid -eq $me } catch { $false }
    }
    foreach ($p in $mine) { Stop-Process -Id $p.ProcessId -Force -ErrorAction SilentlyContinue }
    Start-Sleep -Seconds 2
    if (-not (Get-CimInstance Win32_Process -Filter "Name = 'explorer.exe'" | Where-Object {
            try { (Invoke-CimMethod -InputObject $_ -MethodName GetOwnerSid).Sid -eq $me } catch { $false } })) {
        Start-Process explorer.exe
    }
}

# The files this script ever writes into InstallDir. Uninstall removes these and nothing else.
$OwnedFiles = @('c2paview.dll', 'c2paview-helper.exe', 'Install-C2paViewTab.ps1', 'Update-TrustLists.ps1')
$OwnedDirs  = @('trust', 'samples', 'tmp-low')

function Remove-InstalledFiles([string]$dir) {
    # Refuse to touch a folder that does not look like ours (guards -InstallDir typos).
    if (-not (Test-Path (Join-Path $dir 'c2paview.dll')) -and -not (Test-Path (Join-Path $dir 'c2paview-helper.exe'))) {
        throw "$dir does not contain a C2PA View install (no c2paview.dll / c2paview-helper.exe); nothing deleted."
    }
    $locked = @()
    foreach ($f in $OwnedFiles) {
        $p = Join-Path $dir $f
        if (Test-Path $p) { try { Remove-Item $p -Force } catch { $locked += $p } }
    }
    Get-ChildItem -Path $dir -Filter '*.old-*' -File -ErrorAction SilentlyContinue | ForEach-Object {
        try { Remove-Item $_.FullName -Force } catch { $locked += $_.FullName }
    }
    foreach ($d in $OwnedDirs) {
        $p = Join-Path $dir $d
        if (Test-Path $p) { try { Remove-Item $p -Recurse -Force } catch { $locked += $p } }
    }
    # Remove the folder itself only if nothing foreign is left in it.
    if (-not (Get-ChildItem -Path $dir -Force -ErrorAction SilentlyContinue)) { Remove-Item $dir -Force -ErrorAction SilentlyContinue }
    return $locked
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
    Write-Host "Removing the Content Credentials tab ($ScopeName)..."
    $otherRoot = if ($AllUsers) { 'HKCU:\Software\Classes' } else { 'HKLM:\Software\Classes' }
    if (Test-Path "$otherRoot\CLSID\$Clsid") {
        $other = if ($AllUsers) { 'per-user' } else { 'per-machine' }
        $flag  = if ($AllUsers) { 'without' } else { 'with' }
        Write-Warning "A $other install is also registered; run again $flag -AllUsers to remove that one too."
    }
    if ($PSCmdlet.ShouldProcess("$ClassesRoot registry", 'remove property sheet handler')) {
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
        if ($AllUsers -and (Test-Path $ApprovedKey)) { Remove-ItemProperty -Path $ApprovedKey -Name $Clsid -ErrorAction SilentlyContinue }
        Invoke-ShellNotify
    }
    if ($RestartExplorer) { Restart-Explorer }

    if (Test-Path $InstallDir) {
        if ($PSCmdlet.ShouldProcess($InstallDir, 'delete the installed C2PA View files')) {
            $locked = Remove-InstalledFiles $InstallDir
            if ($locked.Count -eq 0) {
                Write-Host "Removed the installed files from $InstallDir"
            } else {
                $dll = Join-Path $InstallDir 'c2paview.dll'
                if (Test-Path $dll) {
                    $aside = "$dll.old-$(Get-Date -Format yyyyMMddHHmmss)"
                    try { Move-Item -Path $dll -Destination $aside -Force } catch { }
                }
                Write-Warning "Still in use by Explorer, left behind: $($locked -join ', ')"
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

Write-Host "Installing the Content Credentials tab for $ScopeName ($arch)"
Write-Host "  from: $SourceDir"
Write-Host "  to:   $InstallDir"

if ($PSCmdlet.ShouldProcess($InstallDir, 'copy files')) {
    New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
    New-Item -ItemType Directory -Force -Path (Join-Path $InstallDir 'trust') | Out-Null
    if ((Get-ChildItem -Path $InstallDir -Force -ErrorAction SilentlyContinue | Where-Object {
            $_.Name -notin ($OwnedFiles + $OwnedDirs) -and $_.Name -notlike '*.old-*' }).Count -gt 0) {
        Write-Warning "$InstallDir already contains files that are not part of C2PA View; they will be left alone, but consider a dedicated folder."
    }
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

if ($PSCmdlet.ShouldProcess("$ClassesRoot registry", 'register property sheet handler')) {
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
    if ($AllUsers) {
        # Lets the handler load even where the EnforceShellExtensionSecurity policy is on.
        New-Item -Path $ApprovedKey -Force | Out-Null
        Set-ItemProperty -Path $ApprovedKey -Name $Clsid -Value $Description
    }
    Invoke-ShellNotify
}
if ($RestartExplorer) { Restart-Explorer }

Write-Host ''
Write-Host 'Installed. Right-click an image, video, audio or PDF file > Properties > "Content Credentials" tab.'
$scopeArg = if ($AllUsers) { ' -AllUsers' } else { '' }
$howTo    = if ($AllUsers) { ' (from an elevated PowerShell)' } else { '' }
Write-Host "To remove$howTo`:  powershell -ExecutionPolicy Bypass -File `"$InstallDir\Install-C2paViewTab.ps1`" -Uninstall$scopeArg -RestartExplorer"
