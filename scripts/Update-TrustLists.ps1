<#
.SYNOPSIS
    Refreshes the bundled C2PA trust lists from their official sources.

.DESCRIPTION
    This is the ONLY part of C2PA View that uses the network, and only when you run it.
    It downloads the C2PA Conformance Program trust lists and the interim Content
    Credentials (CAI) lists, validates them, and replaces the copies in the trust folder
    atomically. A VERSION.txt records the date and sources; the tab shows that date under
    "About this check".

.PARAMETER TrustDir
    Folder to update. Default: %LOCALAPPDATA%\C2PAView\trust if installed, else .\trust
    relative to this script's parent folder.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\Update-TrustLists.ps1
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$TrustDir
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

if (-not $TrustDir) {
    $installed = Join-Path $env:LOCALAPPDATA 'C2PAView\trust'
    $local     = Join-Path $PSScriptRoot 'trust'
    $parent    = Join-Path (Split-Path -Parent $PSScriptRoot) 'trust'
    $TrustDir  = @($installed, $local, $parent) | Where-Object { Test-Path $_ } | Select-Object -First 1
    if (-not $TrustDir) { $TrustDir = $installed }
}
New-Item -ItemType Directory -Force -Path $TrustDir | Out-Null

$Sources = @(
    @{ File = 'c2pa-trust-list.pem';        Url = 'https://raw.githubusercontent.com/c2pa-org/conformance-public/main/trust-list/C2PA-TRUST-LIST.pem';     Check = '-----BEGIN CERTIFICATE-----' },
    @{ File = 'c2pa-tsa-trust-list.pem';    Url = 'https://raw.githubusercontent.com/c2pa-org/conformance-public/main/trust-list/C2PA-TSA-TRUST-LIST.pem'; Check = '-----BEGIN CERTIFICATE-----' },
    @{ File = 'interim-anchors.pem';        Url = 'https://contentcredentials.org/trust/anchors.pem';                                                        Check = '-----BEGIN CERTIFICATE-----' },
    @{ File = 'interim-allowed.sha256.txt'; Url = 'https://contentcredentials.org/trust/allowed.sha256.txt';                                                 Check = '[0-9A-Fa-f]{64}|[A-Za-z0-9+/=]{40,}' },
    @{ File = 'store.cfg';                  Url = 'https://contentcredentials.org/trust/store.cfg';                                                          Check = '\d+(\.\d+){3,}' }
)

$tmp = Join-Path ([IO.Path]::GetTempPath()) ("c2paview-trust-" + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Force -Path $tmp | Out-Null
$ok = $true
try {
    foreach ($s in $Sources) {
        Write-Host "Downloading $($s.File) ..."
        $dest = Join-Path $tmp $s.File
        try {
            Invoke-WebRequest -Uri $s.Url -OutFile $dest -UseBasicParsing -TimeoutSec 60
        } catch {
            Write-Warning "  failed: $($_.Exception.Message)"
            $ok = $false; continue
        }
        $body = Get-Content -Path $dest -Raw -ErrorAction SilentlyContinue
        if (-not $body -or $body -notmatch $s.Check) {
            Write-Warning "  $($s.File) did not look valid (expected /$($s.Check)/). Keeping the existing copy."
            Remove-Item $dest -Force -ErrorAction SilentlyContinue
            $ok = $false
        }
    }

    $downloaded = Get-ChildItem -Path $tmp -File
    if (-not $downloaded) { throw 'Nothing was downloaded; trust lists unchanged.' }

    if ($PSCmdlet.ShouldProcess($TrustDir, "replace $($downloaded.Count) trust list file(s)")) {
        foreach ($f in $downloaded) {
            Move-Item -Path $f.FullName -Destination (Join-Path $TrustDir $f.Name) -Force
        }
        $stamp = (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd')
        $lines = @($stamp, "# Trust list snapshot fetched $stamp UTC by Update-TrustLists.ps1", "# Sources:")
        $lines += $Sources | ForEach-Object { "#   $($_.File) <- $($_.Url)" }
        Set-Content -Path (Join-Path $TrustDir 'VERSION.txt') -Value $lines -Encoding UTF8
        Write-Host "Trust lists updated in $TrustDir ($stamp)."
        if (-not $ok) { Write-Warning 'One or more lists could not be refreshed; the previous copies of those were kept.' }
    }
} finally {
    Remove-Item -Path $tmp -Recurse -Force -ErrorAction SilentlyContinue
}
