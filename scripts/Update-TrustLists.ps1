<#
.SYNOPSIS
    Refreshes the bundled C2PA trust lists from their official sources.

.DESCRIPTION
    This is the ONLY part of C2PA View that uses the network, and only when you run it.
    It downloads the C2PA Conformance Program trust lists and the interim Content
    Credentials (CAI) lists, validates them, and replaces the copies in the trust folder
    only if every one of them downloaded and validated - otherwise nothing changes. A
    VERSION.txt records the date and sources; the tab shows that date under "About this check".

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

    $downloaded = @(Get-ChildItem -Path $tmp -File)
    if (-not $ok -or $downloaded.Count -ne $Sources.Count) {
        throw "Not every list could be downloaded and validated ($($downloaded.Count) of $($Sources.Count)). Nothing was changed - the existing snapshot is untouched."
    }

    # All-or-nothing: swap the complete set in, then stamp the date that describes it.
    if ($PSCmdlet.ShouldProcess($TrustDir, "replace all $($Sources.Count) trust list files")) {
        $stamp = (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd')
        $lines = @($stamp, "# Trust list snapshot fetched $stamp UTC by Update-TrustLists.ps1", "# Sources:")
        $lines += $Sources | ForEach-Object { "#   $($_.File) <- $($_.Url)" }
        Set-Content -Path (Join-Path $tmp 'VERSION.txt') -Value $lines -Encoding UTF8
        $backup = "$TrustDir.previous"
        if (Test-Path $backup) { Remove-Item $backup -Recurse -Force }
        Copy-Item -Path $TrustDir -Destination $backup -Recurse -Force
        try {
            foreach ($f in @(Get-ChildItem -Path $tmp -File)) {
                Move-Item -Path $f.FullName -Destination (Join-Path $TrustDir $f.Name) -Force
            }
            Remove-Item $backup -Recurse -Force -ErrorAction SilentlyContinue
        } catch {
            Copy-Item -Path (Join-Path $backup '*') -Destination $TrustDir -Force
            Remove-Item $backup -Recurse -Force -ErrorAction SilentlyContinue
            throw "Replacing the trust lists failed part-way; the previous snapshot was restored. $($_.Exception.Message)"
        }
        Write-Host "Trust lists updated in $TrustDir ($stamp)."
    }
} finally {
    Remove-Item -Path $tmp -Recurse -Force -ErrorAction SilentlyContinue
}
