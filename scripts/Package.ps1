<#
.SYNOPSIS
    Assembles the release layout and zip from built binaries.

.DESCRIPTION
    Expects -BinDir to contain x64\ and/or arm64\ folders with c2paview.dll and
    c2paview-helper.exe. Produces dist\c2paview-tab-<version>\ and a zip + SHA256SUMS.txt.

.EXAMPLE
    .\scripts\Package.ps1 -BinDir stage\bin -OutDir dist
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string]$BinDir,
    [string]$OutDir = 'dist',
    [string]$Version
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $PSScriptRoot
if (-not $Version) {
    $toml = Get-Content (Join-Path $root 'helper\Cargo.toml') -Raw
    if ($toml -match '(?m)^version\s*=\s*"([^"]+)"') { $Version = $Matches[1] } else { $Version = '0.0.0' }
}
$name  = "c2paview-tab-$Version"
$stage = Join-Path $OutDir $name
if (Test-Path $stage) { Remove-Item $stage -Recurse -Force }
New-Item -ItemType Directory -Force -Path $stage | Out-Null

$archs = Get-ChildItem -Path $BinDir -Directory | Where-Object { $_.Name -in @('x64', 'arm64') }
if (-not $archs) { throw "No x64\ or arm64\ folder under $BinDir" }
foreach ($a in $archs) {
    $dest = Join-Path $stage "bin\$($a.Name)"
    New-Item -ItemType Directory -Force -Path $dest | Out-Null
    foreach ($f in @('c2paview.dll', 'c2paview-helper.exe')) {
        $p = Join-Path $a.FullName $f
        if (-not (Test-Path $p)) { throw "Missing $p" }
        Copy-Item $p -Destination $dest
    }
}
Copy-Item (Join-Path $root 'trust')   -Destination (Join-Path $stage 'trust')   -Recurse
Copy-Item (Join-Path $root 'samples') -Destination (Join-Path $stage 'samples') -Recurse
foreach ($f in @('scripts\Install-C2paViewTab.ps1', 'scripts\Update-TrustLists.ps1', 'README.md', 'LICENSE', 'THIRD-PARTY.md')) {
    Copy-Item (Join-Path $root $f) -Destination $stage
}

$zip = Join-Path $OutDir "$name.zip"
if (Test-Path $zip) { Remove-Item $zip -Force }
Compress-Archive -Path $stage -DestinationPath $zip -CompressionLevel Optimal

$sums = Join-Path $OutDir 'SHA256SUMS.txt'
$h = (Get-FileHash -Algorithm SHA256 $zip).Hash.ToLower()
"$h  $name.zip" | Set-Content -Path $sums -Encoding ASCII
Get-ChildItem -Path $stage -Recurse -File | ForEach-Object {
    $rel = $_.FullName.Substring($stage.Length + 1) -replace '\\', '/'
    "$((Get-FileHash -Algorithm SHA256 $_.FullName).Hash.ToLower())  $name/$rel"
} | Add-Content -Path $sums -Encoding ASCII

Write-Host "Packaged: $zip"
Get-Content $sums | Select-Object -First 1
