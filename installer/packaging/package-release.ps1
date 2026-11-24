param(
    [string]$OutDir = '',
    [string]$Binary = '',
    [string]$Version = ''
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$installerRoot = [IO.Path]::GetFullPath((Join-Path $scriptDir '..'))
$repoRoot = [IO.Path]::GetFullPath((Join-Path $installerRoot '..'))
$outFull = if ($OutDir) { [IO.Path]::GetFullPath($OutDir) } else { Join-Path $installerRoot 'dist' }

if ($env:OS -ne 'Windows_NT') {
    throw 'package-release.ps1 must run on Windows.'
}
$arch = if ($env:PROCESSOR_ARCHITECTURE -eq 'ARM64') { 'arm64' } else { 'x64' }

if ($Binary) {
    $bin = [IO.Path]::GetFullPath($Binary)
} else {
    & cargo build --manifest-path (Join-Path $installerRoot 'Cargo.toml') --release --locked
    if ($LASTEXITCODE -ne 0) {
        throw "cargo build failed with exit code $LASTEXITCODE"
    }
    $bin = Join-Path $installerRoot 'target\release\sds-installer.exe'
}

if (-not (Test-Path -LiteralPath $bin -PathType Leaf)) {
    throw "sds-installer.exe binary missing: $bin"
}

if (-not $Version) {
    $verOut = (& $bin --version) | Select-Object -First 1
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to run $bin --version"
    }
    $parts = ($verOut -split '\s+') | Where-Object { $_ }
    $Version = if ($parts.Count -ge 2) { $parts[1] } else { '0.1.0' }
}

$revision = '0' * 40
if (Get-Command git -ErrorAction SilentlyContinue) {
    $gitRev = (& git -C $repoRoot rev-parse HEAD 2>$null)
    if ($LASTEXITCODE -eq 0 -and ($gitRev -match '^[a-fA-F0-9]{40}$')) {
        $revision = $gitRev.ToLowerInvariant()
    }
}

New-Item -ItemType Directory -Path $outFull -Force | Out-Null
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
$workDir = Join-Path ([IO.Path]::GetTempPath()) ('sds-pkg-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $workDir -Force | Out-Null

try {
    $stageDir = Join-Path $workDir 'stage'
    New-Item -ItemType Directory -Path $stageDir -Force | Out-Null
    Copy-Item -LiteralPath $bin -Destination (Join-Path $stageDir 'sds-installer.exe') -Force

    $releaseMeta = [ordered]@{
        arch     = $arch
        identity = 'local.secure-desktop-stream.Installer'
        platform = 'windows'
        revision = $revision
        version  = $Version
    } | ConvertTo-Json -Compress
    [IO.File]::WriteAllText((Join-Path $stageDir 'release.json'), ($releaseMeta + "`n"), $utf8NoBom)

    $archiveName = "sds-installer-${Version}-windows-${arch}.zip"
    $archivePath = Join-Path $outFull $archiveName
    if (Test-Path -LiteralPath $archivePath) {
        Remove-Item -LiteralPath $archivePath -Force
    }

    Add-Type -AssemblyName System.IO.Compression.FileSystem
    [System.IO.Compression.ZipFile]::CreateFromDirectory(
        $stageDir,
        $archivePath,
        [System.IO.Compression.CompressionLevel]::Optimal,
        $false
    )

    $sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $archivePath).Hash.ToLowerInvariant()
    $bytes = (Get-Item -LiteralPath $archivePath).Length

    & $bin verify-archive --archive $archivePath --sha256 $sha256 --platform windows
    if ($LASTEXITCODE -ne 0) {
        throw "verify-archive failed for $archivePath (exit $LASTEXITCODE)"
    }

    $manifestObj = [ordered]@{
        format   = 1
        version  = $Version
        revision = $revision
        builds   = [ordered]@{
            $arch = [ordered]@{
                file   = $archiveName
                sha256 = $sha256
                bytes  = $bytes
            }
        }
    }
    $manifestJson = ($manifestObj | ConvertTo-Json -Depth 4) -replace "`r`n", "`n"
    [IO.File]::WriteAllText((Join-Path $outFull 'windows-latest.json'), ($manifestJson + "`n"), $utf8NoBom)
    [IO.File]::WriteAllText((Join-Path $outFull 'SHA256SUMS-windows'), ("$sha256  $archiveName`n"), $utf8NoBom)

    Write-Output "Packaged $archivePath (sha256=$sha256, bytes=$bytes)"
} finally {
    if (Test-Path -LiteralPath $workDir) {
        Remove-Item -LiteralPath $workDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}
