param(
    [ValidateSet('All', 'Client', 'Host', 'Installer')]
    [string]$Component = 'All',
    [string]$InstallBase = (Join-Path $env:LOCALAPPDATA 'Programs\SecureDesktopStream'),
    [switch]$PurgeConfig,
    [switch]$KeepFirewall,
    [switch]$DryRun
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

if ($env:OS -ne 'Windows_NT') { throw 'The Windows uninstaller requires Windows.' }
if (-not $env:LOCALAPPDATA) { throw 'LOCALAPPDATA is required.' }

$installBaseFull = [IO.Path]::GetFullPath($InstallBase).TrimEnd('\')
if ($installBaseFull -match '^[A-Za-z]:$' -or $InstallBase.Contains('..') -or -not $installBaseFull.EndsWith('\SecureDesktopStream', [StringComparison]::OrdinalIgnoreCase)) {
    throw "Refusing unsafe InstallBase path (must resolve to ...\SecureDesktopStream): $InstallBase"
}

function Remove-SafeTarget([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) { return }
    if ($DryRun) {
        Write-Output "[dry-run] remove $Path"
        return
    }
    $item = Get-Item -LiteralPath $Path -Force
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        # Remove junction/symlink itself safely via .NET without recursing into target or shelling out.
        [System.IO.Directory]::Delete($Path, $false)
    } elseif ($item.PSIsContainer) {
        Remove-Item -LiteralPath $Path -Recurse -Force
    } else {
        Remove-Item -LiteralPath $Path -Force
    }
    Write-Output "Removed: $Path"
}

$exe = Join-Path $installBaseFull 'Installer\current\sds-installer.exe'
$delegatedClientHost = $false
if (Test-Path -LiteralPath $exe) {
    if ($Component -eq 'Client' -or $Component -eq 'Host') {
        $cliArgs = @('uninstall', '--component', $Component.ToLowerInvariant())
        if ($PurgeConfig) { $cliArgs += '--purge-config' }
        if ($KeepFirewall) { $cliArgs += '--keep-firewall' }
        if ($DryRun) { $cliArgs += '--dry-run' } else { $cliArgs += '--yes' }
        & $exe @cliArgs
        if ($LASTEXITCODE -ne 0) { throw "sds-installer uninstall failed with exit code $LASTEXITCODE" }
        exit 0
    } elseif ($Component -eq 'All') {
        foreach ($sub in @('client', 'host')) {
            $cliArgs = @('uninstall', '--component', $sub)
            if ($PurgeConfig) { $cliArgs += '--purge-config' }
            if ($KeepFirewall) { $cliArgs += '--keep-firewall' }
            if ($DryRun) { $cliArgs += '--dry-run' } else { $cliArgs += '--yes' }
            & $exe @cliArgs
            if ($LASTEXITCODE -ne 0) { throw "sds-installer uninstall ($sub) failed with exit code $LASTEXITCODE" }
        }
        $delegatedClientHost = $true
    }
}

if (-not $delegatedClientHost -and ($Component -eq 'All' -or $Component -eq 'Client')) {
    if (-not $DryRun) {
        Get-Process -Name 'Moonlight' -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    }
    $clientDir = Join-Path $installBaseFull 'Client'
    Remove-SafeTarget (Join-Path $clientDir 'current')
    Remove-SafeTarget $clientDir
}

if (-not $delegatedClientHost -and ($Component -eq 'All' -or $Component -eq 'Host')) {
    if (-not $DryRun) {
        Get-Process -Name 'sunshine' -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    }
    $hostDir = Join-Path $installBaseFull 'Sunshine'
    Remove-SafeTarget (Join-Path $hostDir 'current')
    if (-not $KeepFirewall) {
        if ($DryRun) {
            Write-Output "[dry-run] Remove-NetFirewallRule -DisplayName 'SDS-*'"
        } else {
            Get-NetFirewallRule -DisplayName 'SDS-*' -ErrorAction SilentlyContinue | Remove-NetFirewallRule
        }
    }
    if ($PurgeConfig) {
        Remove-SafeTarget $hostDir
    } else {
        Remove-SafeTarget (Join-Path $hostDir 'versions')
    }
}

if ($Component -eq 'All' -or $Component -eq 'Installer') {
    if (-not $DryRun) {
        Get-Process -Name 'sds-installer' -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    }
    $instDir = Join-Path $installBaseFull 'Installer'
    Remove-SafeTarget (Join-Path $instDir 'current')
    Remove-SafeTarget $instDir
    $shortcut = Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs\Secure Desktop Stream Installer.lnk'
    Remove-SafeTarget $shortcut
}

if ($PurgeConfig -and $Component -eq 'All') {
    Remove-SafeTarget $installBaseFull
    Remove-SafeTarget (Join-Path $env:LOCALAPPDATA 'SecureDesktopStream')
}

Write-Output "Windows uninstall complete (Component=$Component, DryRun=$DryRun, PurgeConfig=$PurgeConfig)."
