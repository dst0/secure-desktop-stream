param(
    [Parameter(Mandatory = $false)]
    [string]$ControllerIp = '',
    [string]$InstallDir = '%LOCALAPPDATA%\Programs\SecureDesktopStream\Sunshine',
    [switch]$OpenPairing,
    [switch]$ClosePairing,
    [switch]$Uninstall
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

if ($Uninstall) {
    Get-NetFirewallRule -DisplayName 'SDS-*' -ErrorAction SilentlyContinue | Remove-NetFirewallRule
    Write-Output 'Removed all SDS-* Windows Defender Firewall rules.'
    exit 0
}

$parsedIp = $null
if (-not [System.Net.IPAddress]::TryParse($ControllerIp, [ref]$parsedIp) -or $parsedIp.Equals([System.Net.IPAddress]::Any) -or $parsedIp.Equals([System.Net.IPAddress]::IPv6Any)) {
    throw "ControllerIp must be a specific IPv4/IPv6 literal, not Any/unspecified: $ControllerIp"
}

$expandedDir = [Environment]::ExpandEnvironmentVariables($InstallDir)
$sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value

function Protect-PrivateDirectory([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) { New-Item -ItemType Directory -Path $Path -Force | Out-Null }
    $acl = New-Object System.Security.AccessControl.DirectorySecurity
    $acl.SetSecurityDescriptorSddlForm("O:$sid" + "D:P(A;OICI;FA;;;$sid)(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)")
    Set-Acl -LiteralPath $Path -AclObject $acl
}

Protect-PrivateDirectory (Join-Path $env:USERPROFILE 'Downloads\Moonlight')
Protect-PrivateDirectory (Join-Path $env:USERPROFILE 'Downloads\Moonlight\Outbox')
Protect-PrivateDirectory (Join-Path $expandedDir 'config')

if ($OpenPairing) {
    Get-NetFirewallRule -DisplayName 'SDS-Pairing-47989' -ErrorAction SilentlyContinue | Remove-NetFirewallRule
    New-NetFirewallRule -DisplayName 'SDS-Pairing-47989' -Direction Inbound -Action Allow -Protocol TCP -LocalPort 47989 -RemoteAddress $ControllerIp -Profile Private,Domain | Out-Null
    Write-Output "Opened 47989/tcp temporarily for pairing from $ControllerIp"
    exit 0
}

if ($ClosePairing) {
    Get-NetFirewallRule -DisplayName 'SDS-Pairing-47989' -ErrorAction SilentlyContinue | Remove-NetFirewallRule
    Write-Output 'Closed 47989/tcp pairing firewall rule'
    exit 0
}

Get-NetFirewallRule -DisplayName 'SDS-*' -ErrorAction SilentlyContinue | Remove-NetFirewallRule
New-NetFirewallRule -DisplayName 'SDS-Block-WebUI-47990' -Direction Inbound -Action Block -Protocol TCP -LocalPort 47990 | Out-Null
New-NetFirewallRule -DisplayName 'SDS-Allow-HTTPS-47984' -Direction Inbound -Action Allow -Protocol TCP -LocalPort 47984 -RemoteAddress $ControllerIp -Profile Private,Domain | Out-Null
New-NetFirewallRule -DisplayName 'SDS-Allow-RTSP-48010' -Direction Inbound -Action Allow -Protocol TCP -LocalPort 48010 -RemoteAddress $ControllerIp -Profile Private,Domain | Out-Null
New-NetFirewallRule -DisplayName 'SDS-Allow-Stream-UDP' -Direction Inbound -Action Allow -Protocol UDP -LocalPort 47998-48000 -RemoteAddress $ControllerIp -Profile Private,Domain | Out-Null
New-NetFirewallRule -DisplayName 'SDS-Allow-Mic-48002' -Direction Inbound -Action Allow -Protocol UDP -LocalPort 48002 -RemoteAddress $ControllerIp -Profile Private,Domain | Out-Null
Write-Output "Hardened Windows firewall and private directories configured for controller $ControllerIp"
