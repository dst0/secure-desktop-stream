param(
    [string]$ReleaseBase = '',
    [string]$ArchivePath = '',
    [string]$ExpectedSha256 = '',
    [string]$InstallRoot = (Join-Path $env:LOCALAPPDATA 'Programs\SecureDesktopStream\Installer'),
    [switch]$FromSource,
    [switch]$AutoDeps,
    [switch]$AllowUnsigned,
    [switch]$NoGui,
    [switch]$DryRun
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

if ($env:OS -ne 'Windows_NT') { throw 'The Windows installer requires Windows.' }
if (-not $env:LOCALAPPDATA) { throw 'LOCALAPPDATA is required for per-user installation.' }

if (-not ('Sds.WindowsInstallerInterop' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.IO;
using System.Text;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
namespace Sds {
    public static class WindowsInstallerInterop {
        [StructLayout(LayoutKind.Sequential)] private struct SecurityAttributes {
            public int Length;
            public IntPtr SecurityDescriptor;
            public bool InheritHandle;
        }
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool ConvertStringSecurityDescriptorToSecurityDescriptorW(string value, uint revision, out IntPtr descriptor, IntPtr size);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool CreateDirectoryW(string path, ref SecurityAttributes attributes);
        [DllImport("kernel32.dll")] private static extern IntPtr LocalFree(IntPtr memory);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern SafeFileHandle CreateFileW(string path, uint access, uint share, IntPtr security, uint creation, uint flags, IntPtr template);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool DeviceIoControl(SafeFileHandle handle, uint code, IntPtr input, uint inputLength, byte[] output, uint outputLength, out uint returned, IntPtr overlapped);
        public static void CreatePrivateDirectory(string path, string sid) {
            string sddl = "O:" + sid + "D:P(A;OICI;FA;;;" + sid + ")(A;OICI;FA;;;SY)";
            IntPtr descriptor;
            if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, 1, out descriptor, IntPtr.Zero))
                throw new Win32Exception(Marshal.GetLastWin32Error());
            try {
                var attributes = new SecurityAttributes { Length = Marshal.SizeOf(typeof(SecurityAttributes)), SecurityDescriptor = descriptor, InheritHandle = false };
                if (!CreateDirectoryW(path, ref attributes)) {
                    int code = Marshal.GetLastWin32Error();
                    if (code != 183) throw new Win32Exception(code);
                }
            } finally { LocalFree(descriptor); }
        }
        public static string GetJunctionTarget(string path) {
            const uint FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000;
            const uint FILE_FLAG_BACKUP_SEMANTICS = 0x02000000;
            const uint FSCTL_GET_REPARSE_POINT = 0x000900A8;
            using (SafeFileHandle handle = CreateFileW(path, 0x80000000, 7, IntPtr.Zero, 3, FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS, IntPtr.Zero)) {
                if (handle.IsInvalid) throw new Win32Exception(Marshal.GetLastWin32Error());
                byte[] buffer = new byte[16384];
                uint returned;
                if (!DeviceIoControl(handle, FSCTL_GET_REPARSE_POINT, IntPtr.Zero, 0, buffer, (uint)buffer.Length, out returned, IntPtr.Zero))
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                if (returned < 16 || BitConverter.ToUInt32(buffer, 0) != 0xA0000003) throw new IOException("Current install path is not a directory junction.");
                ushort offset = BitConverter.ToUInt16(buffer, 8);
                ushort length = BitConverter.ToUInt16(buffer, 10);
                if (16 + offset + length > returned || (length % 2) != 0) throw new IOException("Current junction target is malformed.");
                string target = Encoding.Unicode.GetString(buffer, 16 + offset, length);
                if (target.StartsWith("\\??\\UNC\\", StringComparison.OrdinalIgnoreCase)) return "\\\\" + target.Substring(8);
                if (target.StartsWith("\\??\\", StringComparison.OrdinalIgnoreCase)) return target.Substring(4);
                return target;
            }
        }
    }
}
'@
}

function Resolve-FullPath([string]$Path) { return [IO.Path]::GetFullPath($Path) }

function Assert-NoReparseAncestors([string]$Path) {
    $current = Split-Path -Parent (Resolve-FullPath $Path)
    while ($current) {
        if (Test-Path -LiteralPath $current) {
            $item = Get-Item -LiteralPath $current -Force
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "Reparse point in private install path: $current"
            }
        }
        $parent = Split-Path -Parent $current
        if (-not $parent -or $parent -eq $current) { break }
        $current = $parent
    }
}

function Ensure-PrivateDirectory([string]$Path) {
    Assert-NoReparseAncestors $Path
    if (-not (Test-Path -LiteralPath $Path)) {
        $parent = Split-Path -Parent $Path
        if ($parent -and -not (Test-Path -LiteralPath $parent)) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }
        $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
        [Sds.WindowsInstallerInterop]::CreatePrivateDirectory($Path, $sid)
        return
    }
    if (((Get-Item -LiteralPath $Path -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "Private install directory cannot be a reparse point: $Path"
    }
    $acl = Get-Acl -LiteralPath $Path
    $allowed = @([Security.Principal.WindowsIdentity]::GetCurrent().User.Value, 'S-1-5-18', 'S-1-5-32-544')
    foreach ($rule in $acl.Access) {
        $sid = $rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
        if ($sid -notin $allowed) { throw "Install directory grants access to another identity: $Path" }
    }
}

function Assert-PeHeader([string]$ExePath, [string]$ExpectedArch) {
    $bytes = [IO.File]::ReadAllBytes($ExePath)
    if ($bytes.Length -lt 64 -or $bytes[0] -ne 0x4D -or $bytes[1] -ne 0x5A) { throw "Not a valid PE file: $ExePath" }
    $peOff = [BitConverter]::ToInt32($bytes, 60)
    if ($peOff -lt 0 -or $peOff + 6 -gt $bytes.Length) { throw "Malformed PE header: $ExePath" }
    if ($bytes[$peOff] -ne 0x50 -or $bytes[$peOff + 1] -ne 0x45 -or $bytes[$peOff + 2] -ne 0 -or $bytes[$peOff + 3] -ne 0) {
        throw "Missing PE signature: $ExePath"
    }
    $machine = [BitConverter]::ToUInt16($bytes, $peOff + 4)
    $wanted = if ($ExpectedArch -eq 'arm64') { 0xAA64 } else { 0x8664 }
    if ($machine -ne $wanted) { throw ("Unexpected PE machine 0x{0:X4} for arch {1}" -f $machine, $ExpectedArch) }
}

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$installerRoot = Resolve-FullPath (Join-Path $scriptDir '..')
if (-not $FromSource -and -not $ArchivePath -and -not $ReleaseBase) {
    if (Test-Path -LiteralPath (Join-Path $installerRoot 'Cargo.toml')) { $FromSource = $true }
    else { throw 'Specify -FromSource, -ArchivePath + -ExpectedSha256, or -ReleaseBase.' }
}

$procArch = if ([Environment]::Is64BitOperatingSystem) {
    if ($env:PROCESSOR_ARCHITECTURE -eq 'ARM64') { 'arm64' } else { 'x64' }
} else { throw '64-bit Windows is required.' }
$expectedPeArch = if ($procArch -eq 'arm64') { 'arm64' } else { 'x86_64' }

$installRootFull = Resolve-FullPath $InstallRoot
$workDir = Join-Path ([IO.Path]::GetTempPath()) ('sds-win-inst-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $workDir -Force | Out-Null

try {
    $payloadDir = Join-Path $workDir 'payload'
    New-Item -ItemType Directory -Path $payloadDir -Force | Out-Null
    $revisionTag = 'local-source'

    if ($FromSource) {
        $manifestCargo = Join-Path $installerRoot 'Cargo.toml'
        if (-not (Test-Path -LiteralPath $manifestCargo)) { throw 'Missing installer/Cargo.toml for -FromSource.' }
        if ($DryRun) {
            Write-Output "Dry run: would build $manifestCargo with cargo build --release --locked and install to $installRootFull"
            exit 0
        }
        if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
            if ($AutoDeps -and (Get-Command winget -ErrorAction SilentlyContinue)) {
                Write-Output 'Installing Rustup & Git via winget (-AutoDeps)...'
                & winget install --id Rustlang.Rustup -e --silent --accept-package-agreements --accept-source-agreements
                $cargoBin = Join-Path $env:USERPROFILE '.cargo\bin'
                if (Test-Path -LiteralPath $cargoBin) { $env:PATH = "$cargoBin;$env:PATH" }
            }
        }
        if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
            throw 'Rust cargo is required for -FromSource. Install Rustup (winget install Rustlang.Rustup) or pass -AutoDeps.'
        }
        & cargo build --manifest-path $manifestCargo --release --locked
        if ($LASTEXITCODE -ne 0) { throw "cargo build failed with exit code $LASTEXITCODE" }
        $builtExe = Join-Path $installerRoot 'target\release\sds-installer.exe'
        if (-not (Test-Path -LiteralPath $builtExe)) { throw "Built executable missing: $builtExe" }
        Copy-Item -LiteralPath $builtExe -Destination (Join-Path $payloadDir 'sds-installer.exe') -Force
        $revisionTag = (Get-FileHash -Algorithm SHA256 -LiteralPath $builtExe).Hash.ToLowerInvariant().Substring(0, 16)
    } else {
        $zipFile = Join-Path $workDir 'release.zip'
        $expectedHash = ''
        if ($ArchivePath) {
            if ($ExpectedSha256 -notmatch '^[0-9a-fA-F]{64}$') { throw '-ExpectedSha256 (64 hex chars) is required with -ArchivePath.' }
            $expectedHash = $ExpectedSha256.ToLowerInvariant()
            Copy-Item -LiteralPath $ArchivePath -Destination $zipFile -Force
        } else {
            if ($ReleaseBase -notmatch '^https://') { throw '-ReleaseBase must start with https://' }
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13
            $manifestUri = $ReleaseBase.TrimEnd('/') + '/windows-latest.json'
            try {
                $manifest = Invoke-RestMethod -Uri $manifestUri -TimeoutSec 30
            } catch {
                throw "Failed to fetch release manifest ($manifestUri). If prebuilt releases are not published yet, clone the repo and pass -FromSource -AllowUnsigned. Underlying error: $($_.Exception.Message)"
            }
            $build = $manifest.builds.$procArch
            if (-not $build) { throw "No Windows build for $procArch in manifest." }
            if ($build.file -notmatch '^sds-installer-[A-Za-z0-9._-]+-windows-(x64|arm64)\.zip$') { throw 'Invalid release filename.' }
            $expectedHash = ([string]$build.sha256).ToLowerInvariant()
            if ($expectedHash -notmatch '^[0-9a-f]{64}$') { throw 'Invalid SHA-256 in manifest.' }
            Invoke-WebRequest -Uri ($ReleaseBase.TrimEnd('/') + '/' + $build.file) -OutFile $zipFile -TimeoutSec 120
        }
        $actualHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $zipFile).Hash.ToLowerInvariant()
        if ($actualHash -ne $expectedHash) { throw "Archive SHA-256 mismatch: expected $expectedHash, got $actualHash" }
        $revisionTag = $expectedHash.Substring(0, 16)
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        $zipReader = [System.IO.Compression.ZipFile]::OpenRead($zipFile)
        try {
            $entryCount = 0
            [int64]$totalUncompressed = 0
            $seenNames = @{}
            foreach ($entry in $zipReader.Entries) {
                $entryCount++
                if ($entryCount -gt 1000) { throw 'ZIP exceeds maximum 1000 entries.' }
                $name = $entry.FullName
                if ([string]::IsNullOrEmpty($name) -or $name.StartsWith('/') -or $name.StartsWith('\') -or ($name -match '^[A-Za-z]:')) {
                    throw "Unsafe archive path in ZIP: $name"
                }
                $norm = $name.Replace('\', '/')
                foreach ($seg in $norm.Split('/')) {
                    if ($seg -eq '..') { throw "Path traversal in ZIP entry: $name" }
                }
                $lower = $norm.ToLowerInvariant()
                if ($seenNames.ContainsKey($lower)) { throw "Duplicate or colliding ZIP entry: $name" }
                $seenNames[$lower] = $true
                $totalUncompressed += $entry.Length
                if ($totalUncompressed -gt 268435456) { throw 'ZIP uncompressed size exceeds 256 MiB limit.' }
            }
        } finally {
            $zipReader.Dispose()
        }
        Expand-Archive -LiteralPath $zipFile -DestinationPath $payloadDir -Force
    }

    foreach ($entry in @(Get-ChildItem -LiteralPath $payloadDir -Force -Recurse)) {
        if (($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw "Refusing reparse point in payload: $($entry.FullName)" }
    }
    $exePath = Join-Path $payloadDir 'sds-installer.exe'
    if (-not (Test-Path -LiteralPath $exePath -PathType Leaf)) { throw 'sds-installer.exe missing in payload.' }
    Assert-PeHeader $exePath $expectedPeArch

    if ($DryRun) {
        Write-Output "Dry run complete: verified payload ($revisionTag) for $installRootFull"
        exit 0
    }

    $versionRoot = Join-Path $installRootFull 'versions'
    $versionPath = Join-Path $versionRoot $revisionTag
    $currentPath = Join-Path $installRootFull 'current'
    Ensure-PrivateDirectory $installRootFull
    Ensure-PrivateDirectory $versionRoot

    if (-not (Test-Path -LiteralPath $versionPath)) {
        $stagePath = Join-Path $versionRoot ('.install-' + [Guid]::NewGuid().ToString('N'))
        Ensure-PrivateDirectory $stagePath
        try {
            Copy-Item -LiteralPath (Join-Path $payloadDir '*') -Destination $stagePath -Recurse -Force
            if ($AllowUnsigned) {
                # Only unblock verified payload after SHA-256 check; SmartScreen stays enabled globally.
                Get-ChildItem -LiteralPath $stagePath -Recurse -File | Unblock-File
            }
            [IO.Directory]::Move($stagePath, $versionPath)
        } catch {
            if (Test-Path -LiteralPath $stagePath) { Remove-Item -LiteralPath $stagePath -Recurse -Force -ErrorAction SilentlyContinue }
            throw
        }
    }

    $nextPath = Join-Path $installRootFull ('.current-' + [Guid]::NewGuid().ToString('N'))
    $oldPath = Join-Path $installRootFull ('.current-old-' + [Guid]::NewGuid().ToString('N'))
    $hadCurrent = Test-Path -LiteralPath $currentPath
    if ($hadCurrent) {
        $curItem = Get-Item -LiteralPath $currentPath -Force
        if (($curItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) { throw "Refusing non-junction current path: $currentPath" }
        $prevTarget = Resolve-FullPath ([Sds.WindowsInstallerInterop]::GetJunctionTarget($currentPath))
        $prefix = (Resolve-FullPath $versionRoot).TrimEnd('\') + '\'
        if (-not $prevTarget.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) { throw 'Existing current junction escapes version store.' }
    }
    New-Item -ItemType Junction -Path $nextPath -Target $versionPath | Out-Null
    try {
        if ($hadCurrent) { [IO.Directory]::Move($currentPath, $oldPath) }
        [IO.Directory]::Move($nextPath, $currentPath)
    } catch {
        if ($hadCurrent -and -not (Test-Path -LiteralPath $currentPath) -and (Test-Path -LiteralPath $oldPath)) {
            [IO.Directory]::Move($oldPath, $currentPath)
        }
        if (Test-Path -LiteralPath $nextPath) { Remove-Item -LiteralPath $nextPath -Force -ErrorAction SilentlyContinue }
        throw
    }
    if (Test-Path -LiteralPath $oldPath) { Remove-Item -LiteralPath $oldPath -Force -ErrorAction SilentlyContinue }

    $startMenu = Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs'
    New-Item -ItemType Directory -Path $startMenu -Force | Out-Null
    $shell = New-Object -ComObject WScript.Shell
    $shortcut = $shell.CreateShortcut((Join-Path $startMenu 'Secure Desktop Stream Installer.lnk'))
    $shortcut.TargetPath = Join-Path $currentPath 'sds-installer.exe'
    $shortcut.Arguments = 'gui'
    $shortcut.WorkingDirectory = $currentPath
    $shortcut.Save()

    Write-Output "Installed Secure Desktop Stream Installer at $currentPath"
    if (-not $NoGui) {
        & (Join-Path $currentPath 'sds-installer.exe') gui
    }
} finally {
    if (Test-Path -LiteralPath $workDir) { Remove-Item -LiteralPath $workDir -Recurse -Force -ErrorAction SilentlyContinue }
}
