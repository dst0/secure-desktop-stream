#!/usr/bin/env python3
"""Export a manifest-admitted, relocatable AMD64 Windows test bundle.

The input is a standard sha256sum list. `source/` entries resolve beneath the
reviewed source snapshot; `tests/` entries resolve beneath its generated test
directory. No directory is copied implicitly. Generated runtime fixtures must
all be admitted, so an incomplete manifest fails rather than truncating tests.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import struct
import subprocess
import tempfile
import unicodedata
import zipfile

COMPILER_DIRECTORIES = {'CMakeFiles', 'googletest'}
GENERATED_METADATA = {'cmake_install.cmake', 'CTestTestfile.cmake', 'Makefile', 'DartConfiguration.tcl', 'libsunshine_tray_test_helpers.a'}
RESERVED = {'CON', 'PRN', 'AUX', 'NUL', *('COM' + str(i) for i in range(1, 10)), *('LPT' + str(i) for i in range(1, 10))}
RESERVED |= {prefix + number for prefix in ['COM', 'LPT'] for number in ['¹', '²', '³']}
LAUNCHER = r'''[CmdletBinding()]
param([string]$Filter = 'SdsWindowsFsTest.*:SdsFilesTest.*:Sds*HttpTest.*', [switch]$FullSuite)
function Get-NativeTestOracle {
    param([string]$XmlPath, [string[]]$RequiredCases = @(), [switch]$RequireAllCompleted)
    $answer = [ordered]@{ valid=$false; reason='missing-xml'; cases=0; executed=0; skipped=0; required_missing=@(); required_incomplete=@() }
    if (-not (Test-Path -LiteralPath $XmlPath -PathType Leaf)) { return [pscustomobject]$answer }
    try {
        $settings = [Xml.XmlReaderSettings]::new()
        $settings.DtdProcessing = [Xml.DtdProcessing]::Prohibit
        $settings.XmlResolver = $null
        $reader = [Xml.XmlReader]::Create($XmlPath, $settings)
        try {
            $document = [Xml.XmlDocument]::new()
            $document.XmlResolver = $null
            $document.Load($reader)
        } finally { $reader.Dispose() }
    } catch { $answer.reason='invalid-xml'; return [pscustomobject]$answer }
    $cases = @($document.SelectNodes('//testcase'))
    $executed = @($cases | Where-Object { $_.GetAttribute('status') -eq 'run' -and $_.GetAttribute('result') -eq 'completed' -and $null -eq $_.SelectSingleNode('skipped') })
    $answer.cases=$cases.Count; $answer.executed=$executed.Count; $answer.skipped=$cases.Count-$executed.Count
    if ($cases.Count -eq 0) { $answer.reason='no-cases'; return [pscustomobject]$answer }
    if ($executed.Count -eq 0) { $answer.reason='zero-executed'; return [pscustomobject]$answer }
    if ($RequireAllCompleted -and $answer.skipped -gt 0) { $answer.reason='noncompleted-cases'; return [pscustomobject]$answer }
    if (@($cases | Where-Object { $null -ne $_.SelectSingleNode('failure') -or $null -ne $_.SelectSingleNode('error') }).Count -gt 0) {
        $answer.reason='xml-failures'; return [pscustomobject]$answer
    }
    foreach ($required in $RequiredCases) {
        $matching = @($cases | Where-Object { ($_.GetAttribute('classname') + '.' + $_.GetAttribute('name')) -eq $required })
        if ($matching.Count -ne 1) { $answer.required_missing += $required; continue }
        if ($matching[0].GetAttribute('status') -ne 'run' -or $matching[0].GetAttribute('result') -ne 'completed' -or $null -ne $matching[0].SelectSingleNode('skipped')) {
            $answer.required_incomplete += $required
        }
    }
    if ($answer.required_missing.Count -gt 0) { $answer.reason='required-missing-or-duplicate'; return [pscustomobject]$answer }
    if ($answer.required_incomplete.Count -gt 0) { $answer.reason='required-not-completed'; return [pscustomobject]$answer }
    $answer.valid=$true; $answer.reason='passed'; return [pscustomobject]$answer
}
function Clear-NativeTestEnvironment {
    $saved = @{}; $record = @()
    foreach ($name in @('GTEST_TOTAL_SHARDS','GTEST_SHARD_INDEX','GTEST_SHARD_STATUS_FILE','SKIP_SYSTEM_TESTS','GTEST_FILTER','GTEST_REPEAT','GTEST_LIST_TESTS','GTEST_ALSO_RUN_DISABLED_TESTS','GTEST_SHUFFLE','GTEST_RANDOM_SEED','GTEST_FAIL_FAST','GTEST_OUTPUT','GTEST_CATCH_EXCEPTIONS','GTEST_THROW_ON_FAILURE','GTEST_BREAK_ON_FAILURE','GTEST_FLAGFILE')) {
        $value = [Environment]::GetEnvironmentVariable($name, 'Process')
        $saved[$name] = $value
        $record += [pscustomobject]@{ name=$name; inherited=($null -ne $value); cleared=$true }
        Remove-Item -LiteralPath ('Env:' + $name) -ErrorAction SilentlyContinue
    }
    return [pscustomobject]@{ saved=$saved; record=$record }
}
function Restore-NativeTestEnvironment {
    param($State)
    if ($null -ne $State) {
        foreach ($name in $State.saved.Keys) {
            if ($null -eq $State.saved[$name]) { Remove-Item -LiteralPath ('Env:' + $name) -ErrorAction SilentlyContinue }
            else { [Environment]::SetEnvironmentVariable($name, $State.saved[$name], 'Process') }
        }
    }
}
function Assert-CleanTestsTree {
    param([string]$TestsPath, [Collections.Generic.HashSet[string]]$ManifestedPaths)
    $testsRoot = [IO.DirectoryInfo]::new($TestsPath)
    if (-not $testsRoot.Exists) {
        throw 'Tests directory is missing.'
    }
    if ($testsRoot.Attributes -band [IO.FileAttributes]::ReparsePoint) {
        throw ('Reparse point is not allowed: ' + $testsRoot.FullName)
    }
    $queue = [Collections.Generic.Queue[IO.DirectoryInfo]]::new()
    $queue.Enqueue($testsRoot)
    while ($queue.Count -gt 0) {
        $dir = $queue.Dequeue()
        foreach ($entry in $dir.GetFileSystemInfos()) {
            if ($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) {
                throw ('Reparse point is not allowed under tests: ' + $entry.FullName)
            }
            if ($entry -is [IO.DirectoryInfo]) {
                $queue.Enqueue($entry)
            } else {
                $fullPath = [IO.Path]::GetFullPath($entry.FullName)
                if (-not $ManifestedPaths.Contains($fullPath)) {
                    throw ('Unmanifested file under tests: ' + $entry.FullName)
                }
            }
        }
    }
}
$ErrorActionPreference = 'Stop'
if ([Environment]::OSVersion.Platform -ne 'Win32NT' -or -not [Environment]::Is64BitProcess) {
    throw 'Run this bundle in native 64-bit Windows PowerShell.'
}
if ($FullSuite) { $Filter = '*' }
$acceptanceScope = if ($FullSuite) { 'full-suite' } elseif ($PSBoundParameters.ContainsKey('Filter')) { 'custom-filter' } else { 'default-windows-security' }
$requiredCases = @()
if ($acceptanceScope -ne 'custom-filter') {
    $requiredCases = @(
        'SdsWindowsFsTest.RejectsOwnedDirectoryWritableByEveryone',
        'SdsWindowsFsTest.RejectsNullDacl',
        'SdsWindowsFsTest.NewDirectoriesAndFilesStayPrivateUnderPermissiveParent',
        'SdsWindowsFsTest.RevalidatesDaclUnderRetainedDirectoryHandle',
        'SdsWindowsFsTest.ExistingWritableByEveryoneFileCannotBeListedOrRead',
        'SdsWindowsFsTest.RetainedDirectoryCannotBeRenamedAndPartIdentityCannotBeSubstituted',
        'SdsWindowsFsTest.RejectsDirectoryReparsePointWithoutTouchingTarget',
        'SdsFilesTest.ReceivedFileHasInternetZoneBeforeItIsPublished',
        'SdsFilesTest.FailedInternetZoneMarkingDiscardsPartWithoutPublishing',
        'SdsFilesTest.RechecksAuthorizationAfterIntegrityWorkAndDiscardsDeniedUpload',
        'SdsFilesTest.RechecksAuthorizationForEachCollisionAttempt',
        'SdsLargePayloadHttpTest.ClipboardPayloadAboveFourMiBTraversesTheProductionHttpsServer'
    )
}
if ($Filter -notmatch '^[A-Za-z0-9_.*?:/=-]+$') { throw 'Invalid GoogleTest filter.' }
$root = [IO.Path]::GetFullPath($PSScriptRoot)
$lease = [IO.File]::Open((Join-Path $root 'native-test.lock'), [IO.FileMode]::OpenOrCreate, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
$oldTemp = $env:TEMP
$oldTmp = $env:TMP
$oldGcovPrefix = $env:GCOV_PREFIX
$oldGcovStrip = $env:GCOV_PREFIX_STRIP
$executionEnvironment = $null
try {
$metadata = Get-Content -LiteralPath (Join-Path $root 'bundle-manifest.json') -Raw | ConvertFrom-Json
$manifestedTests = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
foreach ($entry in $metadata.files) {
    $candidate = [IO.Path]::GetFullPath((Join-Path $root $entry.path))
    if (-not $candidate.StartsWith($root + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Manifest path escapes the bundle.'
    }
    $candidateItem = Get-Item -LiteralPath $candidate -Force
    if ($candidateItem.Attributes -band [IO.FileAttributes]::ReparsePoint) {
        throw ('Bundle entry is a reparse point: ' + $entry.path)
    }
    if ((Get-FileHash -LiteralPath $candidate -Algorithm SHA256).Hash.ToLowerInvariant() -ne $entry.sha256) {
        throw ('Bundle hash mismatch: ' + $entry.path)
    }
    if ($entry.path -imatch '^tests/') {
        [void]$manifestedTests.Add($candidate)
    }
}
$tests = Join-Path $root 'tests'
if (-not $manifestedTests.Contains([IO.Path]::GetFullPath((Join-Path $tests 'test_sunshine.exe')))) {
    throw 'Native test executable missing from manifest.'
}
Assert-CleanTestsTree -TestsPath $tests -ManifestedPaths $manifestedTests
$attemptName = [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ') + '-' + [Guid]::NewGuid().ToString('N').Substring(0, 8)
$attempt = Join-Path (Join-Path $root 'runs') $attemptName
[void][IO.Directory]::CreateDirectory($attempt)
$scratch = Join-Path $attempt 'scratch'
[void][IO.Directory]::CreateDirectory($scratch)
    $env:TEMP = $scratch
    $env:TMP = $scratch
    $env:GCOV_PREFIX = Join-Path $attempt 'coverage'
    $env:GCOV_PREFIX_STRIP = '0'
    [void][IO.Directory]::CreateDirectory($env:GCOV_PREFIX)
    $executionEnvironment = Clear-NativeTestEnvironment
    $xml = Join-Path $attempt 'native-results.xml'
    $arguments = @('--gtest_color=no', ('--gtest_filter="' + $Filter + '"'), ('--gtest_output=xml:"' + $xml + '"'))
    $process = Start-Process -FilePath (Join-Path $tests 'test_sunshine.exe') -ArgumentList $arguments `
        -WorkingDirectory $tests -NoNewWindow -PassThru -Wait `
        -RedirectStandardOutput (Join-Path $attempt 'native-stdout.log') `
        -RedirectStandardError (Join-Path $attempt 'native-stderr.log')
    $oracle = Get-NativeTestOracle -XmlPath $xml -RequiredCases $requiredCases -RequireAllCompleted:($acceptanceScope -eq 'default-windows-security')
    $exitCode = $process.ExitCode
    if ($exitCode -eq 0 -and -not $oracle.valid) { $exitCode = 3 }
    $result = [ordered]@{ exit_status=$exitCode; native_exit_status=$process.ExitCode; source_digest=$metadata.source_digest; image_id=$metadata.image_id; filter=$Filter; acceptance_scope=$acceptanceScope; environment=$executionEnvironment.record; oracle=$oracle }
    $temporary = Join-Path $attempt 'native-receipt.json.tmp'
    [IO.File]::WriteAllText($temporary, ($result | ConvertTo-Json), [Text.UTF8Encoding]::new($false))
    Move-Item -LiteralPath $temporary -Destination (Join-Path $attempt 'native-receipt.json')
    Write-Output ('Native receipt: ' + (Join-Path $attempt 'native-receipt.json'))
    exit $exitCode
} finally {
    $env:TEMP = $oldTemp
    $env:TMP = $oldTmp
    $env:GCOV_PREFIX = $oldGcovPrefix
    $env:GCOV_PREFIX_STRIP = $oldGcovStrip
    Restore-NativeTestEnvironment -State $executionEnvironment
    $lease.Dispose()
}
'''


def safe_name(value):
    """Require one portable relative archive path, including Windows name rules."""
    path = PurePosixPath(value)
    if not path.parts or path.is_absolute() or path.as_posix() != value:
        raise ValueError('noncanonical bundle path: ' + repr(value))
    for part in path.parts:
        if part in {'.', '..'} or part.endswith(('.', ' ')) or any(ord(c) < 32 or c in '\\<>:"|?*' for c in part):
            raise ValueError('unsafe Windows bundle path: ' + repr(value))
        if part.split('.')[0].rstrip(' .').upper() in RESERVED:
            raise ValueError('reserved Windows bundle path: ' + repr(value))
        if part in {'.git', '.venv', 'node_modules', '.DS_Store'} or part.startswith('._'):
            raise ValueError('non-fixture metadata is forbidden: ' + repr(value))
    return path


def read_manifest(path):
    """Read an explicit fixture allowlist without silently skipping entries."""
    entries = {}
    folded = set()
    for line in Path(path).read_text(encoding='utf-8').splitlines():
        if not line or line.startswith('#'):
            continue
        match = re.fullmatch(r'([0-9a-fA-F]{64}) [ *](.+)', line)
        if not match:
            raise ValueError('invalid sha256sum fixture line')
        digest, name = match.groups()
        parsed = safe_name(name)
        if parsed.parts[0] not in {'source', 'tests'} or len(parsed.parts) < 2:
            raise ValueError('fixture must be under source/ or tests/')
        key = unicodedata.normalize('NFC', name).casefold()
        if key in folded:
            raise ValueError('duplicate/case-colliding fixture: ' + name)
        folded.add(key)
        entries[name] = digest.lower()
    if not entries:
        raise ValueError('fixture manifest is empty')
    return entries


def admitted_file(root, relative):
    """Resolve only regular files contained in the declared input tree."""
    original = root / relative
    cursor = original
    while cursor != root:
        if cursor.is_symlink():
            raise ValueError('fixture is a symlink: ' + str(relative))
        cursor = cursor.parent
    resolved = original.resolve(strict=True)
    if not resolved.is_relative_to(root.resolve()) or not resolved.is_file():
        raise ValueError('fixture is outside its declared root: ' + str(relative))
    return resolved


def require_amd64_pe(path):
    """Check PE identity without executing a Windows binary on the build host."""
    with path.open('rb') as source:
        header = source.read(64)
        if len(header) != 64 or header[:2] != b'MZ':
            raise ValueError('not a Windows PE: ' + path.name)
        offset = struct.unpack_from('<I', header, 60)[0]
        if offset > path.stat().st_size - 26:
            raise ValueError('truncated PE header: ' + path.name)
        source.seek(offset)
        header = source.read(26)
        if header[:4] != b'PE\0\0' or struct.unpack_from('<H', header, 4)[0] != 0x8664 or struct.unpack_from('<H', header, 24)[0] != 0x20b:
            raise ValueError('expected AMD64 PE32+: ' + path.name)


def runtime_fixtures(root):
    """Enumerate every generated runtime fixture, excluding only compiler internals."""
    result = set()
    for path in root.rglob('*'):
        relative = path.relative_to(root)
        if relative.parts[0] in COMPILER_DIRECTORIES:
            continue
        if path.is_symlink():
            raise ValueError('runtime fixture is a symlink: ' + relative.as_posix())
        if path.is_file() and relative.as_posix() != 'test_sunshine.exe' and relative.as_posix() not in GENERATED_METADATA:
            result.add('tests/' + relative.as_posix())
    return result


def required_source_fixtures(root):
    """Require known source fixtures; the collector verifies the independent set."""
    required = {'source/sunshine.png', 'source/tests/unit/test_video.cpp'}
    shaders = root / 'src_assets/windows/assets/shaders/directx'
    if not shaders.is_dir():
        raise ValueError('reviewed Windows shader fixture directory is missing')
    shader_files = [path for path in shaders.rglob('*') if path.is_file()]
    if not shader_files:
        raise ValueError('reviewed Windows shader fixture directory is empty')
    required.update('source/' + path.relative_to(root).as_posix() for path in shader_files)
    return required


def add_bytes(archive, name, value):
    """Write deterministic regular ZIP entries usable by Windows Expand-Archive."""
    entry = zipfile.ZipInfo(name, (1980, 1, 1, 0, 0, 0))
    entry.create_system = 0
    entry.external_attr = 0x20
    entry.compress_type = zipfile.ZIP_DEFLATED
    archive.writestr(entry, value, compresslevel=6)


def export(source_root, test_root, fixture_manifest, dlls, output, source_digest, image_id, dependency_checker=None):
    """Verify all declared input bytes before atomically publishing a complete bundle."""
    source_root, test_root, output = Path(source_root), Path(test_root), Path(output)
    if not re.fullmatch(r'[0-9a-f]{64}', source_digest) or not re.fullmatch(r'sha256:[0-9a-f]{64}', image_id):
        raise ValueError('source digest and immutable Docker image ID are required')
    if output.exists():
        raise FileExistsError('refusing to replace an existing test bundle')
    entries = read_manifest(fixture_manifest)
    missing = runtime_fixtures(test_root) - entries.keys()
    if missing:
        raise ValueError('runtime fixtures missing from allowlist: ' + ', '.join(sorted(missing)))
    missing = required_source_fixtures(source_root) - entries.keys()
    if missing:
        raise ValueError('source fixtures missing from allowlist: ' + ', '.join(sorted(missing)))
    files = {}
    for name, digest in entries.items():
        namespace, relative = name.split('/', 1)
        files[name] = (admitted_file(source_root if namespace == 'source' else test_root, relative), digest)
    reserved = {'tests/test_sunshine.exe', 'run-tests.ps1', 'bundle-manifest.json'}
    binary = admitted_file(test_root, 'test_sunshine.exe')
    require_amd64_pe(binary)
    files['tests/test_sunshine.exe'] = (binary, None)
    for dll in dlls:
        dll = Path(dll)
        if not dll.name or dll.name in {'.', '..'}:
            raise ValueError('invalid runtime DLL path: ' + repr(str(dll)))
        safe_name(dll.name)
        name = 'tests/' + dll.name
        if not dll.name.lower().endswith('.dll') or name.casefold() in {x.casefold() for x in reserved | files.keys()}:
            raise ValueError('duplicate/invalid runtime DLL: ' + dll.name)
        admitted_dll = admitted_file(dll.parent, dll.name)
        require_amd64_pe(admitted_dll)
        files[name] = (admitted_dll, None)
    if 'tests/zlib1.dll' not in {name.casefold() for name in files}:
        raise ValueError('the reviewed AMD64 runtime requires zlib1.dll')
    if any(name.casefold() in {x.casefold() for x in reserved} for name in entries):
        raise ValueError('fixture manifest collides with generated bundle files')
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='native-bundle-', dir=output.parent) as temporary:
        staged = Path(temporary) / 'bundle.zip'
        payload = []
        dependency_root = Path(temporary) / 'dependencies'
        dependency_root.mkdir()
        if dependency_checker:
            runtime_binaries = {'tests/test_sunshine.exe'} | {'tests/' + Path(path).name for path in dlls}
            for name, (path, _) in files.items():
                if name in runtime_binaries:
                    digest = hashlib.sha256()
                    with path.open('rb') as source, (dependency_root / path.name).open('xb') as target:
                        for chunk in iter(lambda: source.read(1024 * 1024), b''):
                            digest.update(chunk)
                            target.write(chunk)
                    files[name] = (path, digest.hexdigest())
            subprocess.run([str(dependency_checker), str(dependency_root)], check=True)
        with zipfile.ZipFile(staged, 'w', compression=zipfile.ZIP_DEFLATED, compresslevel=6) as archive:
            for name, (path, expected) in sorted(files.items()):
                digest = hashlib.sha256()
                entry = zipfile.ZipInfo(name, (1980, 1, 1, 0, 0, 0))
                entry.create_system = 0
                entry.external_attr = 0x20
                entry.compress_type = zipfile.ZIP_DEFLATED
                with path.open('rb') as source, archive.open(entry, 'w') as target:
                    for chunk in iter(lambda: source.read(1024 * 1024), b''):
                        digest.update(chunk)
                        target.write(chunk)
                actual = digest.hexdigest()
                if expected is not None and actual != expected:
                    raise ValueError('fixture hash mismatch: ' + name)
                payload.append({'path': name, 'sha256': actual})
            launcher = LAUNCHER.replace('\n', '\r\n').encode('utf-8')
            add_bytes(archive, 'run-tests.ps1', launcher)
            payload.append({'path': 'run-tests.ps1', 'sha256': hashlib.sha256(launcher).hexdigest()})
            metadata = {'source_digest': source_digest, 'image_id': image_id,
                        'fixture_manifest_sha256': hashlib.sha256(Path(fixture_manifest).read_bytes()).hexdigest(),
                        'runtime_paths': {'source': '../source', 'tests': '.'},
                        'files': payload,
                        'static_dependency_check': 'MSYS2-known runtime imports passed' if dependency_checker else 'not executed',
                        'native_loader_and_tests_verified': False}
            add_bytes(archive, 'bundle-manifest.json', (json.dumps(metadata, sort_keys=True, indent=2) + '\n').encode())
        with zipfile.ZipFile(staged) as archive:
            if archive.testzip() is not None or set(archive.namelist()) != {item['path'] for item in payload} | {'bundle-manifest.json'}:
                raise ValueError('bundle ZIP verification failed')
            for item in metadata['files']:
                digest = hashlib.sha256()
                with archive.open(item['path']) as source:
                    for chunk in iter(lambda: source.read(1024 * 1024), b''):
                        digest.update(chunk)
                if digest.hexdigest() != item['sha256']:
                    raise ValueError('bundle payload verification failed')
        with staged.open('rb') as source:
            os.fsync(source.fileno())
        os.link(staged, output)
        descriptor = os.open(output.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    return metadata


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ['source-root', 'test-root', 'fixture-manifest', 'output', 'source-digest', 'image-id']:
        parser.add_argument('--' + name, required=True)
    parser.add_argument('--dll', action='append', default=[])
    parser.add_argument('--dependency-checker', required=True)
    options = parser.parse_args()
    try:
        result = export(options.source_root, options.test_root, options.fixture_manifest, options.dll,
                        options.output, options.source_digest, options.image_id, options.dependency_checker)
    except (ValueError, OSError, zipfile.BadZipFile, subprocess.CalledProcessError) as error:
        raise SystemExit('refusing native test bundle: ' + str(error)) from error
    print('verified bundle files=' + str(len(result['files'])) + '; native Windows execution still required')
