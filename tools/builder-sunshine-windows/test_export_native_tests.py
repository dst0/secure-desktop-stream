#!/usr/bin/env python3
"""Behavioral tests for manifest-only Windows native test delivery."""

import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile
import unittest
import zipfile

SPEC = importlib.util.spec_from_file_location('export_native_tests', Path(__file__).with_name('export-native-tests.py'))
EXPORTER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(EXPORTER)


class NativeTestBundleTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.base = Path(self.temporary.name)
        self.source = self.base / 'source-input'
        self.tests = self.base / 'test-input'
        self.source.mkdir()
        self.tests.mkdir()
        self.manifest = self.base / 'fixtures.sha256'
        self.output = self.base / 'native-tests.zip'
        self.digest = 'a' * 64
        self.image = 'sha256:' + 'b' * 64
        self.dll = self.base / 'zlib1.dll'
        self.write_pe(self.tests / 'test_sunshine.exe')
        self.write_pe(self.dll)
        self.entries = {}
        self.fixture('source/tests/unit/test_video.cpp', b'synthetic source fixture')
        self.fixture('source/sunshine.png', b'synthetic image fixture')
        self.fixture('source/src_assets/windows/assets/shaders/directx/test.hlsl', b'synthetic shader fixture')
        self.fixture('tests/test_assets/icon.svg', b'<svg/>')
        self.fixture('tests/src_assets/common/assets/web/public/assets/locale/en.json', b'{"a":"one"}')
        self.fixture('tests/src_assets/common/assets/web/public/assets/locale/uk.json', b'{"a":"two"}')
        self.write_manifest()

    def tearDown(self):
        self.temporary.cleanup()

    @staticmethod
    def write_pe(path, machine=0x8664):
        data = bytearray(256)
        data[:2] = b'MZ'
        struct.pack_into('<I', data, 60, 128)
        data[128:132] = b'PE\0\0'
        struct.pack_into('<H', data, 132, machine)
        struct.pack_into('<H', data, 152, 0x20b)
        path.write_bytes(data)

    def fixture(self, name, data):
        namespace, relative = name.split('/', 1)
        path = (self.source if namespace == 'source' else self.tests) / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        self.entries[name] = hashlib.sha256(data).hexdigest()

    def write_manifest(self):
        self.manifest.write_text(''.join(f'{digest}  {name}\n' for name, digest in sorted(self.entries.items())))

    def export(self, **overrides):
        args = dict(source_root=self.source, test_root=self.tests, fixture_manifest=self.manifest,
                    dlls=[self.dll], output=self.output, source_digest=self.digest, image_id=self.image)
        args.update(overrides)
        return EXPORTER.export(**args)

    def test_preserves_all_admitted_fixtures_and_does_not_copy_unlisted_source(self):
        (self.source / 'private.pem').write_text('synthetic non-fixture, must not ship')
        compiler = self.tests / 'CMakeFiles' / 'compiler.obj'
        compiler.parent.mkdir()
        compiler.write_bytes(b'compiler output is not a fixture')
        metadata = self.export()
        self.assertFalse(metadata['native_loader_and_tests_verified'])
        with zipfile.ZipFile(self.output) as archive:
            self.assertEqual(set(archive.namelist()), set(self.entries) | {'tests/test_sunshine.exe', 'tests/zlib1.dll', 'run-tests.ps1', 'bundle-manifest.json'})
            for name in self.entries:
                self.assertEqual(hashlib.sha256(archive.read(name)).hexdigest(), self.entries[name])
            self.assertNotIn('source/private.pem', archive.namelist())
            self.assertEqual(json.loads(archive.read('bundle-manifest.json'))['runtime_paths'], {'source': '../source', 'tests': '.'})

    def test_omitted_runtime_fixture_is_a_failure_not_a_truncated_bundle(self):
        for name, message in [('tests/src_assets/common/assets/web/public/assets/locale/uk.json', 'runtime fixtures missing'), ('source/src_assets/windows/assets/shaders/directx/test.hlsl', 'source fixtures missing')]:
            with self.subTest(name=name):
                digest = self.entries.pop(name)
                self.write_manifest()
                with self.assertRaisesRegex(ValueError, message):
                    self.export()
                self.assertFalse(self.output.exists())
                self.entries[name] = digest

    def test_changed_fixture_fails_before_publication(self):
        (self.source / 'tests/unit/test_video.cpp').write_text('changed after admission')
        with self.assertRaisesRegex(ValueError, 'fixture hash mismatch'):
            self.export()
        self.assertFalse(self.output.exists())

    def test_existing_output_is_preserved(self):
        self.output.write_bytes(b'previous immutable receipt')
        with self.assertRaises(FileExistsError):
            self.export()
        self.assertEqual(self.output.read_bytes(), b'previous immutable receipt')

    def test_invalid_paths_and_metadata_are_rejected(self):
        for name in ['../escape', 'tests/../escape', 'tests/C:escape', 'tests/CON.txt', 'tests/COM¹', 'source/.git/config', 'source/node_modules/key', 'tests/._metadata', 'tests/a.']:
            with self.subTest(name=name):
                self.manifest.write_text('a' * 64 + '  ' + name + '\n')
                with self.assertRaises(ValueError):
                    self.export()
                self.assertFalse(self.output.exists())

    def test_case_collisions_are_rejected(self):
        self.manifest.write_text('a' * 64 + '  source/A.txt\n' + 'b' * 64 + '  source/a.txt\n')
        with self.assertRaisesRegex(ValueError, 'case-colliding'):
            self.export()

    def test_external_symlink_cannot_enter_bundle(self):
        outside = self.base / 'outside'
        outside.write_bytes(b'synthetic outside data')
        link = self.source / 'link.txt'
        link.symlink_to(outside)
        self.entries['source/link.txt'] = hashlib.sha256(outside.read_bytes()).hexdigest()
        self.write_manifest()
        with self.assertRaisesRegex(ValueError, 'symlink'):
            self.export()

    def test_symlink_dll_is_rejected(self):
        real_dll = self.base / 'real.dll'
        self.write_pe(real_dll)
        sym_dll = self.base / 'sym.dll'
        sym_dll.symlink_to(real_dll)
        with self.assertRaisesRegex(ValueError, 'symlink'):
            self.export(dlls=[self.dll, sym_dll])
        self.assertFalse(self.output.exists())

    def test_requires_amd64_pe_and_zlib_runtime(self):
        self.write_pe(self.tests / 'test_sunshine.exe', machine=0xaa64)
        with self.assertRaisesRegex(ValueError, 'AMD64'):
            self.export()
        self.write_pe(self.tests / 'test_sunshine.exe')
        with self.assertRaisesRegex(ValueError, 'zlib1.dll'):
            self.export(dlls=[])
        self.assertFalse(self.output.exists())

    def test_bad_provenance_or_dependency_failure_cannot_publish(self):
        with self.assertRaisesRegex(ValueError, 'digest'):
            self.export(source_digest='unknown')
        checker = self.base / 'check-dependencies.sh'
        checker.write_text('#!/bin/sh\nexit 1\n')
        checker.chmod(0o700)
        with self.assertRaises(subprocess.CalledProcessError):
            self.export(dependency_checker=checker)
        self.assertFalse(self.output.exists())
        binary = self.tests / 'test_sunshine.exe'
        checker.write_text('#!/usr/bin/env python3\nfrom pathlib import Path\np=Path(' + repr(str(binary)) + ')\np.write_bytes(p.read_bytes()+b"changed after dependency inspection")\n')
        with self.assertRaisesRegex(ValueError, 'fixture hash mismatch'):
            self.export(dependency_checker=checker)
        self.assertFalse(self.output.exists())

    def test_native_launcher_parses_and_windows_zip_extraction_preserves_all_files(self):
        executable = shutil.which('pwsh')
        if executable is None:
            self.skipTest('PowerShell parser/Expand-Archive unavailable on this test host')
        self.export()
        destination = self.base / 'expanded'
        script = '''param($Archive,$Destination)
$ErrorActionPreference = 'Stop'
Expand-Archive -LiteralPath $Archive -DestinationPath $Destination
$tokens = $null; $errors = $null
[void][System.Management.Automation.Language.Parser]::ParseFile((Join-Path $Destination 'run-tests.ps1'), [ref]$tokens, [ref]$errors)
if ($errors.Count -gt 0) { throw 'Generated launcher has PowerShell syntax errors' }
'''
        parser = self.base / 'parse-and-expand.ps1'
        parser.write_text(script)
        subprocess.run([executable, '-NoLogo', '-NoProfile', '-NonInteractive', '-File', str(parser), str(self.output), str(destination)], check=True, capture_output=True, text=True)
        for item in json.loads((destination / 'bundle-manifest.json').read_text())['files']:
            self.assertEqual(hashlib.sha256((destination / item['path']).read_bytes()).hexdigest(), item['sha256'])

    def test_launcher_oracle_rejects_zero_skipped_missing_and_failed_security_cases(self):
        executable = shutil.which('pwsh')
        if executable is None:
            self.skipTest('PowerShell oracle runner unavailable on this test host')
        launcher = self.base / 'launcher.ps1'
        launcher.write_text(EXPORTER.LAUNCHER)
        passed = '<testcase classname="Security" name="required" status="run" result="completed"/>'
        other = '<testcase classname="Other" name="passed" status="run" result="completed"/>'
        skipped = '<testcase classname="Security" name="required" status="run" result="skipped"><skipped/></testcase>'
        examples = {
            'empty': ('<testsuites tests="99"/>', False, 'no-cases'),
            'all-skipped': ('<testsuites>' + skipped + '</testsuites>', False, 'zero-executed'),
            'missing': ('<testsuites>' + other + '</testsuites>', False, 'required-missing-or-duplicate'),
            'required-skipped': ('<testsuites>' + other + skipped + '</testsuites>', False, 'required-not-completed'),
            'duplicate': ('<testsuites>' + passed + passed + '</testsuites>', False, 'required-missing-or-duplicate'),
            'failure': ('<testsuites><testcase classname="Security" name="required" status="run" result="completed"><failure/></testcase></testsuites>', False, 'xml-failures'),
            'invalid': ('not XML', False, 'invalid-xml'),
            'valid': ('<testsuites>' + passed + '<testcase classname="Other" name="optional" status="run" result="skipped"><skipped/></testcase></testsuites>', True, 'passed'),
        }
        for name, (xml, _, _) in examples.items():
            (self.base / (name + '.xml')).write_text(xml)
        script = r'''param($Launcher,$Directory)
$ErrorActionPreference='Stop'
$tokens=$null; $errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($Launcher,[ref]$tokens,[ref]$errors)
if ($errors.Count) { throw 'launcher parse failure' }
$functions=$ast.FindAll({ param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -in @('Get-NativeTestOracle','Clear-NativeTestEnvironment','Restore-NativeTestEnvironment') },$true)
foreach($definition in $functions) { . ([scriptblock]::Create($definition.Extent.Text)) }
$result=@{}
foreach($file in Get-ChildItem -LiteralPath $Directory -Filter '*.xml') { $result[$file.BaseName]=Get-NativeTestOracle -XmlPath $file.FullName -RequiredCases @('Security.required') }
$strict=Get-NativeTestOracle -XmlPath (Join-Path $Directory 'valid.xml') -RequiredCases @('Security.required') -RequireAllCompleted
$env:GTEST_TOTAL_SHARDS='99'; $env:GTEST_SHARD_INDEX='7'; $env:SKIP_SYSTEM_TESTS='1'; $env:GTEST_LIST_TESTS='1'
$state=Clear-NativeTestEnvironment
$cleared=($null -eq $env:GTEST_TOTAL_SHARDS -and $null -eq $env:GTEST_SHARD_INDEX -and $null -eq $env:SKIP_SYSTEM_TESTS -and $null -eq $env:GTEST_LIST_TESTS)
Restore-NativeTestEnvironment -State $state
$restored=($env:GTEST_TOTAL_SHARDS -eq '99' -and $env:GTEST_SHARD_INDEX -eq '7' -and $env:SKIP_SYSTEM_TESTS -eq '1' -and $env:GTEST_LIST_TESTS -eq '1')
[pscustomobject]@{ oracles=$result; strict=$strict; cleared=$cleared; restored=$restored; inherited=@($state.record | Where-Object inherited).Count } | ConvertTo-Json -Depth 7 -Compress
'''
        runner = self.base / 'oracle-test.ps1'
        runner.write_text(script)
        result = subprocess.run([executable, '-NoLogo', '-NoProfile', '-NonInteractive', '-File', str(runner), str(launcher), str(self.base)], check=True, capture_output=True, text=True)
        actual = json.loads(result.stdout)
        self.assertTrue(actual['cleared'])
        self.assertTrue(actual['restored'])
        self.assertGreaterEqual(actual['inherited'], 4)
        self.assertFalse(actual['strict']['valid'])
        self.assertEqual(actual['strict']['reason'], 'noncompleted-cases')
        for name, (_, valid, reason) in examples.items():
            self.assertEqual(actual['oracles'][name]['valid'], valid, name)
            self.assertEqual(actual['oracles'][name]['reason'], reason, name)
        self.assertEqual(actual['oracles']['valid']['executed'], 1)
        self.assertEqual(actual['oracles']['valid']['skipped'], 1)

    def test_launcher_rejects_unmanifested_files_and_reparse_points_under_tests(self):
        executable = shutil.which('pwsh')
        if executable is None:
            self.skipTest('PowerShell parser/Expand-Archive unavailable on this test host')
        self.export()
        destination = self.base / 'clean-expanded'
        script = r'''param($Archive,$Destination,$EvilTarget)
$ErrorActionPreference = 'Stop'
Expand-Archive -LiteralPath $Archive -DestinationPath $Destination
$launcher = Join-Path $Destination 'run-tests.ps1'
$tokens = $null; $errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($launcher, [ref]$tokens, [ref]$errors)
if ($errors.Count) { throw 'launcher parse failure' }
$fn = $ast.FindAll({ param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Assert-CleanTestsTree' }, $true)
foreach ($d in $fn) { . ([scriptblock]::Create($d.Extent.Text)) }
$root = [IO.Path]::GetFullPath($Destination)
$metadata = Get-Content -LiteralPath (Join-Path $root 'bundle-manifest.json') -Raw | ConvertFrom-Json
$manifested = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
foreach ($entry in $metadata.files) {
    if ($entry.path -imatch '^tests/') {
        [void]$manifested.Add([IO.Path]::GetFullPath((Join-Path $root $entry.path)))
    }
}
$tests = Join-Path $root 'tests'
Assert-CleanTestsTree -TestsPath $tests -ManifestedPaths $manifested

$results = @{}
$rogue = Join-Path $tests 'hijack.dll'
[IO.File]::WriteAllText($rogue, 'rogue')
try { Assert-CleanTestsTree -TestsPath $tests -ManifestedPaths $manifested; $results['unmanifested'] = 'allowed' }
catch { $results['unmanifested'] = $_.Exception.Message }
Remove-Item -LiteralPath $rogue

$symFile = Join-Path $tests 'sym.dll'
[IO.File]::CreateSymbolicLink($symFile, $EvilTarget) | Out-Null
try { Assert-CleanTestsTree -TestsPath $tests -ManifestedPaths $manifested; $results['reparse_file'] = 'allowed' }
catch { $results['reparse_file'] = $_.Exception.Message }
Remove-Item -LiteralPath $symFile

$symDir = Join-Path $tests 'symdir'
[IO.Directory]::CreateSymbolicLink($symDir, (Split-Path -Parent $EvilTarget)) | Out-Null
try { Assert-CleanTestsTree -TestsPath $tests -ManifestedPaths $manifested; $results['reparse_dir'] = 'allowed' }
catch { $results['reparse_dir'] = $_.Exception.Message }
Remove-Item -LiteralPath $symDir

$results | ConvertTo-Json -Compress
'''
        evil = self.base / 'evil.txt'
        evil.write_text('outside')
        runner = self.base / 'clean-tree-test.ps1'
        runner.write_text(script)
        out = subprocess.run([executable, '-NoLogo', '-NoProfile', '-NonInteractive', '-File', str(runner), str(self.output), str(destination), str(evil)], check=True, capture_output=True, text=True)
        res = json.loads(out.stdout)
        self.assertIn('Unmanifested file under tests', res['unmanifested'])
        self.assertIn('Reparse point is not allowed under tests', res['reparse_file'])
        self.assertIn('Reparse point is not allowed under tests', res['reparse_dir'])


if __name__ == '__main__':
    unittest.main()
