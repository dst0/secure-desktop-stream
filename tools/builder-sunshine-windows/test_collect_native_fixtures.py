#!/usr/bin/env python3
"""Verify fixture admission against the actual source fingerprint, not a directory copy."""

import hashlib
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import subprocess
import sys
import json

SPEC = importlib.util.spec_from_file_location('collector', Path(__file__).with_name('collect-native-fixtures.py'))
COLLECTOR = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(COLLECTOR)


class FixtureAdmissionTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.base = Path(self.temporary.name)
        self.source, self.tests = self.base / 'source', self.base / 'tests'
        self.source.mkdir()
        self.tests.mkdir()
        self.inventory, self.output = self.base / 'source.sha256', self.base / 'fixtures.sha256'
        self.entries = {}
        generator = Path(__file__).resolve().parents[2] / 'sunshine/tests/CMakeLists.txt'
        target = self.source / 'tests/CMakeLists.txt'
        target.parent.mkdir()
        target.write_bytes(generator.read_bytes())
        self.entries['tests/CMakeLists.txt'] = hashlib.sha256(target.read_bytes()).hexdigest()
        for name in ('sunshine.png', 'tests/unit/test_video.cpp', 'src_assets/windows/assets/shaders/directx/test.hlsl'):
            self.source_file(name)
        for name in COLLECTOR.COPYONLY_PATHS:
            self.source_file(name)
            self.runtime_file(name, name)
        for runtime, source in COLLECTOR.RENAMES.items():
            self.source_file(source)
            self.runtime_file(runtime, source)
        for name in ('src_assets/common/assets/web/public/assets/locale/en.json', 'src_assets/common/assets/web/public/assets/locale/uk.json'):
            self.source_file(name)
            self.runtime_file(name, name)
        self.write_inventory()

    def tearDown(self):
        self.temporary.cleanup()

    def source_file(self, name):
        path = self.source / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(('synthetic ' + name).encode())
        self.entries[name] = hashlib.sha256(path.read_bytes()).hexdigest()

    def runtime_file(self, name, source):
        path = self.tests / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes((self.source / source).read_bytes())

    def write_inventory(self):
        self.inventory.write_text(''.join(digest + '  ' + name + '\n' for name, digest in sorted(self.entries.items())))

    def collect(self):
        return COLLECTOR.collect(self.source, self.tests, self.inventory, self.output)

    def test_complete_copyonly_inventory_and_all_five_renames(self):
        (self.tests / 'libsunshine_tray_test_helpers.a').write_bytes(b'compiler archive')
        self.source_file('private-non-fixture.txt')
        self.write_inventory()
        result = self.collect()
        entries = COLLECTOR.EXPORTER.read_manifest(self.output)
        self.assertEqual(result['source_fixtures'], 3)
        self.assertEqual(result['runtime_fixtures'], 31)
        self.assertEqual(len(entries), 34)
        self.assertNotIn('source/private-non-fixture.txt', entries)
        self.assertFalse(any(name.endswith('.a') for name in entries))
        for runtime, source in COLLECTOR.RENAMES.items():
            self.assertEqual(entries['tests/' + runtime], self.entries[source])

    def test_unknown_or_changed_fixture_cannot_be_admitted(self):
        unexpected = self.tests / 'unreviewed.txt'
        unexpected.write_bytes(b'not in reviewed source')
        with self.assertRaisesRegex(ValueError, 'unknown runtime fixtures'):
            self.collect()
        unexpected.unlink()
        runtime = self.tests / next(iter(COLLECTOR.RENAMES))
        runtime.write_bytes(b'changed COPYONLY bytes')
        with self.assertRaisesRegex(ValueError, 'differs from sealed source'):
            self.collect()
        self.assertFalse(self.output.exists())

    def test_missing_generated_copyonly_or_locale_is_rejected(self):
        for name in ('test_assets/web/images/logo-sunshine.svg', 'src_assets/common/assets/web/public/assets/locale/uk.json'):
            with self.subTest(name=name):
                path = self.tests / name
                original = path.read_bytes()
                path.unlink()
                try:
                    with self.assertRaisesRegex(ValueError, 'missing required runtime fixtures'):
                        self.collect()
                    self.assertFalse(self.output.exists())
                finally:
                    self.output.unlink(missing_ok=True)
                    path.write_bytes(original)

    def test_source_drift_missing_origin_and_symlink_fail_closed(self):
        path = self.source / 'sunshine.png'
        original = path.read_bytes()
        path.write_bytes(b'source changed after sealing')
        with self.assertRaisesRegex(ValueError, 'differs from sealed source'):
            self.collect()
        path.write_bytes(original)
        digest = self.entries.pop('sunshine.png')
        self.write_inventory()
        with self.assertRaisesRegex(ValueError, 'missing from sealed source'):
            self.collect()
        self.entries['sunshine.png'] = digest
        self.write_inventory()
        path.unlink()
        path.symlink_to(self.source / 'tests/unit/test_video.cpp')
        with self.assertRaisesRegex(ValueError, 'symlink'):
            self.collect()

    def test_source_inventory_rejects_traversal_duplicates_and_invalid_hash(self):
        for line in ['a' * 64 + '  ../escape', 'a' * 64 + '  /absolute', 'bad  source', 'a' * 64 + '  same\n' + 'b' * 64 + '  same']:
            with self.subTest(line=line):
                self.inventory.write_text(line + '\n')
                with self.assertRaises(ValueError):
                    self.collect()
                self.assertFalse(self.output.exists())

    def test_generator_drift_and_removed_source_shader_are_rejected(self):
        generator = self.source / 'tests/CMakeLists.txt'
        original = generator.read_bytes()
        generator.write_bytes(original + b'\n# changed fixture generator\n')
        self.entries['tests/CMakeLists.txt'] = hashlib.sha256(generator.read_bytes()).hexdigest()
        self.write_inventory()
        with self.assertRaisesRegex(ValueError, 'unreviewed Windows fixture generator'):
            self.collect()
        generator.write_bytes(original)
        self.entries['tests/CMakeLists.txt'] = hashlib.sha256(original).hexdigest()
        self.source_file(COLLECTOR.SHADERS_PREFIX + 'second.hlsl')
        self.write_inventory()
        (self.source / (COLLECTOR.SHADERS_PREFIX + 'second.hlsl')).unlink()
        with self.assertRaisesRegex(ValueError, 'shader fixture set differs'):
            self.collect()
        self.assertFalse(self.output.exists())

    def test_cli_emits_standard_allowlist_bound_to_source_inventory(self):
        result = subprocess.run([sys.executable, str(Path(COLLECTOR.__file__)), '--source-root', str(self.source),
                                 '--test-root', str(self.tests), '--source-inventory', str(self.inventory),
                                 '--output', str(self.output)], check=True, capture_output=True, text=True)
        metadata = json.loads(result.stdout)
        self.assertEqual(metadata['source_inventory_sha256'], hashlib.sha256(self.inventory.read_bytes()).hexdigest())
        self.assertEqual(metadata['fixture_manifest_sha256'], hashlib.sha256(self.output.read_bytes()).hexdigest())
        self.assertEqual(len(COLLECTOR.EXPORTER.read_manifest(self.output)), 34)

    def test_case_collisions_and_immutable_output(self):
        for name in ('A.txt', 'a.txt'):
            self.source_file(name)
            self.runtime_file(name, name)
        # Force the same collision on case-insensitive development filesystems.
        for root in (self.source, self.tests):
            for name in ('A.txt', 'a.txt'):
                (root / name).write_bytes(b'same reviewed bytes')
        for name in ('A.txt', 'a.txt'):
            self.entries[name] = hashlib.sha256(b'same reviewed bytes').hexdigest()
        self.write_inventory()
        runtime = COLLECTOR.EXPORTER.runtime_fixtures(self.tests) | {'tests/A.txt', 'tests/a.txt'}
        with patch.object(COLLECTOR.EXPORTER, 'runtime_fixtures', return_value=runtime), patch.object(COLLECTOR, 'COPYONLY_PATHS', COLLECTOR.COPYONLY_PATHS | {'A.txt', 'a.txt'}):
            with self.assertRaisesRegex(ValueError, 'case-colliding'):
                self.collect()
        self.assertFalse(self.output.exists())
        self.output.write_text('preserved receipt')
        with self.assertRaises(FileExistsError):
            self.collect()
        self.assertEqual(self.output.read_text(), 'preserved receipt')


if __name__ == '__main__':
    unittest.main()
