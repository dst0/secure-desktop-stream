#!/usr/bin/env python3
"""Admit COPYONLY native fixtures from the sealed source's sha256sum inventory.

Every generated runtime fixture must match a reviewed source file. Five tray
icon renames are explicit; unknown files fail instead of silently reducing the
suite. The result is the exporter's scoped, standard sha256sum input list.
"""

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import re
import tempfile

SPEC = importlib.util.spec_from_file_location('native_bundle_exporter', Path(__file__).with_name('export-native-tests.py'))
EXPORTER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(EXPORTER)
# This explicit Windows COPYONLY contract is reviewed with tests/CMakeLists.txt.
# A changed generator must be reviewed instead of silently changing bundle scope.
REVIEWED_TEST_CMAKE_SHA256 = '4d46c149e7df8d1dfbb97e910832917661a44bc72873dda7873e19c7add7ae91'
COPYONLY_PATHS = {
    'cmake/compile_definitions/macos.cmake',
    'cmake/dependencies/Boost_Sunshine.cmake',
    'cmake/macros/common.cmake',
    'cmake/prep/options.cmake',
    'package-lock.cmake',
    'packaging/linux/Arch/PKGBUILD',
    'packaging/linux/flatpak/modules/boost.json',
    'packaging/linux/flatpak/scripts/additional-install.sh',
    'scripts/linux_build.sh',
    'src/config.cpp',
    'src_assets/common/assets/web/Config.vue',
    'src_assets/common/assets/web/locale.js',
    'docs/building.md',
    'docs/configuration.md',
    'docs/getting_started.md',
    'docs/troubleshooting.md',
    'src_assets/common/assets/web/public/assets/locale/en.json',
    'src_assets/common/assets/web/configs/config_tabs.json',
    'src_assets/common/assets/web/configs/VirtualKeyCodeSelect.vue',
    'src_assets/common/assets/web/configs/virtual_key_codes.js',
    'src_assets/common/assets/web/configs/tabs/General.vue',
    'src_assets/common/assets/web/configs/tabs/Inputs.vue',
    'src_assets/linux/misc/60-sunshine.conf',
    'src_assets/linux/misc/60-sunshine.rules',
    'tests/scripts/test_additional_install.sh',
}
LOCALES_PREFIX = 'src_assets/common/assets/web/public/assets/locale/'
SHADERS_PREFIX = 'src_assets/windows/assets/shaders/directx/'
RENAMES = {
    'test_assets/web/images/logo-sunshine.svg': 'sunshine.svg',
    'test_assets/web/images/logo-libvirtualhid.svg': 'third-party/libvirtualhid/libvirtualhid.svg',
    **{'test_assets/web/images/' + icon: 'src_assets/common/assets/web/public/images/' + icon
       for icon in ('sunshine-locked.svg', 'sunshine-playing.svg', 'sunshine-pausing.svg')},
}


def read_source_inventory(path):
    """Read canonical relative source names without requiring all to ship on Windows."""
    inventory = {}
    for line in Path(path).read_text(encoding='utf-8').splitlines():
        if not line or line.startswith('#'):
            continue
        match = re.fullmatch(r'([0-9a-f]{64}) [ *](.+)', line)
        if not match:
            raise ValueError('invalid source sha256sum line')
        digest, name = match.groups()
        relative = PurePosixPath(name)
        if relative.is_absolute() or relative.as_posix() != name or '..' in relative.parts or '\\' in name or name in inventory:
            raise ValueError('unsafe or duplicate source inventory path: ' + name)
        inventory[name] = digest
    if not inventory:
        raise ValueError('empty source inventory')
    return inventory


def collect(source_root, test_root, source_inventory, output):
    """Publish only complete fixtures whose bytes match the sealed source inventory."""
    source_root, test_root, output = Path(source_root), Path(test_root), Path(output)
    if output.exists():
        raise FileExistsError('refusing to replace an existing fixture manifest')
    inventory = read_source_inventory(source_inventory)
    generator = EXPORTER.admitted_file(source_root, 'tests/CMakeLists.txt')
    if inventory.get('tests/CMakeLists.txt') != REVIEWED_TEST_CMAKE_SHA256 or hashlib.sha256(generator.read_bytes()).hexdigest() != REVIEWED_TEST_CMAKE_SHA256:
        raise ValueError('unreviewed Windows fixture generator; review the explicit COPYONLY contract')
    entries = {}
    required = {'source/sunshine.png', 'source/tests/unit/test_video.cpp'}
    required |= {'source/' + name for name in inventory if name.startswith(SHADERS_PREFIX)}
    if required != EXPORTER.required_source_fixtures(source_root):
        raise ValueError('source shader fixture set differs from sealed inventory')
    runtime = EXPORTER.runtime_fixtures(test_root)
    expected_runtime = {'tests/' + name for name in COPYONLY_PATHS | RENAMES.keys()}
    expected_runtime |= {'tests/' + name for name in inventory if name.startswith(LOCALES_PREFIX)}
    if 'packaging/linux/copr/Sunshine.spec' in inventory:
        expected_runtime.add('tests/packaging/linux/copr/Sunshine.spec')
    if missing := expected_runtime - runtime:
        raise ValueError('missing required runtime fixtures: ' + ', '.join(sorted(missing)))
    if unknown := runtime - expected_runtime:
        raise ValueError('unknown runtime fixtures outside reviewed COPYONLY contract: ' + ', '.join(sorted(unknown)))
    for name in sorted(required | runtime):
        EXPORTER.safe_name(name)
        namespace, relative = name.split('/', 1)
        origin = RENAMES.get(relative, relative) if namespace == 'tests' else relative
        expected = inventory.get(origin)
        if expected is None:
            raise ValueError('fixture origin missing from sealed source inventory: ' + name)
        source = EXPORTER.admitted_file(source_root, origin)
        target = EXPORTER.admitted_file(test_root if namespace == 'tests' else source_root, relative)
        for path in {source, target}:
            with path.open('rb') as file:
                actual = hashlib.file_digest(file, 'sha256').hexdigest()
            if actual != expected:
                raise ValueError('fixture differs from sealed source: ' + name)
        entries[name] = expected
    payload = ''.join(digest + '  ' + name + '\n' for name, digest in sorted(entries.items()))
    output.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix='.fixtures-', dir=output.parent)
    try:
        with os.fdopen(descriptor, 'w', encoding='utf-8') as target:
            target.write(payload)
            target.flush()
            os.fsync(target.fileno())
        # The exporter also rejects names that collide on Windows.
        EXPORTER.read_manifest(temporary)
        os.link(temporary, output)
    finally:
        Path(temporary).unlink()
    return {'source_inventory_sha256': hashlib.sha256(Path(source_inventory).read_bytes()).hexdigest(),
            'fixture_manifest_sha256': hashlib.sha256(payload.encode()).hexdigest(),
            'runtime_fixtures': len(runtime), 'source_fixtures': len(required)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-root', type=Path, required=True)
    parser.add_argument('--test-root', type=Path, required=True)
    parser.add_argument('--source-inventory', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    print(json.dumps(collect(**vars(parser.parse_args())), sort_keys=True))


if __name__ == '__main__':
    main()
