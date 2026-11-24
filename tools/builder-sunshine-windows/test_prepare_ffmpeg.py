import hashlib
import io
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest


SCRIPT = Path(__file__).with_name('prepare-ffmpeg.py')
FILES = {'ffmpeg/lib/libavcodec.a': b'archive', 'ffmpeg/include/libavcodec.h': b'header'}


class PrepareFFmpegTest(unittest.TestCase):
    def setUp(self):
        staging = tempfile.TemporaryDirectory()
        self.addCleanup(staging.cleanup)
        self.root = Path(staging.name)
        self.archive = self.root / 'ffmpeg.tar.gz'
        self.fixture()

    def fixture(self, extra=None):
        with tarfile.open(self.archive, 'w:gz') as tar:
            for name, data in FILES.items():
                info = tarfile.TarInfo('./' + name)
                info.size = len(data)
                tar.addfile(info, io.BytesIO(data))
            for entry in extra or ():
                tar.addfile(entry, io.BytesIO(b''))
        self.pin = hashlib.sha256(self.archive.read_bytes()).hexdigest()

    def run_helper(self, pin=None, ok=True):
        result = subprocess.run([sys.executable, str(SCRIPT), str(self.archive), pin or self.pin],
                                capture_output=True, text=True, check=False)
        if ok:
            self.assertEqual(result.returncode, 0, result.stderr)
        else:
            self.assertEqual(result.returncode, 1, result.stderr)
        return result

    def test_extract_then_reuse_verified_tree_without_rewriting(self):
        self.run_helper()
        for name, data in FILES.items():
            self.assertEqual((self.root / name).read_bytes(), data)
        item = self.root / next(iter(FILES))
        os.utime(item, (12345, 12345))
        self.run_helper()
        self.assertEqual(item.stat().st_mtime, 12345)

    def test_explicit_directories_after_files_and_empty_directories(self):
        entries = [tarfile.TarInfo(name) for name in ('./', 'ffmpeg/', 'ffmpeg/lib/', 'ffmpeg/empty/')]
        for entry in entries:
            entry.type = tarfile.DIRTYPE
        self.fixture(entries)
        self.run_helper()
        self.assertTrue((self.root / 'ffmpeg/empty').is_dir())
        self.run_helper()

    def test_rejects_duplicate_normalized_member_and_file_directory_conflict(self):
        cases = [('ffmpeg/lib/libavcodec.a', tarfile.REGTYPE, 'duplicate'),
                 ('ffmpeg/lib', tarfile.REGTYPE, 'type conflict')]
        for name, kind, reason in cases:
            with self.subTest(name=name):
                entry = tarfile.TarInfo(name)
                entry.type = kind
                self.fixture([entry])
                self.assertIn(reason, self.run_helper(ok=False).stderr)
                self.assertFalse((self.root / 'ffmpeg').exists())

    def test_refuses_modified_header_even_when_archive_and_libcodec_are_intact(self):
        self.run_helper()
        header = self.root / 'ffmpeg/include/libavcodec.h'
        header.write_bytes(b'forged')
        self.assertIn('content differs', self.run_helper(ok=False).stderr)
        self.assertEqual(header.read_bytes(), b'forged')

    def test_refuses_missing_or_additional_tree_member(self):
        self.run_helper()
        header = self.root / 'ffmpeg/include/libavcodec.h'
        header.unlink()
        self.assertIn('inventory differs', self.run_helper(ok=False).stderr)
        header.write_bytes(b'header')
        (self.root / 'ffmpeg/lib/extra.a').write_bytes(b'archive')
        self.assertIn('inventory differs', self.run_helper(ok=False).stderr)

    def test_refuses_symlink_in_tree_even_with_matching_contents(self):
        self.run_helper()
        header = self.root / 'ffmpeg/include/libavcodec.h'
        header.rename(self.root / 'substitute')
        header.symlink_to(self.root / 'substitute')
        self.assertIn('not a regular file', self.run_helper(ok=False).stderr)

    def test_refuses_symlink_archive_input(self):
        link = self.root / 'link.tar.gz'
        link.symlink_to(self.archive)
        result = subprocess.run([sys.executable, str(SCRIPT), str(link), self.pin],
                                capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 1)

    def test_archive_must_match_pin_before_extraction(self):
        self.assertIn('SHA-256', self.run_helper('0' * 64, ok=False).stderr)
        self.assertFalse((self.root / 'ffmpeg').exists())

    def test_archive_refuses_link_and_escape_before_publication(self):
        for name, kind in [('ffmpeg/lib/alias.a', tarfile.SYMTYPE), ('ffmpeg/../escape', tarfile.REGTYPE)]:
            with self.subTest(name=name):
                entry = tarfile.TarInfo(name)
                entry.type = kind
                entry.linkname = '../../outside'
                self.fixture([entry])
                self.run_helper(ok=False)
                self.assertFalse((self.root / 'ffmpeg').exists())
                self.assertFalse((self.root / 'escape').exists())


if __name__ == '__main__':
    unittest.main()
