#!/usr/bin/env python3
"""Behavioral regressions for sysroot package extraction and confinement."""

import importlib.util
import io
import pathlib
import subprocess
import tarfile
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location("extract_msys2", pathlib.Path(__file__).with_name("extract-msys2.py"))
EXTRACTOR = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(EXTRACTOR)


class ExtractMsys2Test(unittest.TestCase):
    """Exercise real compressed package shapes without network or privileged writes."""

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.base = pathlib.Path(self.temporary.name)
        self.package = self.base / "fixture.pkg.tar.zst"
        self.destination = self.base / "sysroot"

    def tearDown(self):
        self.temporary.cleanup()

    def package_with(self, members):
        """Write a zstd-compressed tar, preserving adversarial member names."""
        raw = self.base / "package.tar"
        with tarfile.open(raw, "w") as archive:
            for name, content, link, *kind in [(".PKGINFO", b"pkgname = fixture\n", None), *members]:
                member = tarfile.TarInfo(name)
                if kind:
                    member.type = kind[0]
                if member.isdir():
                    archive.addfile(member)
                    continue
                if link is not None:
                    member.type = kind[0] if kind else tarfile.SYMTYPE
                    member.linkname = link
                    archive.addfile(member)
                else:
                    member.size = len(content)
                    archive.addfile(member, io.BytesIO(content))
        subprocess.run(["zstd", "-q", "-f", str(raw), "-o", str(self.package)], check=True)

    def test_payload_extracts_without_metadata(self):
        self.package_with([("ucrt64/include/example.h", b"synthetic header", None), ("ucrt64/include/alias.h", b"", "example.h")])
        self.assertEqual(EXTRACTOR.extract(self.package, self.destination), 2)
        self.assertEqual((self.destination / "include/example.h").read_bytes(), b"synthetic header")
        self.assertEqual((self.destination / "include/alias.h").read_bytes(), b"synthetic header")
        self.assertFalse((self.destination / ".PKGINFO").exists())

    def test_metadata_only_dependency_is_accepted(self):
        self.package_with([(".BUILDINFO", b"synthetic metadata", None), (".MTREE", b"synthetic mtree", None)])
        self.assertEqual(EXTRACTOR.extract(self.package, self.destination), 0)
        self.assertEqual(list(self.destination.iterdir()), [])

    def test_host_alpm_hooks_are_validated_but_never_installed(self):
        directories = [(name, b"", None, tarfile.DIRTYPE) for name in ["usr", "usr/share", "usr/share/libalpm", "usr/share/libalpm/hooks"]]
        self.package_with([*directories, ("usr/share/libalpm/hooks/mingw-w64-ucrt-x86_64-gio-querymodules.hook", b"synthetic host package hook", None), ("ucrt64/include/example.h", b"target header", None)])
        self.assertEqual(EXTRACTOR.extract(self.package, self.destination), 1)
        self.assertEqual((self.destination / "include/example.h").read_bytes(), b"target header")
        self.assertFalse((self.destination / "usr").exists())

    def test_host_hook_allowlist_does_not_accept_other_usr_payload_or_links(self):
        for member in [("usr/bin/program.exe", b"bad", None), ("usr/share/libalpm/hooks/other-package.hook", b"bad", None), ("usr/share/libalpm/hooks/mingw-w64-ucrt-x86_64-gio-querymodules.hook", b"", "../../../../outside"), ("usr", b"not a directory", None)]:
            with self.subTest(name=member[0]):
                self.package_with([("ucrt64/good", b"must not extract", None), member])
                with self.assertRaises(ValueError):
                    EXTRACTOR.extract(self.package, self.destination)
                self.assertFalse(self.destination.exists())

    def test_real_hardlink_preserves_data_and_identity(self):
        self.package_with([("ucrt64/lib/original.a", b"synthetic library", None), ("ucrt64/lib/alias.a", b"", "ucrt64/lib/original.a", tarfile.LNKTYPE)])
        self.assertEqual(EXTRACTOR.extract(self.package, self.destination), 2)
        original = self.destination / "lib/original.a"
        alias = self.destination / "lib/alias.a"
        self.assertEqual(alias.read_bytes(), b"synthetic library")
        self.assertEqual(alias.stat().st_ino, original.stat().st_ino)

    def test_escaping_hardlink_is_rejected_before_any_write(self):
        for target in ["ucrt64/../outside", "/tmp/outside", "./ucrt64/../../outside", "../ucrt64/file", "ucrt64/./file", "ucrt64//file", "ucrt64/sub/../file"]:
            with self.subTest(target=target):
                self.package_with([("ucrt64/good", b"must not extract", None), ("ucrt64/alias", b"", target, tarfile.LNKTYPE)])
                with self.assertRaises(ValueError):
                    EXTRACTOR.extract(self.package, self.destination)
                self.assertFalse(self.destination.exists())

    def test_symlink_package_is_refused(self):
        self.package_with([("ucrt64/include/example.h", b"synthetic header", None)])
        link = self.base / "link.pkg.tar.zst"
        link.symlink_to(self.package)
        with self.assertRaises(OSError):
            EXTRACTOR.extract(link, self.destination)
        self.assertFalse(self.destination.exists())

    def test_unexpected_root_and_traversal_are_rejected_before_any_write(self):
        for bad in ["etc/passwd", "ucrt64/../escape", "/ucrt64/absolute", "ucrt64/../../escape", "ucrt64\\escape", "./ucrt64/file", "ucrt64//file"]:
            with self.subTest(bad=bad):
                self.package_with([("ucrt64/good", b"must not extract", None), (bad, b"bad", None)])
                with self.assertRaises(ValueError):
                    EXTRACTOR.extract(self.package, self.destination)
                self.assertFalse(self.destination.exists())

    def test_escaping_link_is_rejected_before_any_write(self):
        for target in ["../../escape", "/tmp/escape", "..\\escape"]:
            with self.subTest(target=target):
                self.package_with([("ucrt64/alias", b"", target)])
                with self.assertRaises(ValueError):
                    EXTRACTOR.extract(self.package, self.destination)
                self.assertFalse(self.destination.exists())

    def test_preexisting_destination_symlink_cannot_escape(self):
        self.destination.mkdir()
        outside = self.base / "outside"
        outside.mkdir()
        (self.destination / "include").symlink_to(outside, target_is_directory=True)
        self.package_with([("ucrt64/include/escape", b"bad", None)])
        with self.assertRaises(tarfile.OutsideDestinationError):
            EXTRACTOR.extract(self.package, self.destination)
        self.assertEqual(list(outside.iterdir()), [])

    def test_truncated_compressed_archive_fails(self):
        self.package.write_bytes(b"not zstd")
        with self.assertRaises((ValueError, tarfile.TarError)):
            EXTRACTOR.extract(self.package, self.destination)
        self.assertFalse(self.destination.exists())


if __name__ == "__main__":
    unittest.main()
