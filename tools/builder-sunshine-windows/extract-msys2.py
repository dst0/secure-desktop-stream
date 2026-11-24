#!/usr/bin/env python3
"""Validate a hash-verified MSYS2 package, then extract only its ucrt64 payload.

Metadata-only packages are valid dependencies. Metadata never enters the sysroot;
unknown roots, traversal, special files and escaping links fail before extraction.
Python's data filter also checks destination symlinks left by preceding packages.
"""

import contextlib
import copy
import os
import pathlib
import posixpath
import re
import stat
import subprocess
import sys
import tarfile

METADATA = {".BUILDINFO", ".MTREE", ".PKGINFO", ".INSTALL"}
HOST_METADATA_DIRECTORIES = {"usr", "usr/share", "usr/share/libalpm", "usr/share/libalpm/hooks"}
HOST_HOOK = re.compile(r"usr/share/libalpm/hooks/mingw-w64-ucrt-x86_64-[A-Za-z0-9_.+-]+\.hook")


@contextlib.contextmanager
def open_package(package):
    """Read zstd archives as a stream without following symlinks or buffering to disk."""
    fd = os.open(package, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as source:
        if not stat.S_ISREG(os.fstat(source.fileno()).st_mode):
            raise ValueError("package is not a regular file")
        process = subprocess.Popen(["zstd", "-dc"], stdin=source, stdout=subprocess.PIPE)
        try:
            with tarfile.open(fileobj=process.stdout, mode="r|") as archive:
                yield archive
        finally:
            process.stdout.close()
            result = process.wait()
    if result:
        raise ValueError(f"zstd failed with status {result}")


def validate(member):
    """Return whether this member is payload, refusing unexpected archive shapes."""
    name = member.name
    parts = pathlib.PurePosixPath(name).parts
    if not parts or name.startswith("/") or ".." in parts or "\\" in name or name != posixpath.normpath(name):
        raise ValueError(f"unsafe archive path: {name!r}")
    if name in METADATA:
        if not member.isfile():
            raise ValueError(f"metadata is not a regular file: {name!r}")
        return False
    # Some target packages ship MSYS2 pacman hooks outside ucrt64. They are host
    # package-manager metadata, never target payload and never executed here.
    if name in HOST_METADATA_DIRECTORIES:
        if not member.isdir():
            raise ValueError(f"host metadata path is not a directory: {name!r}")
        return False
    if HOST_HOOK.fullmatch(name):
        if not member.isfile():
            raise ValueError(f"host package hook is not a regular file: {name!r}")
        return False
    if parts[0] != "ucrt64":
        raise ValueError(f"unexpected archive root: {name!r}")
    if len(parts) == 1:
        if not member.isdir():
            raise ValueError("ucrt64 root is not a directory")
        return False
    if not (member.isfile() or member.isdir() or member.issym() or member.islnk()):
        raise ValueError(f"unsupported archive member type: {name!r}")
    if member.issym() or member.islnk():
        target = member.linkname
        if target.startswith("/") or "\\" in target:
            raise ValueError(f"absolute/non-POSIX link: {name!r}")
        resolved = posixpath.normpath(target if member.islnk() else posixpath.join(posixpath.dirname(name), target))
        if not resolved.startswith("ucrt64/"):
            raise ValueError(f"escaping archive link: {name!r}")
        if member.islnk() and (not target.startswith("ucrt64/") or target != posixpath.normpath(target)):
            raise ValueError(f"noncanonical hard link: {name!r}")
    return True


def extract(package, destination):
    """Validate the entire archive before modifying the existing sysroot."""
    metadata = set()
    payload = 0
    with open_package(package) as archive:
        for member in archive:
            payload += validate(member)
            if member.name in METADATA:
                if member.name in metadata:
                    raise ValueError(f"duplicate metadata: {member.name}")
                metadata.add(member.name)
    if ".PKGINFO" not in metadata:
        raise ValueError("package has no .PKGINFO")
    destination = pathlib.Path(destination)
    destination.mkdir(parents=True, exist_ok=True)
    with open_package(package) as archive:
        for member in archive:
            if not validate(member):
                continue
            member = copy.copy(member)
            member.name = member.name[len("ucrt64/"):]
            if member.islnk():
                member.linkname = member.linkname[len("ucrt64/"):]
            archive.extract(member, destination, filter="data")
    return payload


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit("usage: extract-msys2.py <package.pkg.tar.zst> <destination>")
    try:
        count = extract(sys.argv[1], sys.argv[2])
    except (ValueError, OSError, tarfile.TarError) as error:
        raise SystemExit(f"refusing MSYS2 package: {error}") from error
    print(f"validated {count} ucrt64 payload entries")
