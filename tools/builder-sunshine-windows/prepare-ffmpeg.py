#!/usr/bin/env python3
"""Admit the pinned Windows FFmpeg release and attest an existing build cache."""

import hashlib
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import sys
import tarfile
import tempfile


class InvalidCache(ValueError):
    pass


def member_path(name):
    path = PurePosixPath(name)
    if not path.parts and name in ('', '.', './'):
        return None
    if not path.parts or path.parts[0] != 'ffmpeg' or '..' in path.parts or '\\' in name:
        raise InvalidCache('member falls outside the FFmpeg tree')
    return path


def inventory(root):
    result = {}
    for directory, subdirs, files in os.walk(root, followlinks=False, onerror=raise_walk):
        for part in subdirs + files:
            path = Path(directory, part)
            relative = PurePosixPath(path.relative_to(root.parent).as_posix())
            mode = path.lstat().st_mode
            if not (stat.S_ISDIR(mode) or stat.S_ISREG(mode)):
                raise InvalidCache(f'not a regular file or directory: {relative}')
            result[relative] = 'dir' if stat.S_ISDIR(mode) else 'file'
    return result


def raise_walk(error):
    raise error


def open_cached_file(root_fd, relative):
    """Open an existing cached file component-by-component without following symlinks."""
    current = root_fd
    opened = []
    try:
        for part in relative.parts[:-1]:
            nxt = os.open(part, os.O_RDONLY | os.O_NOFOLLOW | os.O_DIRECTORY, dir_fd=current)
            opened.append(nxt)
            current = nxt
        leaf = os.open(relative.parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=current)
    finally:
        for fd in reversed(opened):
            os.close(fd)
    stream = os.fdopen(leaf, 'rb')
    try:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise InvalidCache(f'FFmpeg cache member is not a regular file: {relative}')
    except Exception:
        stream.close()
        raise
    return stream


def process_members(archive, base, reuse):
    root = base / 'ffmpeg'
    expected = {}
    seen = set()
    actual = inventory(root) if reuse else None
    codec = PurePosixPath('ffmpeg/lib/libavcodec.a')
    root_fd = os.open(root, os.O_RDONLY | os.O_NOFOLLOW | os.O_DIRECTORY) if reuse else None

    def register(path, kind):
        previous = expected.setdefault(path, kind)
        if previous != kind:
            raise InvalidCache(f'member type conflict: {path}')

    try:
        with tarfile.open(fileobj=archive, mode='r|gz') as tar:
            for member in tar:
                path = member_path(member.name)
                if path is None and member.isdir():
                    continue
                if path is None or path in seen or not (member.isfile() or member.isdir()):
                    raise InvalidCache('duplicate or unsupported FFmpeg archive member')
                seen.add(path)
                kind = 'dir' if member.isdir() else 'file'
                for parent in path.parents:
                    if parent.parts:
                        register(parent, 'dir')
                register(path, kind)
                target = base / path
                if member.isdir():
                    if not reuse:
                        target.mkdir(parents=True, exist_ok=True)
                    continue
                with tar.extractfile(member) as contents:
                    if reuse:
                        if actual.get(path) != 'file':
                            raise InvalidCache(f'FFmpeg cache inventory differs: {path}')
                        with open_cached_file(root_fd, Path(path).relative_to('ffmpeg')) as installed:
                            if hashlib.file_digest(contents, 'sha256').digest() != hashlib.file_digest(installed, 'sha256').digest():
                                raise InvalidCache(f'FFmpeg cache content differs: {path}')
                    else:
                        target.parent.mkdir(parents=True, exist_ok=True)
                        with target.open('xb') as output:
                            shutil.copyfileobj(contents, output)
                        target.chmod(0o700 if member.mode & 0o111 else 0o600)
    finally:
        if root_fd is not None:
            os.close(root_fd)
    if expected.get(codec) != 'file':
        raise InvalidCache('FFmpeg archive lacks its required codec library')
    expected.pop(PurePosixPath('ffmpeg'))
    if reuse and actual != expected:
        raise InvalidCache('FFmpeg cache inventory differs')


def prepare(archive, pin):
    if not re.fullmatch('[0-9a-f]{64}', pin):
        raise InvalidCache('invalid expected FFmpeg SHA-256')
    base = archive.parent
    root = base / 'ffmpeg'
    with os.fdopen(os.open(archive, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), 'rb') as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise InvalidCache('FFmpeg archive is not a regular file')
        if hashlib.file_digest(stream, 'sha256').hexdigest() != pin:
            raise InvalidCache('FFmpeg archive SHA-256 mismatch')
        stream.seek(0)
        if root.is_symlink() or (root.exists() and not root.is_dir()):
            raise InvalidCache('FFmpeg root is not a real directory')
        if root.exists():
            process_members(stream, base, reuse=True)
        else:
            with tempfile.TemporaryDirectory(prefix='.ffmpeg-extract-', dir=base) as staging:
                process_members(stream, Path(staging), reuse=False)
                (Path(staging) / 'ffmpeg').rename(root)


if __name__ == '__main__':
    try:
        _, archive_path, digest = sys.argv
        prepare(Path(archive_path), digest)
    except (EOFError, OSError, ValueError, tarfile.TarError) as error:
        print(f'Windows FFmpeg preparation refused: {error}', file=sys.stderr)
        sys.exit(1)
