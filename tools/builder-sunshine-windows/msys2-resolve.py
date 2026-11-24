#!/usr/bin/env python3
"""Resolve MSYS2 UCRT64 packages from a signature-verified repo database into a lock file.

Usage: msys2-resolve.py <extracted-db-dir> <packages.in> <packages.lock>

packages.in lists one root package per line (without the mingw-w64-ucrt-x86_64- prefix).
Lines of the form "!name" exclude a package (and do not traverse it); "#" starts a comment.
The lock file lists "<filename> <sha256>" for the dependency closure, sorted by name.
"""
import os
import re
import sys

PREFIX = "mingw-w64-ucrt-x86_64-"
FILENAME_RE = re.compile(r"^[A-Za-z0-9_.+~-]+$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def parse_desc(path):
    fields, key = {}, None
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.rstrip("\n")
            if line.startswith("%") and line.endswith("%"):
                key = line.strip("%")
                fields[key] = []
            elif line and key:
                fields[key].append(line)
    return fields


def strip_version(dep):
    return re.split(r"[<>=]", dep, maxsplit=1)[0].strip()


def main():
    db_dir, spec, lock = sys.argv[1:4]
    pkgs, provides = {}, {}
    for entry in os.listdir(db_dir):
        desc = os.path.join(db_dir, entry, "desc")
        if not os.path.isfile(desc):
            continue
        d = parse_desc(desc)
        name = d["NAME"][0]
        pkgs[name] = d
        for p in d.get("PROVIDES", []):
            provides.setdefault(strip_version(p), name)

    roots, excluded = [], set()
    with open(spec, encoding="utf-8") as f:
        for line in f:
            line = line.split("#", 1)[0].strip()
            if not line:
                continue
            if line.startswith("!"):
                excluded.add(PREFIX + line[1:])
            else:
                roots.append(PREFIX + line)

    def resolve(name):
        if name in pkgs:
            return name
        if name in provides:
            return provides[name]
        raise SystemExit(f"unresolvable package: {name}")

    seen, stack = set(), [resolve(r) for r in roots]
    while stack:
        name = stack.pop()
        if name in seen or name in excluded:
            continue
        seen.add(name)
        for dep in pkgs[name].get("DEPENDS", []):
            dep_name = strip_version(dep)
            if not dep_name.startswith(PREFIX):
                continue  # msys runtime packages (bash, etc.) are not needed in a cross sysroot
            resolved = resolve(dep_name)
            if resolved not in excluded:
                stack.append(resolved)

    with open(lock, "w", encoding="utf-8") as out:
        out.write("# MSYS2 ucrt64 packages: <filename> <sha256> (from the signature-verified ucrt64.db)\n")
        for name in sorted(seen):
            d = pkgs[name]
            filename = d["FILENAME"][0]
            digest = d["SHA256SUM"][0]
            if filename in {".", ".."} or not FILENAME_RE.fullmatch(filename):
                raise SystemExit(f"invalid package filename in database: {filename!r}")
            if not SHA256_RE.fullmatch(digest):
                raise SystemExit(f"invalid package sha256 in database for {filename!r}: {digest!r}")
            out.write(f"{filename} {digest}\n")
    total = sum(int(pkgs[n]["CSIZE"][0]) for n in seen)
    print(f"{len(seen)} packages, {total / 1e6:.0f} MB compressed -> {lock}")


if __name__ == "__main__":
    main()
