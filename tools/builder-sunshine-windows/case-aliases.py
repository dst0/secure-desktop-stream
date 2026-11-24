#!/usr/bin/env python3
"""Case-alias shims for building Windows code on a case-sensitive file system.

Windows sources (Sunshine and its submodules) spell SDK headers and import libraries the way the
Windows SDK does (``Windows.h``, ``WinSock2.h``, ``winrt/windows.foundation.h``, ``D3DCompiler``,
``Windowsapp.lib``). NTFS does not care; the MinGW sysroot on Linux has ``windows.h``,
``winrt/Windows.Foundation.h``, ``libd3dcompiler.a``. Instead of patching every source and
submodule, create symlinks with the spelling the build asks for:

  case-aliases.py headers <source-dir> <sysroot-include-dir> <alias-include-dir>
      Scans #include directives; for every include that does not exist with that exact spelling in
      the sysroot but does exist case-insensitively, links <alias-include-dir>/<spelling> to it.
      The alias dir is added with -idirafter, so project headers always win.

  case-aliases.py libs <build.ninja> <sysroot-lib-dir> <alias-lib-dir>
      Reads the link lines CMake generated (-lName and Name.lib items); for every library that
      only exists with different case in the sysroot, links <alias-lib-dir>/libName.a to it.
"""
import os
import re
import sys

SOURCE_EXT = {".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx", ".ipp", ".inl", ".rc"}
SKIP_DIRS = {".git", "node_modules", "cmake-build-windows-cross", "build"}
INCLUDE_RE = re.compile(r'^\s*#\s*include\s*[<"]([^>"]+)[>"]', re.M)


def index_tree(root):
    """Map lower-case relative path -> exact relative path for every file under root."""
    index = {}
    for dirpath, _, files in os.walk(root):
        for name in files:
            rel = os.path.relpath(os.path.join(dirpath, name), root)
            index.setdefault(rel.lower(), rel)
    return index


def link(alias_root, wanted, target):
    path = os.path.join(alias_root, wanted)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    if os.path.lexists(path):
        os.remove(path)
    os.symlink(target, path)


def headers(src, sysroot_include, alias):
    index = index_tree(sysroot_include)
    wanted = set()
    for dirpath, dirs, files in os.walk(src):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for name in files:
            if os.path.splitext(name)[1].lower() not in SOURCE_EXT:
                continue
            try:
                with open(os.path.join(dirpath, name), encoding="utf-8", errors="ignore") as f:
                    wanted.update(INCLUDE_RE.findall(f.read()))
            except OSError:
                continue
    count = 0
    for inc in sorted(wanted):
        inc = inc.replace("\\", "/")
        if os.path.exists(os.path.join(sysroot_include, inc)):
            continue
        exact = index.get(inc.lower())
        if exact:
            link(alias, inc, os.path.join(sysroot_include, exact))
            count += 1
            print(f"header alias: {inc} -> {exact}")
    print(f"{count} header aliases in {alias}")


def libs(ninja, sysroot_lib, alias):
    present = {n.lower(): n for n in os.listdir(sysroot_lib)}
    names = set()
    with open(ninja, encoding="utf-8", errors="ignore") as f:
        for line in f:
            if "LINK_LIBRARIES" not in line and "LINK_FLAGS" not in line:
                continue
            names.update(re.findall(r"(?:^|\s)-l([A-Za-z0-9_.+-]+)", line))
            names.update(m for m in re.findall(r"(?:^|\s)([A-Za-z0-9_+-]+)\.lib(?=\s|$)", line))
    count = 0
    for name in sorted(names):
        candidates = [f"lib{name}.dll.a", f"{name}.dll.a", f"lib{name}.a", f"{name}.lib"]
        if any(os.path.exists(os.path.join(sysroot_lib, c)) for c in candidates):
            continue
        for c in candidates:
            exact = present.get(c.lower())
            if exact:
                link(alias, f"lib{name}.a", os.path.join(sysroot_lib, exact))
                link(alias, f"{name}.lib", os.path.join(sysroot_lib, exact))
                count += 1
                print(f"library alias: {name} -> {exact}")
                break
    print(f"{count} library aliases in {alias}")


def main():
    mode, a, b, c = sys.argv[1:5]
    os.makedirs(c, exist_ok=True)
    {"headers": headers, "libs": libs}[mode](a, b, c)


if __name__ == "__main__":
    main()
