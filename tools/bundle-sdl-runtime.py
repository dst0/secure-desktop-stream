#!/usr/bin/env python3
"""Bundle the reviewed SDL3 runtime dynamically required by SDL2-compat on macOS."""

import argparse
import hashlib
import json
import os
import subprocess
from pathlib import Path


MACHO_THIN_MAGICS = {b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xce"}
MACHO_FAT_MAGICS = {
    b"\xca\xfe\xba\xbe": "big",
    b"\xbe\xba\xfe\xca": "little",
    b"\xca\xfe\xba\xbf": "big",
    b"\xbf\xba\xfe\xca": "little",
}


def is_macho(path: Path) -> bool:
    if path.is_symlink() or not path.is_file():
        return False
    with path.open("rb") as file:
        header = file.read(8)
    if len(header) < 4:
        return False
    magic = header[:4]
    if magic in MACHO_THIN_MAGICS:
        return True
    endian = MACHO_FAT_MAGICS.get(magic)
    if endian and len(header) == 8:
        nfat = int.from_bytes(header[4:8], endian)
        return 0 < nfat < 20
    return False


def parse_load_dependencies(path: Path) -> list[str]:
    """Return unique LC_LOAD_* / LC_REEXPORT_DYLIB names across all Mach-O slices."""
    output = subprocess.check_output(["otool", "-l", "-arch", "all", str(path)], text=True)
    lines = output.splitlines()
    dependencies: list[str] = []
    seen: set[str] = set()
    load_cmds = {"cmd LC_LOAD_DYLIB", "cmd LC_LOAD_WEAK_DYLIB", "cmd LC_REEXPORT_DYLIB"}
    i = 0
    while i < len(lines):
        if lines[i].strip() in load_cmds:
            for j in range(i + 1, min(i + 12, len(lines))):
                entry = lines[j].strip()
                if entry.startswith(("cmd ", "Load command ", "Mach header")):
                    break
                if entry.startswith("name "):
                    dep = entry[5:].rsplit(" (offset ", 1)[0]
                    if dep not in seen:
                        seen.add(dep)
                        dependencies.append(dep)
                    break
        i += 1
    return dependencies


def bundle_runtime(bundle):
    frameworks = bundle / "Contents/Frameworks"
    shim = frameworks / "libSDL2-2.0.0.dylib"
    if not shim.is_file() or b"@loader_path/libSDL3.dylib" not in shim.read_bytes():
        return None
    prefix = Path(subprocess.check_output(["brew", "--prefix", "sdl3"], text=True).strip()).resolve()
    source = (prefix / "lib/libSDL3.0.dylib").resolve(strict=True)
    cellar = Path(subprocess.check_output(["brew", "--cellar", "sdl3"], text=True).strip()).resolve()
    if not prefix.is_relative_to(cellar):
        raise RuntimeError("SDL3 runtime is outside the installed Homebrew package")
    if not source.is_relative_to(prefix):
        raise RuntimeError("SDL3 library resolves outside its package prefix")
    receipt_file = prefix / "INSTALL_RECEIPT.json"
    receipt = json.loads(receipt_file.read_text())
    if receipt.get("source", {}).get("tap") != "homebrew/core" or not receipt.get("poured_from_bottle"):
        raise RuntimeError("SDL3 runtime requires a reviewed Homebrew-core bottle")
    architectures = subprocess.check_output(["lipo", "-archs", str(source)], text=True).split()
    client_architectures = subprocess.check_output(["lipo", "-archs", str(bundle / "Contents/MacOS/Moonlight")], text=True).split()
    if not set(client_architectures).issubset(architectures):
        raise RuntimeError("SDL3 runtime does not support every client architecture")
    for dependency in parse_load_dependencies(source):
        if not dependency.startswith(("/usr/lib/", "/System/Library/")):
            raise RuntimeError("SDL3 has an unreviewed non-system dependency: " + dependency)
    destination = frameworks / "libSDL3.dylib"
    data = source.read_bytes()
    destination.write_bytes(data)
    os.chmod(destination, 0o755)
    subprocess.run(["install_name_tool", "-id", "@rpath/libSDL3.dylib", str(destination)], check=True)
    rewritten = []
    # Homebrew's sdl2 alias and sdl2-compat prefix can differ. macdeployqt can leave
    # SDL2_ttf pointing at that absolute alias, loading a second SDL/SDL3 instance.
    names = {"libSDL2-2.0.0.dylib": "libSDL2-2.0.0.dylib",
             "libSDL3.0.dylib": "libSDL3.dylib", "libSDL3.dylib": "libSDL3.dylib"}
    for image in bundle.rglob("*"):
        if not is_macho(image):
            continue
        for dependency in parse_load_dependencies(image):
            filename = Path(dependency).name
            if dependency.startswith(("/opt/homebrew/", "/usr/local/")) and filename in names:
                if not os.access(image, os.W_OK):
                    os.chmod(image, image.stat().st_mode | 0o200)
                replacement = "@executable_path/../Frameworks/" + names[filename]
                subprocess.run(["install_name_tool", "-change", dependency, replacement, str(image)], check=True)
                rewritten.append({"image": str(image.relative_to(bundle)), "dependency": dependency, "replacement": replacement})
    provenance = {
        "package": "sdl3", "version": prefix.name, "tap": "homebrew/core",
        "poured_from_bottle": True, "architectures": architectures,
        "source_sha256": hashlib.sha256(data).hexdigest(),
        "receipt_sha256": hashlib.sha256(receipt_file.read_bytes()).hexdigest(),
        "bundled_name": "Contents/Frameworks/libSDL3.dylib",
        "rewritten_dependencies": rewritten,
    }
    resources = bundle / "Contents/Resources"
    resources.mkdir(parents=True, exist_ok=True)
    (resources / "sds-sdl-runtime.json").write_text(json.dumps(provenance, indent=2, sort_keys=True) + "\n")
    return provenance


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("bundle", type=Path)
    arguments = parser.parse_args()
    result = bundle_runtime(arguments.bundle.resolve(strict=True))
    print(json.dumps(result if result is not None else {"sdl2_compat": False}, sort_keys=True))
