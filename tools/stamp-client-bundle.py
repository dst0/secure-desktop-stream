#!/usr/bin/env python3
"""Record the actual source and bundled Mach-O deployment requirements before signing."""

import argparse
import json
import plistlib
import re
import subprocess
from pathlib import Path


def git(path, *args):
    return subprocess.check_output(["git", "-C", str(path), *args], text=True).strip()


def stamp(source, bundle, require_clean=False):
    protocol = source / "moonlight-common-c/moonlight-common-c"
    state = {
        "client_commit": git(source, "rev-parse", "HEAD"),
        "protocol_commit": git(protocol, "rev-parse", "HEAD"),
        "client_dirty": bool(git(source, "status", "--porcelain")),
        "protocol_dirty": bool(git(protocol, "status", "--porcelain")),
    }
    if require_clean and (state["client_dirty"] or state["protocol_dirty"]):
        raise RuntimeError("Release candidate requires clean client and protocol checkouts")
    requirements = {}
    for path in bundle.rglob("*"):
        if path.is_symlink() or not path.is_file():
            continue
        with path.open("rb") as file:
            magic = file.read(4)
        if magic not in (b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca"):
            continue
        output = subprocess.check_output(["vtool", "-show-build", str(path)], text=True)
        versions = re.findall(r"\bminos\s+([\d.]+)", output)
        if not versions:
            raise RuntimeError(f"Missing deployment requirement: {path.relative_to(bundle)}")
        requirements[str(path.relative_to(bundle))] = versions
    if not requirements:
        raise RuntimeError("Bundle contains no Mach-O images")
    version_key = lambda version: tuple(int(part) for part in version.split("."))
    minimum = max((v for versions in requirements.values() for v in versions), key=version_key)
    plist_path = bundle / "Contents/Info.plist"
    with plist_path.open("rb") as file:
        plist = plistlib.load(file)
    # Do not lower a stricter requirement already declared by the application.
    minimum = max(minimum, plist.get("LSMinimumSystemVersion", "0"), key=version_key)
    plist.update(LSMinimumSystemVersion=minimum, SDSClientCommit=state["client_commit"],
                 SDSProtocolCommit=state["protocol_commit"],
                 SDSSourceDirty=state["client_dirty"] or state["protocol_dirty"])
    with plist_path.open("wb") as file:
        plistlib.dump(plist, file)
    state.update(minimum_macos=minimum, macho_requirements=requirements)
    resources = bundle / "Contents/Resources"
    resources.mkdir(exist_ok=True)
    (resources / "sds-build.json").write_text(json.dumps(state, indent=2, sort_keys=True) + "\n")
    print(json.dumps({key: value for key, value in state.items() if key != "macho_requirements"}))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("bundle", type=Path)
    parser.add_argument("--require-clean", action="store_true")
    args = parser.parse_args()
    stamp(args.source.resolve(), args.bundle.resolve(), args.require_clean)
