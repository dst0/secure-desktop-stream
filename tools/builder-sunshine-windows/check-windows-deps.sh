#!/usr/bin/env bash
# Lists the DLL imports of every PE executable/DLL under <dir> and fails if one of them is a
# MinGW/MSYS2 runtime DLL (present in /ucrt64/bin) that is not shipped in <dir> itself.
# This is the cross-build equivalent of the "Check Windows linkage" step in ci-windows.yml.
# Other imports remain system-or-unclassified; native loader verification is required.
#
# Usage: check-windows-deps.sh <unpacked-package-dir> [objdump]
set -euo pipefail
DIR=${1:?dir}; OBJDUMP=${2:-/ucrt64/bin/x86_64-w64-mingw32-objdump}
MSYS_BIN=${MSYS_BIN:-/ucrt64/bin}
[ -d "$DIR" ] && [ -d "$MSYS_BIN" ] && [ -x "$OBJDUMP" ] || { echo "FAIL: dependency scan inputs/toolchain are missing" >&2; exit 2; }
declare -A shipped msys
while IFS= read -r -d '' f; do shipped[$(basename "${f,,}")]=1; done < <(find "$DIR" -type f -iname '*.dll' -print0)
while IFS= read -r -d '' f; do msys[$(basename "${f,,}")]=1; done < <(find "$MSYS_BIN" -maxdepth 1 -type f -iname '*.dll' -print0)
status=0
binaries_seen=0
while IFS= read -r -d '' bin; do
  file -b "$bin" | grep -q 'PE32' || continue
  binaries_seen=$((binaries_seen + 1))
  rel=${bin#"$DIR"/}
  imports=$("$OBJDUMP" -p "$bin" | sed -n 's/^\s*DLL Name: //p' | sort -fu)
  echo "== $rel ($(file -b "$bin" | cut -d, -f1))"
  while IFS= read -r dll; do
    [ -n "$dll" ] || continue
    key=${dll,,}
    if [[ -n ${shipped[$key]:-} ]]; then kind=shipped
    elif [[ -n ${msys[$key]:-} ]]; then kind=MISSING-MSYS2-RUNTIME; status=1
    else kind=system-or-unclassified; fi
    printf '   %-40s %s\n' "$dll" "$kind"
  done <<< "$imports"
done < <(find "$DIR" -type f \( -iname '*.exe' -o -iname '*.dll' \) -print0 | sort -z)
if [ "$binaries_seen" -eq 0 ]; then echo "FAIL: no PE binaries were inspected" >&2; exit 2; fi
if [ $status -ne 0 ]; then echo "FAIL: MSYS2 DLLs are imported but not shipped"; else echo "OK: every known MSYS2 runtime import is shipped; native loader verification remains required"; fi
exit $status
