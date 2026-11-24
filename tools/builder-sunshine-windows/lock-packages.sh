#!/usr/bin/env bash
# Regenerates packages.lock from the current MSYS2 ucrt64 repository database.
# The database signature must verify against the MSYS2 keyring: the signing key must not be
# revoked and must be an MSYS2 master key or be certified by at least two master keys
# (the same trust model pacman-key --populate msys2 sets up). Package SHA-256 values in the lock
# come from that verified database; fetch-msys2.sh checks every download against them.
# Needs: curl, gpg, python3, zstd. Usage: lock-packages.sh
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
W=$(mktemp -d); trap 'rm -rf "$W"' EXIT
REPO=${MSYS2_MIRROR:-https://repo.msys2.org/mingw/ucrt64}
[[ $REPO == https://* ]] || { echo "MSYS2_MIRROR must start with https://" >&2; exit 1; }
# Updating this trust root is a separate reviewed input change, never a branch-tip download.
KEYRING=https://raw.githubusercontent.com/msys2/MSYS2-keyring/5d249077a0cfeec9dbf51515e5e01da413d28859
curl -fsSL --proto =https --tlsv1.2 -o "$W/ucrt64.db" "$REPO/ucrt64.db"
curl -fsSL --proto =https --tlsv1.2 -o "$W/ucrt64.db.sig" "$REPO/ucrt64.db.sig"
for f in msys2.gpg msys2-trusted msys2-revoked; do curl -fsSL --proto =https --tlsv1.2 -o "$W/$f" "$KEYRING/$f"; done
(
  cd "$W"
  sha256sum -c --quiet - <<'CHECKSUMS'
1257d4ccc536c53333445a618039af4c3ea3f56b96601de9af89151ea529c19a  msys2.gpg
a8d39040a7b6cc14bf4394b5d9c838443925c32b00a7d34e8729c972392dca04  msys2-trusted
62b67ba0217745c7df189092a70d6b7a5781577f6428a5391dccd897edb5756a  msys2-revoked
CHECKSUMS
)
export GNUPGHOME="$W/gnupg"; mkdir -m 700 "$GNUPGHOME"
gpg -q --import "$W/msys2.gpg" 2>/dev/null
validsig=$(gpg --status-fd 1 --verify "$W/ucrt64.db.sig" "$W/ucrt64.db" 2>/dev/null | awk '$1=="[GNUPG:]" && $2=="VALIDSIG" {count++; sig=$3; prim=$12} END{if (count==1) print sig, prim}')
read -r sig_fpr primary_fpr <<<"$validsig"
[[ $sig_fpr =~ ^[0-9A-Fa-f]{40}$ && $primary_fpr =~ ^[0-9A-Fa-f]{40}$ ]] || {
  echo "ucrt64.db signature does not verify with full 40-char fingerprints" >&2
  exit 1
}
if grep -Eiq "^(${sig_fpr}|${primary_fpr})([^0-9A-Fa-f]|$)" "$W/msys2-revoked"; then
  echo "signing key $sig_fpr (primary $primary_fpr) is revoked" >&2
  exit 1
fi
if ! grep -qi "^${primary_fpr}:" "$W/msys2-trusted"; then
  certs=0
  while IFS= read -r issuer_fpr; do
    [[ $issuer_fpr =~ ^[0-9A-Fa-f]{40}$ ]] || continue
    if grep -Eiq "^${issuer_fpr}([^0-9A-Fa-f]|$)" "$W/msys2-revoked"; then continue; fi
    grep -qi "^${issuer_fpr}:" "$W/msys2-trusted" && certs=$((certs + 1))
  done < <(gpg --with-colons --check-sigs "$primary_fpr" 2>/dev/null | awk -F: '$1=="sig" && $2=="!" && $13 ~ /^[0-9A-Fa-f]{40}$/ {print toupper($13)}' | sort -u)
  [ "$certs" -ge 2 ] || { echo "signing key $sig_fpr (primary $primary_fpr) has only $certs master-key certifications" >&2; exit 1; }
  echo "ucrt64.db signed by $sig_fpr (primary $primary_fpr, certified by $certs MSYS2 master keys)"
else
  echo "ucrt64.db signed by MSYS2 master key $sig_fpr (primary $primary_fpr)"
fi
mkdir "$W/db"
python3 -I - "$W/ucrt64.db" "$W/db" <<'PY'
import subprocess, sys, tarfile
db_path, dest_dir = sys.argv[1:3]
proc = subprocess.Popen(["zstd", "-dc", "--", db_path], stdout=subprocess.PIPE)
try:
    with tarfile.open(fileobj=proc.stdout, mode="r|") as archive:
        archive.extractall(dest_dir, filter="data")
finally:
    proc.stdout.close()
    rc = proc.wait()
if rc != 0:
    raise SystemExit(f"zstd failed with status {rc}")
PY
python3 -I "$HERE/msys2-resolve.py" "$W/db" "$HERE/packages.in" "$HERE/packages.lock"
