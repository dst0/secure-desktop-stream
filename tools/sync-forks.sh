#!/usr/bin/env bash
# Update the three public fork submodules (sunshine, moonlight-qt, moonlight-common-c)
# to their tracked origin/main heads, verify submodule remotes, and run PII checks.
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"

for sub in sunshine moonlight-qt moonlight-common-c; do
    echo "=== Syncing $sub ==="
    git submodule update --init --remote "$sub"
    if [ -f "$sub/.gitmodules" ]; then
        git -C "$sub" submodule update
    fi
done

echo "=== Updated submodule commits ==="
git submodule status

echo "=== Running PII audit ==="
python3 "$ROOT/tools/audit-pii.py" --strict --check-git-history --check-submodule-deltas
