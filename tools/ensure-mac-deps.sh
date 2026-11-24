#!/usr/bin/env bash
# Verify and (when SDS_AUTO_INSTALL_DEPS=1) automatically install macOS build/test
# dependencies and initialize the moonlight-common-c submodule when given a worktree.
#
# Usage: tools/ensure-mac-deps.sh [moonlight-qt-worktree]
set -euo pipefail

SRC=${1:-}
AUTO=${SDS_AUTO_INSTALL_DEPS:-1}

if ! xcode-select -p >/dev/null 2>&1; then
    echo "error: Apple Command Line Tools are not installed; run: xcode-select --install" >&2
    exit 2
fi

BREW=$(command -v brew || true)
if [[ -z "$BREW" && -x /opt/homebrew/bin/brew ]]; then
    BREW=/opt/homebrew/bin/brew
elif [[ -z "$BREW" && -x /usr/local/bin/brew ]]; then
    BREW=/usr/local/bin/brew
fi
if [[ -z "$BREW" ]]; then
    echo "error: Homebrew is required on macOS (install from Homebrew before building)" >&2
    exit 2
fi
BREW_DIR=$(dirname "$BREW")
if [[ ":$PATH:" != *":$BREW_DIR:"* ]]; then
    export PATH="$BREW_DIR:$PATH"
fi
BREW_PREFIX=$("$BREW" --prefix)

FORMULAS=(
    qtbase
    qtdeclarative
    qtsvg
    sdl2
    sdl2_ttf
    sdl3
    ffmpeg
    opus
    openssl
    pkg-config
)

MISSING=()
for pkg in "${FORMULAS[@]}"; do
    if [[ ! -e "$BREW_PREFIX/opt/$pkg" ]] && ! "$BREW" list --formula "$pkg" >/dev/null 2>&1; then
        MISSING+=("$pkg")
    fi
done

if (( ${#MISSING[@]} > 0 )); then
    if [[ "$AUTO" == "1" ]]; then
        echo "-- installing missing macOS Homebrew dependencies: ${MISSING[*]}"
        "$BREW" install "${MISSING[@]}"
    else
        echo "error: missing macOS Homebrew dependencies: ${MISSING[*]}" >&2
        exit 2
    fi
fi

if [[ -n "$SRC" ]]; then
    [[ -d "$SRC" ]] || { echo "error: $SRC does not exist" >&2; exit 2; }
    if [[ ! -f "$SRC/moonlight-common-c/moonlight-common-c/src/Limelight.h" ]]; then
        if [[ "$AUTO" == "1" ]]; then
            echo "-- initializing moonlight-common-c submodule in $SRC"
            git -C "$SRC" submodule update --init moonlight-common-c/moonlight-common-c
        else
            echo "error: moonlight-common-c submodule is not checked out in $SRC" >&2
            exit 2
        fi
    fi
fi
