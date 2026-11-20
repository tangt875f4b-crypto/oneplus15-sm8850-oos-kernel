#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# Builds the standalone freestanding `susfs_insmod` loader binary from
# SusFS-LKM-by-uran for aarch64 and writes it to $SUSFS_INSMOD_OUT.
set -euo pipefail

SELF_DIR="$(cd "$(dirname "$0")" && pwd)"
SRC="$SELF_DIR/tools/susfs_insmod.c"
OUT="${SUSFS_INSMOD_OUT:-$SELF_DIR/../ksud/bin/aarch64/susfs/susfs_insmod}"

[[ -f "$SRC" ]] || { echo "susfs_insmod.c not found at $SRC" >&2; exit 1; }

find_clang() {
    if [[ -n "${SUSFS_CC:-}" ]] && command -v "$SUSFS_CC" >/dev/null 2>&1; then
        echo "$SUSFS_CC"
        return 0
    fi
    if [[ -n "${ANDROID_NDK_HOME:-}" ]]; then
        local c
        c="$(find "$ANDROID_NDK_HOME/toolchains/llvm/prebuilt" -maxdepth 3 -name clang -type f 2>/dev/null | head -n 1 || true)"
        if [[ -n "$c" ]]; then
            echo "$c"
            return 0
        fi
    fi
    if command -v clang >/dev/null 2>&1; then
        command -v clang
        return 0
    fi
    return 1
}

CC="$(find_clang)" || { echo "clang not found to compile susfs_insmod.c" >&2; exit 1; }
mkdir -p "$(dirname "$OUT")"

"$CC" --target=aarch64-linux-gnu -O2 -nostdlib -static-pie \
    -fno-stack-protector -fno-builtin -fuse-ld=lld -Wl,-e,_start \
    -o "$OUT" "$SRC"

if command -v llvm-strip >/dev/null 2>&1; then
    llvm-strip --strip-all "$OUT" || true
fi
chmod 0755 "$OUT"
ls -la "$OUT"
