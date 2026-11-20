#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
#
# Builds the vendored SusFS-LKM-by-uran kernel module inside an Android DDK
# container and writes the stripped output to $SUSFS_OUT.
set -eu

SELF_DIR="$(cd "$(dirname "$0")" && pwd)"
SRC="$SELF_DIR/kernel"
VERSION_FILE="$SELF_DIR/VERSION"

[ -d "$SRC" ] || { echo "SusFS LKM source not found at $SRC" >&2; exit 1; }
[ -n "${KDIR:-}" ] || { echo "KDIR is not set; run inside the Android DDK image" >&2; exit 1; }
[ -n "${SUSFS_OUT:-}" ] || { echo "SUSFS_OUT is not set" >&2; exit 1; }

SOURCE_VERSION="${SUSFS_BUILD_VERSION:-}"
if [ -z "$SOURCE_VERSION" ] && [ -f "$VERSION_FILE" ]; then
    SOURCE_VERSION="$(tr -d ' \t\r\n' < "$VERSION_FILE")"
fi
SOURCE_VERSION="${SOURCE_VERSION:-v2.4.0}"

build_dir="$(mktemp -d)"
trap 'rm -rf "$build_dir"' EXIT
cp -a "$SRC/." "$build_dir/"

echo "-- building SusFS-LKM-by-uran ($SOURCE_VERSION) against $KDIR"
make -C "$KDIR" M="$build_dir" ARCH=arm64 CC=clang LLVM=1 LLVM_IAS=1 \
    SUSFS_BUILD_VERSION="$SOURCE_VERSION" modules -j"$(nproc 2>/dev/null || echo 4)"

ko="$build_dir/susfs_guard_lkm.ko"
[ -f "$ko" ] || { echo "susfs_guard_lkm.ko was not produced in $build_dir" >&2; exit 1; }

if command -v python3 >/dev/null 2>&1; then
    if [ -f "$SELF_DIR/tools/cfi_sites.py" ]; then
        ALLOW="init_module,susfs_layers_down,susfs_tw_func,susfs_watch_freeing,hk_own_run,hk_write_run"
        python3 "$SELF_DIR/tools/cfi_sites.py" --allow "$ALLOW" "$ko"
    fi
    if [ -n "${SUSFS_KMI:-}" ] && [ -f "$SELF_DIR/build.py" ]; then
        python3 "$SELF_DIR/build.py" --verify-ko "$ko" --kmi "$SUSFS_KMI" --expected-version "$SOURCE_VERSION"
    fi
fi

llvm-strip --strip-unneeded -R .BTF "$ko"
mkdir -p "$(dirname "$SUSFS_OUT")"
cp "$ko" "$SUSFS_OUT"
ls -la "$SUSFS_OUT"
