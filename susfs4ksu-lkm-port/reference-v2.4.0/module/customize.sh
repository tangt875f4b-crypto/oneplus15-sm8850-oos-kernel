#!/system/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
# Installation only: copy and wire the loader.  The KMI is deliberately not
# inspected or selected here - load.sh owns detection and the override, so an
# install can succeed even when the recovery/installer environment cannot read
# the target kernel's release string.
[ "$KSU" = true ] || abort "- KernelSU-compatible manager required."
[ "$ARCH" = arm64 ] || abort "- arm64 only."
INSTALLED=/data/adb/modules/susfs_guard_lkm
HOOK=/data/adb/post-fs-data.d/00-susfs-guard-lkm.sh
if { [ -e "$HOOK" ] || [ -L "$HOOK" ]; } && ! cmp -s "$HOOK" "$MODPATH/early-dispatch.sh"; then
  [ -f "$INSTALLED/early-dispatch.sh" ] && cmp -s "$HOOK" "$INSTALLED/early-dispatch.sh" || abort "- a different early dispatcher already exists at $HOOK."
fi
if [ -f "$INSTALLED/no_early_load" ]; then
  touch "$MODPATH/no_early_load" || abort "- cannot preserve early-loading opt-out."
else
  touch "$MODPATH/early_load" || abort "- cannot enable early loading."
fi
set_perm_recursive "$MODPATH" 0 0 0755 0644
set_perm "$MODPATH/bin/susfs_insmod" 0 0 0755
for script in early-dispatch.sh late-load.sh load.sh post-fs-data.sh uninstall.sh; do
  set_perm "$MODPATH/$script" 0 0 0755
done
touch "$MODPATH/skip_mount"
if mkdir -p /data/adb/post-fs-data.d; then
  if cp "$MODPATH/early-dispatch.sh" "$HOOK.tmp" &&
     chmod 0755 "$HOOK.tmp" &&
     mv -f "$HOOK.tmp" "$HOOK"; then
    ui_print "- early dispatcher installed"
  else
    rm -f "$HOOK.tmp"
    ui_print "- warning: early dispatcher unavailable; module post-fs-data still loads"
  fi
else
  ui_print "- warning: common script directory unavailable; module post-fs-data still loads"
fi
ui_print "- SusFS LKM by uran (arm64)"
ui_print "- KMI is selected by the boot loader, not by this installer"
ui_print "- Loader only; no rules are applied"
ui_print "- Reboot to load; will not stack on an already-present susfs"
ui_print "- Early loading (post-fs-data.d) enabled by default; create $INSTALLED/no_early_load to opt out."
