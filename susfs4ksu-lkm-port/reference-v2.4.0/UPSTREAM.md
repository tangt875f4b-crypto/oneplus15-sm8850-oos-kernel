# SusFS-LKM-by-uran Upstream Divergence Notes

Base upstream: `SusFS-LKM-by-uran` `v2.4.0` (synced through commit `6f989f4`, with PAC-safe uname/proc consistency stubs, `sus_path` UID filter `0x55554`, bind-root mount hiding, and late-load compatibility).

Local UranXSU modifications (kept minimal so upstream updates remain straightforward):

1. **`kernel/ksu_umount_gate.h`**:
   - Expanded `SUSFS_FIRST_ISOLATED_UID` from `99000` to `90000` so AOSP `app_zygote` isolated child UIDs (`90000..98999`) are classified identically to regular isolated processes (`99000..99999`), matching `kernel/policy/allowlist.h`.
2. **`build-lkm.sh` & `build-insmod.sh`**:
   - Wrapper build scripts used by `.github/workflows/ddk-lkm.yml` and `.github/workflows/builtzygisk.yml` to produce `susfs_guard_lkm.ko` and freestanding `susfs_insmod` into `userspace/ksud/bin/`.
