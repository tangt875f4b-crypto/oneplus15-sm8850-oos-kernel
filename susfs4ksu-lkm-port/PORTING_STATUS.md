# SUSFS 2.4 LKM port — source audit

Audit date: 2026-11-20

## Target
- OnePlus 15, arm64, Linux 6.12.69
- Android 16 / 6.12 (reported by owner)
- KernelSU GKI with FinaSU Built-In
- Do not assume `ksud` is available from shell; inspect loader requirements separately.

## Source snapshots inspected

### Original project
- Repository: https://github.com/inforcqb/susfs4ksu-for-lkm
- Current default-branch commit at audit: `761b93083afd846858257221453bf306465042a3`
- This is newer than the v2.3.0-r18.9-1 release ZIP; do not use the old ZIP as the only source baseline.
- Inspected ABI, supercall dispatcher, module loader, packer and DDK workflow.

### SUSFS 2.4 reference
- Repository: https://github.com/UIRAN23/UranXSU
- Commit: `9ade2f03c7bc2e39b231e0b05105cd548226d2f4`
- `userspace/susfs_lkm` is a full vendored LKM source tree.
- Its VERSION file says `v2.4.0`; README lists `android16-6.12` as supported.
- UPSTREAM.md says the vendored LKM is based on SusFS-LKM-by-uran v2.4.0 and traces its base to the inforcqb LKM family.
- The reference supports both managed LKM loading (e.g. FinaSU) and a KernelSU ZIP path. Do not blindly transplant its ZIP early-load behavior into the target project.

## Confirmed ABI and implementation differences

Original 2.3 `kernel/susfs_abi.h`:
- `SUSFS_VERSION_STR` is `v2.3.0`.
- Does not define `CMD_SUSFS_SET_SUS_PATH_UID_FILTER` or `CMD_SUSFS_SET_PRIORITY_UID_FILTER`.

UranXSU-vendored 2.4 `kernel/susfs_abi.h`:
- `SUSFS_VERSION_STR` is `v2.4.0`.
- Adds `CMD_SUSFS_SET_SUS_PATH_UID_FILTER` (0x55554).
- Adds `CMD_SUSFS_SET_PRIORITY_UID_FILTER` (0x60030).
- Changes KSTAT `is_statically` from `int` in the inspected 2.3 LKM ABI to `bool` in the 2.4 reference ABI. This may alter layout/alignment and MUST be reconciled with the actual userspace client before copying structures.
- Adds `susfs_priority.c`, command dispatch and enabled-feature reporting for Priority UID Filter.

## Important distinction: built-in kernel patch contract vs LKM

UranXSU's `docs/susfs-kernel-contract.md` describes built-in kernel patch requirements: SELinux type/AVD registration calls, a Kconfig build contract for Priority UID Filter, and SELinux access/context changes. These are not automatically requirements or callable symbols for an independent LKM. Review the LKM's own SELinux hooks separately; do not assume those built-in patches exist on the target device.

## Migration plan
1. Use current original default-branch source as the behavior/loader baseline, not only the old release ZIP.
2. Compare original LKM files against the vendored 2.4 LKM snapshot.
3. Port 2.4 additions selectively while retaining the target project's LKM integration and packaging.
4. Audit command IDs and every ABI structure against the userspace actually used with FinaSU; resolve the KSTAT field-layout difference before shipping.
5. Check new code against Android 16 / 6.12.69 headers and symbols.
6. Build against exact matching DDK/KMI inputs; an `android16-6.12` label alone does not prove vendor symbol compatibility.
7. Keep artifacts separate from active device installation. No boot image changes or automatic flashing.

## Status
- [x] Isolated working branch created.
- [x] Audited current original source head and release/source distinction.
- [x] Located full SUSFS 2.4.0 LKM reference tree.
- [x] Identified new command IDs and Priority UID Filter source.
- [x] Identified potential KSTAT ABI layout incompatibility.
- [ ] Import reviewed source snapshot.
- [ ] Complete file-by-file migration.
- [ ] Build for exact Android 16 / 6.12 target.
- [ ] Run static/interface checks and package test ZIP.

No installable binary is claimed by this document.
