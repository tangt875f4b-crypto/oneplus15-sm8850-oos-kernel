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
- [ ] Complete file-by-file migration from the pinned reference into the target module design.
- [ ] Build for exact Android 16 / 6.12 target.
- [ ] Run static/interface checks and package test ZIP.

A KMI6 build candidate has now been produced and uploaded as a GitHub Actions artifact; it is not yet device-validated and must not be treated as a confirmed safe install.


## Additional target-source verification (2026-11-20)

The linked personal kernel repository's checked-in `kernel_platform/common/Makefile` identifies Linux **6.12.35**, and its README identifies the qualified build as Android 16 ACK generation 5 / 6.12.35. The owner's previously reported live kernel is **6.12.69**. These are not the same source/build identity. Do not claim the 6.12.35 DDK build is an exact 6.12.69 match.

The original v2.3.0-r18.9-1 source is pinned as a submodule at commit `8619b6ee0d0629836e9c6ce668e8a785dfd53517`. This preserves the exact release baseline without copying or modifying the upstream repository.

The 2.4 reference source files are stored separately under `reference-2.4/kernel/`; they are audit inputs only, not yet applied to the v2.3 source tree.


## Candidate assembly and KMI6 build

- Exact original release baseline: `inforcqb/susfs4ksu-for-lkm` tag `v2.3.0-r18.9-1`, commit `8619b6ee0d0629836e9c6ce668e8a785dfd53517`.
- 2.4 LKM reference: `UIRAN23/UranXSU` commit `9ade2f03c7bc2e39b231e0b05105cd548226d2f4`.
- Candidate assembled at `susfs4ksu-lkm-port/candidate-v2.4.0/`: 2.4 kernel source plus the original v2.3 module scripts and packer.
- Local source fixes applied: separate `PRIO_USER` and `IOPRIO_WHO_USER` handling; compare full SELinux type IDs inside hash buckets; use `kfree_rcu()` for RCU-visible SELinux records; use `GFP_KERNEL` under the AVD-rule mutex.
- The candidate packer records the base and reference commits in `provenance.json` and can write `android16-6.12` into `kmi_override`, avoiding the loader's ksud fallback.
- Build workflow: `.github/workflows/build-susfs-2.4.yml`, targeting Android 16 / 6.12 KMI6 with the pinned DDK image. The run is currently pending/in progress; no compiled artifact is claimed yet.

## Kernel source identity warning

The user's linked OnePlus kernel repository `main` has `kernel_platform/common/Makefile` at Linux 6.12.35 (Android 16 KMI generation 5). The phone's reported runtime kernel is 6.12.69; public OnePlus 15 6.12.69 builds identify Android 16 KMI generation 6. The 6.12.35 source tree is therefore not used as an exact KMI6 build source.

A matching generic GKI 6.12.69 source snapshot was identified at `cctv18/android_gki_kernel_common` commit `58ee67741556c83c523f48518284c4a6b1ef31d6` (branch `android16-6.12-2026-03`). The DDK workflow is pinned to the Android 16 / 6.12 KMI6 toolchain; the build log's reported `kernelrelease` must be checked before calling it an exact 6.12.69 build.

Before any device install, verify the full output of `uname -r` on the phone and confirm it contains the expected Android 16 KMI6 tag.


## Build result (2026-11-20)

- GitHub Actions run: `44690468266` — success.
- Artifact: `susfs-2.4.0-oneplus15-android16-6.12` (14-day retention; expires 2026-12-04).
- ZIP: `SUSFS-2.4.0-OnePlus15-android16-6.12.zip`.
- ZIP SHA-256: `0a07ea276b1a49dcdce10b22415f8e8bc1a12f1cb0947b946a0924c22ed73d57`.
- Built module: ARM64 `susfs_guard_lkm-android16-6.12.ko`.
- Built standalone loader: ARM64 `susfs_insmod`.
- DDK kernel release: `6.12.76-4k`; build KMI target: `android16-6.12` (KMI6). This is a KMI6 DDK build, not an exact 6.12.69 patch-level build.
- Passed: source/ABI layout tests, layering tests, CFI-site checks, host loader symbol-match regression test, ZIP integrity, KMI override and provenance assertions.
- Package embeds `kmi_override=android16-6.12`, so the loader selects the single matching KMI without calling `ksud`.

## Remaining pre-install checks

1. Obtain the phone's complete `uname -r` string and confirm it is Android 16 KMI6 (e.g. `android16-6`); the user's earlier report only gave `6.12.69`.
2. Confirm the device does not already have built-in SUSFS active; the module loader has a duplicate-detection guard, but this must be observed on-device.
3. Test module load and each 2.4 feature on the actual OnePlus 15. A successful cross-build does not prove runtime hook compatibility.
4. FinaSU v1.6.4 release notes include Priority UID Filter controls. Older manager versions may not expose the new controls. The LKM includes the SUS_PATH UID-filter command, but manager-side UI support for that command is not yet confirmed.

No boot image was modified or flashed by this workflow.
