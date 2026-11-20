# SUSFS 2.4.0 LKM reference snapshot

This folder contains selected reference files copied from UIRAN23/UranXSU at commit `9ade2f03c7bc2e39b231e0b05105cd548226d2f4` (GPL-2.0). It is a comparison source, not yet the integrated OnePlus 15 build.

Files:
- `susfs_priority.c`: Priority UID Filter and SUS_PATH UID allowlist implementation.
- `susfs_avc_spoof.c`: 2.4 SELinux type/AVD registration exports used by the FinaSU/KernelSU 2.4 policy contract.
- `susfs_fp_hook.c` and `susfs_bti.h`: syscall-table hook implementation required by the priority hooks, including optional compat syscall handling.
- `susfs_abi.h`: 2.4 command IDs and payload structures.

Reference commit: https://github.com/UIRAN23/UranXSU/commit/9ade2f03c7bc2e39b231e0b05105cd548226d2f4

Important review findings before integration:
1. The reference priority wrapper shares one `which == 2` test between getpriority/setpriority and ioprio_get/ioprio_set. Linux defines `IOPRIO_WHO_USER` separately from `PRIO_USER`; verify and correct the ioprio path before enabling it.
2. The reference SELinux cleanup removes RCU hash entries and frees them before `synchronize_rcu()`; this needs deferred freeing (e.g. `kfree_rcu`) to avoid freeing entries while an RCU reader may still hold them.
3. Keep the existing LKM loader and package scripts as the baseline. Do not transplant the reference KernelSU ZIP early-load logic.
4. Preserve the 2.3 KSTAT ABI's field type unless the userspace contract proves otherwise. On the target LP64 ABI, the 2.3 `int` and 2.4 `bool` first field both leave the following 64-bit field at offset 8, but this still needs a compile-time layout assertion against the actual userspace structure.
5. FinaSU's 2.4 SELinux type-registration calls are kernel-patch integration points; an LKM can only satisfy them if its exported functions and symbol visibility match the running FinaSU build.

No build or runtime success is implied by this reference snapshot.
