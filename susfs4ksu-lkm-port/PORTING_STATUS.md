# SUSFS 2.4 LKM port — working notes

This directory is reserved for an isolated SUSFS LKM 2.4 port. It does not modify the kernel source or the repository's default branch.

## Target device/kernel
- Device: OnePlus 15
- Architecture: arm64
- Kernel: 6.12.69
- Kernel family: Android 16 / 6.12 (reported by the owner)
- Root environment: KernelSU GKI with FinaSU Built-In

## Porting constraints
- Keep the upstream `inforcqb/susfs4ksu-for-lkm` LKM loading architecture as the compatibility baseline.
- Bring in SUSFS 2.4.0 core changes and new interfaces from upstream/reference implementations.
- Preserve existing 2.3 functionality and userspace command/ABI compatibility wherever possible.
- Do not replace the device boot image or flash anything automatically.
- Keep this work on the `susfs-2.4-port-work` branch until source review and build validation pass.

## Validation required before calling this usable
- Compare all 2.3 and 2.4 commands, structures, and ioctl/supercall interfaces.
- Check symbol resolution and hook availability for the target 6.12.69 kernel.
- Build the module against the exact matching kernel headers/symbol inputs.
- Verify install/uninstall and failure rollback paths.
- Test old and new features separately; mark unsupported features explicitly.
- Produce a checksummed test ZIP only after a successful build.

## Status
- [x] Isolated working branch created.
- [ ] Import and inspect the exact upstream LKM source snapshot.
- [ ] Diff SUSFS 2.3 baseline against SUSFS 2.4.0 source.
- [ ] Port changes while retaining the original loader and ABI where possible.
- [ ] Build and run static/interface checks.
- [ ] Package a test artifact.

No installable binary is claimed by this document.
