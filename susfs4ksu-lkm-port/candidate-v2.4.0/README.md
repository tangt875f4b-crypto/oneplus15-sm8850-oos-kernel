# SUSFS 2.4.0 compatibility candidate

This candidate combines the SUSFS 2.4.0 LKM kernel source with the original
v2.3.0-r18.9-1 module loader scripts and packaging tools. The original
module load.sh, KMI selection, early dispatcher, and packer are retained.

Local correctness fixes:
- Split PRIO_USER and IOPRIO_WHO_USER filtering; they are different Linux ABI values.
- Make the SELinux SUS type hash collision-safe by storing and comparing the full type value.
- Use RCU-deferred freeing for SELinux type and access-vector rule entries.
- Use GFP_KERNEL for allocation while holding the AVD-rule mutex.

Target: OnePlus 15 ARM64, owner-reported Android 16 / 6.12.69.
The linked kernel repository default branch currently contains 6.12.35, so it is not
treated as an exact 6.12.69 build source.

This directory is source-only. No .ko, flashable ZIP, boot image, or install operation
is included until exact KMI compatibility and compilation are verified. No ksud
dependency is intentionally added.
