/* SPDX-License-Identifier: GPL-2.0 */
/*
 * susfs_uname_stub.S - PAC-safe return-hook stub for __arm64_sys_newuname.
 *
 * __arm64_sys_newuname can start with a PAC prologue, so a C wrapper cannot be
 * used as its detour.  This stub saves caller-saved registers + LR, calls the
 * relocated original via susfs_uname_tramp (signing against SP after frame
 * adjust + LR inside this stub), stores the return value in [sp, #160], and
 * invokes susfs_uname_decide(saved) before returning with the saved LR.
 */

	.text

	.globl	susfs_uname_stub
	.type	susfs_uname_stub, %function
susfs_uname_stub:
	sub	sp, sp, #176
	stp	x0,  x1,  [sp, #0]
	stp	x2,  x3,  [sp, #16]
	stp	x4,  x5,  [sp, #32]
	stp	x6,  x7,  [sp, #48]
	stp	x8,  x9,  [sp, #64]
	stp	x10, x11, [sp, #80]
	stp	x12, x13, [sp, #96]
	stp	x14, x15, [sp, #112]
	stp	x16, x17, [sp, #128]
	stp	x18, x30, [sp, #144]
	adrp	x16, susfs_uname_tramp
	ldr	x16, [x16, :lo12:susfs_uname_tramp]
	blr	x16
	str	x0, [sp, #160]
	mov	x0, sp
	bl	susfs_uname_decide
	ldr	x30, [sp, #152]
	add	sp, sp, #176
	ret
	.size	susfs_uname_stub, . - susfs_uname_stub

	.bss
	.align	3
	.globl	susfs_uname_tramp
susfs_uname_tramp:
	.quad	0
