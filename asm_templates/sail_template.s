    .file	"template.c"
	.option nopic
	.attribute arch, "rv64i2p0_m2p0_a2p0_f2p0_d2p0_c2p0"
	.attribute unaligned_access, 0
	.attribute stack_align, 16
	.text
	.align	1
	.globl	main
	.type	main, @function

main:
	addi	sp,sp,-16
	# sd	s0,8(sp)
	addi	s0,sp,16
    li      a0, 8192
    csrw    mstatus, a0
	fscsr	zero
	li    x0,       0
	li    x1,       0
	li    x2,       0
	li    x3,       0
	li    x4,       0
	li    x5,       0
	li    x6,       0
	li    x7,       0
	li    x8,       0
	li    x9,       0
	li    x10,      0
	li    x11,      0
	li    x12,      0
	li    x13,      0
	li    x14,      0
	li    x15,      0
	li    x16,      0
	li    x17,      0
	li    x18,      0
	li    x19,      0
	li    x20,      0
	li    x21,      0
	li    x22,      0
	li    x23,      0
	li    x24,      0
	li    x25,      0
	li    x26,      0
	li    x27,      0
	li    x28,      0
	li    x29,      0
	li    x30,      0
	li    x31,      0
	fcvt.d.w    f0, x0
	fcvt.d.w    f1, x0
	fcvt.d.w    f2, x0
	fcvt.d.w    f3, x0
	fcvt.d.w    f4, x0
	fcvt.d.w    f5, x0
	fcvt.d.w    f6, x0
	fcvt.d.w    f7, x0
	fcvt.d.w    f8, x0
	fcvt.d.w    f9, x0
	fcvt.d.w    f10, x0
	fcvt.d.w    f11, x0
	fcvt.d.w    f12, x0
	fcvt.d.w    f13, x0
	fcvt.d.w    f14, x0
	fcvt.d.w    f15, x0
	fcvt.d.w    f16, x0
	fcvt.d.w    f17, x0
	fcvt.d.w    f18, x0
	fcvt.d.w    f19, x0
	fcvt.d.w    f20, x0
	fcvt.d.w    f21, x0
	fcvt.d.w    f22, x0
	fcvt.d.w    f23, x0
	fcvt.d.w    f24, x0
	fcvt.d.w    f25, x0
	fcvt.d.w    f26, x0
	fcvt.d.w    f27, x0
	fcvt.d.w    f28, x0
	fcvt.d.w    f29, x0
	fcvt.d.w    f30, x0
	fcvt.d.w    f31, x0
#APP
	nop
#NO_APP
	li	a5,0
	mv	a0,a5
	# ld	s0,8(sp)
	addi	sp,sp,16
	jr	ra
.LFE1:
	.size	main, .-main
	.ident	"GCC: (g2ee5e430018-dirty) 12.2.0"

.section ".tohost","aw",@progbits
.align 6
.globl tohost
tohost: .dword 0
