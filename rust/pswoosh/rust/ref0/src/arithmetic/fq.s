	.att_syntax
	.text
	.p2align	5
	.globl	_fp_fromM
	.globl	fp_fromM
	.globl	_fp_toM
	.globl	fp_toM
	.globl	_fp_inv
	.globl	fp_inv
	.globl	_fp_expm_noct
	.globl	fp_expm_noct
	.globl	_fp_sqr
	.globl	fp_sqr
	.globl	_fp_mul
	.globl	fp_mul
	.globl	_fp_sub
	.globl	fp_sub
	.globl	_fp_add
	.globl	fp_add
	.globl	_bn_sqrn
	.globl	bn_sqrn
	.globl	_bn_muln
	.globl	bn_muln
	.globl	_bn_subn
	.globl	bn_subn
	.globl	_bn_addn
	.globl	bn_addn
	.globl	_bn_set0
	.globl	bn_set0
	.globl	_bn_copy
	.globl	bn_copy
	.globl	_bn_test0
	.globl	bn_test0
	.globl	_bn_eq
	.globl	bn_eq
_fp_fromM:
fp_fromM:
	movq	%rsp, %rax
	leaq	-72(%rsp), %rsp
	andq	$-8, %rsp
	movq	%rax, 64(%rsp)
	movq	%rbx, 32(%rsp)
	movq	%rbp, 40(%rsp)
	movq	%r12, 48(%rsp)
	movq	%r13, 56(%rsp)
	movq	(%rsi), %rax
	movq	%rax, (%rsp)
	movq	8(%rsi), %rax
	movq	%rax, 8(%rsp)
	movq	16(%rsi), %rax
	movq	%rax, 16(%rsp)
	movq	24(%rsi), %rax
	movq	%rax, 24(%rsp)
	movq	%rsp, %rax
	leaq	-96(%rsp), %rsp
	leaq	Lfp_fromM$1(%rip), %r9
	jmp 	L_fp_fromM$1
Lfp_fromM$1:
	leaq	96(%rsp), %rsp
	movq	(%rsi), %rax
	movq	%rax, (%rdi)
	movq	8(%rsi), %rax
	movq	%rax, 8(%rdi)
	movq	16(%rsi), %rax
	movq	%rax, 16(%rdi)
	movq	24(%rsi), %rax
	movq	%rax, 24(%rdi)
	movq	32(%rsp), %rbx
	movq	40(%rsp), %rbp
	movq	48(%rsp), %r12
	movq	56(%rsp), %r13
	movq	64(%rsp), %rsp
	ret 
_fp_toM:
fp_toM:
	movq	%rsp, %rax
	leaq	-80(%rsp), %rsp
	andq	$-8, %rsp
	movq	%rax, 72(%rsp)
	movq	%rbx, 32(%rsp)
	movq	%rbp, 40(%rsp)
	movq	%r12, 48(%rsp)
	movq	%r13, 56(%rsp)
	movq	%r14, 64(%rsp)
	movq	(%rsi), %rax
	movq	%rax, (%rsp)
	movq	8(%rsi), %rax
	movq	%rax, 8(%rsp)
	movq	16(%rsi), %rax
	movq	%rax, 16(%rsp)
	movq	24(%rsi), %rax
	movq	%rax, 24(%rsp)
	movq	%rsp, %rax
	leaq	Lfp_toM$1(%rip), %r14
	jmp 	L_fp_toM$1
Lfp_toM$1:
	movq	(%r13), %rax
	movq	%rax, (%rdi)
	movq	8(%r13), %rax
	movq	%rax, 8(%rdi)
	movq	16(%r13), %rax
	movq	%rax, 16(%rdi)
	movq	24(%r13), %rax
	movq	%rax, 24(%rdi)
	movq	32(%rsp), %rbx
	movq	40(%rsp), %rbp
	movq	48(%rsp), %r12
	movq	56(%rsp), %r13
	movq	64(%rsp), %r14
	movq	72(%rsp), %rsp
	ret 
_fp_inv:
fp_inv:
	movq	%rsp, %rax
	leaq	-120(%rsp), %rsp
	andq	$-8, %rsp
	movq	%rax, 112(%rsp)
	movq	%rbx, 72(%rsp)
	movq	%rbp, 80(%rsp)
	movq	%r12, 88(%rsp)
	movq	%r13, 96(%rsp)
	movq	%r14, 104(%rsp)
	movq	%rdi, (%rsp)
	movq	(%rsi), %rax
	movq	%rax, 8(%rsp)
	movq	8(%rsi), %rax
	movq	%rax, 16(%rsp)
	movq	16(%rsi), %rax
	movq	%rax, 24(%rsp)
	movq	24(%rsi), %rax
	movq	%rax, 32(%rsp)
	leaq	8(%rsp), %rax
	leaq	40(%rsp), %rdx
	leaq	glob_data + 72(%rip), %rcx
	leaq	-64(%rsp), %rsp
	leaq	Lfp_inv$1(%rip), %rsi
	movq	%rsi, 56(%rsp)
	jmp 	L_fp_exp$1
Lfp_inv$1:
	leaq	64(%rsp), %rsp
	movq	(%rsp), %rax
	movq	(%rdx), %rcx
	movq	%rcx, (%rax)
	movq	8(%rdx), %rcx
	movq	%rcx, 8(%rax)
	movq	16(%rdx), %rcx
	movq	%rcx, 16(%rax)
	movq	24(%rdx), %rcx
	movq	%rcx, 24(%rax)
	movq	72(%rsp), %rbx
	movq	80(%rsp), %rbp
	movq	88(%rsp), %r12
	movq	96(%rsp), %r13
	movq	104(%rsp), %r14
	movq	112(%rsp), %rsp
	ret 
_fp_expm_noct:
fp_expm_noct:
	movq	%rsp, %rax
	leaq	-152(%rsp), %rsp
	andq	$-8, %rsp
	movq	%rax, 144(%rsp)
	movq	%rbx, 104(%rsp)
	movq	%rbp, 112(%rsp)
	movq	%r12, 120(%rsp)
	movq	%r13, 128(%rsp)
	movq	%r14, 136(%rsp)
	movq	%rdi, (%rsp)
	movq	(%rsi), %rax
	movq	%rax, 8(%rsp)
	movq	8(%rsi), %rax
	movq	%rax, 16(%rsp)
	movq	16(%rsi), %rax
	movq	%rax, 24(%rsp)
	movq	24(%rsi), %rax
	movq	%rax, 32(%rsp)
	leaq	8(%rsp), %rax
	movq	(%rdx), %rcx
	movq	%rcx, 40(%rsp)
	movq	8(%rdx), %rcx
	movq	%rcx, 48(%rsp)
	movq	16(%rdx), %rcx
	movq	%rcx, 56(%rsp)
	movq	24(%rdx), %rcx
	movq	%rcx, 64(%rsp)
	leaq	40(%rsp), %rcx
	leaq	72(%rsp), %rdx
	leaq	-64(%rsp), %rsp
	leaq	Lfp_expm_noct$1(%rip), %rsi
	movq	%rsi, 56(%rsp)
	jmp 	L_fp_exp$1
Lfp_expm_noct$1:
	leaq	64(%rsp), %rsp
	movq	(%rsp), %rax
	movq	(%rdx), %rcx
	movq	%rcx, (%rax)
	movq	8(%rdx), %rcx
	movq	%rcx, 8(%rax)
	movq	16(%rdx), %rcx
	movq	%rcx, 16(%rax)
	movq	24(%rdx), %rcx
	movq	%rcx, 24(%rax)
	movq	104(%rsp), %rbx
	movq	112(%rsp), %rbp
	movq	120(%rsp), %r12
	movq	128(%rsp), %r13
	movq	136(%rsp), %r14
	movq	144(%rsp), %rsp
	ret 
_fp_sqr:
fp_sqr:
	movq	%rsp, %rax
	leaq	-104(%rsp), %rsp
	andq	$-8, %rsp
	movq	%rax, 96(%rsp)
	movq	%rbx, 64(%rsp)
	movq	%rbp, 72(%rsp)
	movq	%r12, 80(%rsp)
	movq	%r13, 88(%rsp)
	movq	(%rsi), %rax
	movq	%rax, (%rsp)
	movq	8(%rsi), %rax
	movq	%rax, 8(%rsp)
	movq	16(%rsi), %rax
	movq	%rax, 16(%rsp)
	movq	24(%rsi), %rax
	movq	%rax, 24(%rsp)
	movq	%rsp, %r8
	leaq	32(%rsp), %rax
	leaq	-96(%rsp), %rsp
	leaq	Lfp_sqr$1(%rip), %rbp
	jmp 	L_fp_sqr$1
Lfp_sqr$1:
	leaq	96(%rsp), %rsp
	movq	(%r12), %rax
	movq	%rax, (%rdi)
	movq	8(%r12), %rax
	movq	%rax, 8(%rdi)
	movq	16(%r12), %rax
	movq	%rax, 16(%rdi)
	movq	24(%r12), %rax
	movq	%rax, 24(%rdi)
	movq	64(%rsp), %rbx
	movq	72(%rsp), %rbp
	movq	80(%rsp), %r12
	movq	88(%rsp), %r13
	movq	96(%rsp), %rsp
	ret 
_fp_mul:
fp_mul:
	movq	%rsp, %rax
	leaq	-136(%rsp), %rsp
	andq	$-8, %rsp
	movq	%rax, 128(%rsp)
	movq	%rbx, 96(%rsp)
	movq	%rbp, 104(%rsp)
	movq	%r12, 112(%rsp)
	movq	%r13, 120(%rsp)
	movq	(%rsi), %rax
	movq	%rax, (%rsp)
	movq	8(%rsi), %rax
	movq	%rax, 8(%rsp)
	movq	16(%rsi), %rax
	movq	%rax, 16(%rsp)
	movq	24(%rsi), %rax
	movq	%rax, 24(%rsp)
	movq	%rsp, %r10
	movq	(%rdx), %rax
	movq	%rax, 32(%rsp)
	movq	8(%rdx), %rax
	movq	%rax, 40(%rsp)
	movq	16(%rdx), %rax
	movq	%rax, 48(%rsp)
	movq	24(%rdx), %rax
	movq	%rax, 56(%rsp)
	leaq	32(%rsp), %r8
	leaq	64(%rsp), %rax
	leaq	-96(%rsp), %rsp
	leaq	Lfp_mul$1(%rip), %rbp
	jmp 	L_fp_mul$1
Lfp_mul$1:
	leaq	96(%rsp), %rsp
	movq	(%r12), %rax
	movq	%rax, (%rdi)
	movq	8(%r12), %rax
	movq	%rax, 8(%rdi)
	movq	16(%r12), %rax
	movq	%rax, 16(%rdi)
	movq	24(%r12), %rax
	movq	%rax, 24(%rdi)
	movq	96(%rsp), %rbx
	movq	104(%rsp), %rbp
	movq	112(%rsp), %r12
	movq	120(%rsp), %r13
	movq	128(%rsp), %rsp
	ret 
_fp_sub:
fp_sub:
	movq	%rsp, %r10
	leaq	-64(%rsp), %rsp
	andq	$-8, %rsp
	movq	(%rsi), %rax
	movq	%rax, (%rsp)
	movq	8(%rsi), %rax
	movq	%rax, 8(%rsp)
	movq	16(%rsi), %rax
	movq	%rax, 16(%rsp)
	movq	24(%rsi), %rax
	movq	%rax, 24(%rsp)
	movq	%rsp, %rax
	movq	(%rdx), %rcx
	movq	%rcx, 32(%rsp)
	movq	8(%rdx), %rcx
	movq	%rcx, 40(%rsp)
	movq	16(%rdx), %rcx
	movq	%rcx, 48(%rsp)
	movq	24(%rdx), %rcx
	movq	%rcx, 56(%rsp)
	leaq	32(%rsp), %rdx
	leaq	-32(%rsp), %rsp
	leaq	Lfp_sub$1(%rip), %rcx
	jmp 	L_fp_sub$1
Lfp_sub$1:
	leaq	32(%rsp), %rsp
	movq	(%rax), %rcx
	movq	%rcx, (%rdi)
	movq	8(%rax), %rcx
	movq	%rcx, 8(%rdi)
	movq	16(%rax), %rcx
	movq	%rcx, 16(%rdi)
	movq	24(%rax), %rax
	movq	%rax, 24(%rdi)
	movq	%r10, %rsp
	ret 
_fp_add:
fp_add:
	movq	%rsp, %r10
	leaq	-64(%rsp), %rsp
	andq	$-8, %rsp
	movq	(%rsi), %rax
	movq	%rax, (%rsp)
	movq	8(%rsi), %rax
	movq	%rax, 8(%rsp)
	movq	16(%rsi), %rax
	movq	%rax, 16(%rsp)
	movq	24(%rsi), %rax
	movq	%rax, 24(%rsp)
	movq	%rsp, %rax
	movq	(%rdx), %rcx
	movq	%rcx, 32(%rsp)
	movq	8(%rdx), %rcx
	movq	%rcx, 40(%rsp)
	movq	16(%rdx), %rcx
	movq	%rcx, 48(%rsp)
	movq	24(%rdx), %rcx
	movq	%rcx, 56(%rsp)
	leaq	32(%rsp), %rdx
	leaq	-32(%rsp), %rsp
	leaq	Lfp_add$1(%rip), %rcx
	jmp 	L_fp_add$1
Lfp_add$1:
	leaq	32(%rsp), %rsp
	movq	(%rax), %rcx
	movq	%rcx, (%rdi)
	movq	8(%rax), %rcx
	movq	%rcx, 8(%rdi)
	movq	16(%rax), %rcx
	movq	%rcx, 16(%rdi)
	movq	24(%rax), %rax
	movq	%rax, 24(%rdi)
	movq	%r10, %rsp
	ret 
_bn_sqrn:
bn_sqrn:
	movq	%rsp, %rax
	leaq	-104(%rsp), %rsp
	andq	$-8, %rsp
	movq	%rax, 96(%rsp)
	movq	(%rsi), %rax
	movq	%rax, (%rsp)
	movq	8(%rsi), %rax
	movq	%rax, 8(%rsp)
	movq	16(%rsi), %rax
	movq	%rax, 16(%rsp)
	movq	24(%rsi), %rax
	movq	%rax, 24(%rsp)
	movq	%rsp, %rsi
	leaq	32(%rsp), %r8
	movq	(%rsi), %rax
	mulq	%rax
	movq	%rax, (%r8)
	movq	%rdx, %r9
	xorq	%r10, %r10
	xorq	%rcx, %rcx
	movq	(%rsi), %rax
	movq	8(%rsi), %rdx
	mulq	%rdx
	movq	%rax, %r11
	shlq	$1, %rax
	shldq	$1, %r11, %rdx
	movq	$0, %r11
	adcq	%r11, %r11
	addq	%rax, %r9
	adcq	%rdx, %r10
	adcq	%r11, %rcx
	movq	%r9, %rax
	xorq	%r9, %r9
	movq	%rax, 8(%r8)
	movq	(%rsi), %rax
	movq	16(%rsi), %rdx
	mulq	%rdx
	movq	%rax, %r11
	shlq	$1, %rax
	shldq	$1, %r11, %rdx
	movq	$0, %r11
	adcq	%r11, %r11
	addq	%rax, %r10
	adcq	%rdx, %rcx
	adcq	%r11, %r9
	movq	8(%rsi), %rax
	mulq	%rax
	addq	%rax, %r10
	adcq	%rdx, %rcx
	adcq	$0, %r9
	movq	%r10, %rax
	xorq	%r10, %r10
	movq	%rax, 16(%r8)
	movq	(%rsi), %rax
	movq	24(%rsi), %rdx
	mulq	%rdx
	movq	%rax, %r11
	shlq	$1, %rax
	shldq	$1, %r11, %rdx
	movq	$0, %r11
	adcq	%r11, %r11
	addq	%rax, %rcx
	adcq	%rdx, %r9
	adcq	%r11, %r10
	movq	8(%rsi), %rax
	movq	16(%rsi), %rdx
	mulq	%rdx
	movq	%rax, %r11
	shlq	$1, %rax
	shldq	$1, %r11, %rdx
	movq	$0, %r11
	adcq	%r11, %r11
	addq	%rax, %rcx
	adcq	%rdx, %r9
	adcq	%r11, %r10
	movq	%rcx, %rax
	xorq	%rcx, %rcx
	movq	%rax, 24(%r8)
	movq	8(%rsi), %rax
	movq	24(%rsi), %rdx
	mulq	%rdx
	movq	%rax, %r11
	shlq	$1, %rax
	shldq	$1, %r11, %rdx
	movq	$0, %r11
	adcq	%r11, %r11
	addq	%rax, %r9
	adcq	%rdx, %r10
	adcq	%r11, %rcx
	movq	16(%rsi), %rax
	mulq	%rax
	addq	%rax, %r9
	adcq	%rdx, %r10
	adcq	$0, %rcx
	movq	%r9, %rax
	xorq	%r9, %r9
	movq	%rax, 32(%r8)
	movq	16(%rsi), %rax
	movq	24(%rsi), %rdx
	mulq	%rdx
	movq	%rax, %r11
	shlq	$1, %rax
	shldq	$1, %r11, %rdx
	movq	$0, %r11
	adcq	%r11, %r11
	addq	%rax, %r10
	adcq	%rdx, %rcx
	adcq	%r11, %r9
	xorq	%r11, %r11
	movq	%r10, 40(%r8)
	movq	24(%rsi), %rax
	mulq	%rax
	addq	%rax, %rcx
	adcq	%rdx, %r9
	adcq	$0, %r11
	xorq	%rax, %rax
	movq	%rcx, 48(%r8)
	movq	%r9, 56(%r8)
	movq	(%r8), %rax
	movq	%rax, (%rdi)
	movq	8(%r8), %rax
	movq	%rax, 8(%rdi)
	movq	16(%r8), %rax
	movq	%rax, 16(%rdi)
	movq	24(%r8), %rax
	movq	%rax, 24(%rdi)
	movq	32(%r8), %rax
	movq	%rax, 32(%rdi)
	movq	40(%r8), %rax
	movq	%rax, 40(%rdi)
	movq	48(%r8), %rax
	movq	%rax, 48(%rdi)
	movq	56(%r8), %rax
	movq	%rax, 56(%rdi)
	movq	96(%rsp), %rsp
	ret 
_bn_muln:
bn_muln:
	movq	%rsp, %rax
	leaq	-144(%rsp), %rsp
	andq	$-8, %rsp
	movq	%rax, 136(%rsp)
	movq	%rbx, 128(%rsp)
	movq	(%rsi), %rax
	movq	%rax, (%rsp)
	movq	8(%rsi), %rax
	movq	%rax, 8(%rsp)
	movq	16(%rsi), %rax
	movq	%rax, 16(%rsp)
	movq	24(%rsi), %rax
	movq	%rax, 24(%rsp)
	movq	%rsp, %r8
	movq	(%rdx), %rax
	movq	%rax, 32(%rsp)
	movq	8(%rdx), %rax
	movq	%rax, 40(%rsp)
	movq	16(%rdx), %rax
	movq	%rax, 48(%rsp)
	movq	24(%rdx), %rax
	movq	%rax, 56(%rsp)
	leaq	32(%rsp), %r9
	leaq	64(%rsp), %r11
	movq	(%r8), %rax
	mulq	(%r9)
	movq	%rax, (%r11)
	movq	%rdx, %r10
	xorq	%rcx, %rcx
	xorq	%rsi, %rsi
	movq	(%r8), %rax
	mulq	8(%r9)
	addq	%rax, %r10
	adcq	%rdx, %rcx
	adcq	$0, %rsi
	movq	8(%r8), %rax
	mulq	(%r9)
	addq	%rax, %r10
	adcq	%rdx, %rcx
	adcq	$0, %rsi
	movq	%r10, %rax
	xorq	%r10, %r10
	movq	%rax, 8(%r11)
	movq	(%r8), %rax
	mulq	16(%r9)
	addq	%rax, %rcx
	adcq	%rdx, %rsi
	adcq	$0, %r10
	movq	8(%r8), %rax
	mulq	8(%r9)
	addq	%rax, %rcx
	adcq	%rdx, %rsi
	adcq	$0, %r10
	movq	16(%r8), %rax
	mulq	(%r9)
	addq	%rax, %rcx
	adcq	%rdx, %rsi
	adcq	$0, %r10
	movq	%rcx, %rax
	xorq	%rcx, %rcx
	movq	%rax, 16(%r11)
	movq	(%r8), %rax
	mulq	24(%r9)
	addq	%rax, %rsi
	adcq	%rdx, %r10
	adcq	$0, %rcx
	movq	8(%r8), %rax
	mulq	16(%r9)
	addq	%rax, %rsi
	adcq	%rdx, %r10
	adcq	$0, %rcx
	movq	16(%r8), %rax
	mulq	8(%r9)
	addq	%rax, %rsi
	adcq	%rdx, %r10
	adcq	$0, %rcx
	movq	24(%r8), %rax
	mulq	(%r9)
	addq	%rax, %rsi
	adcq	%rdx, %r10
	adcq	$0, %rcx
	movq	%rsi, %rax
	xorq	%rsi, %rsi
	movq	%rax, 24(%r11)
	movq	8(%r8), %rax
	mulq	24(%r9)
	addq	%rax, %r10
	adcq	%rdx, %rcx
	adcq	$0, %rsi
	movq	16(%r8), %rax
	mulq	16(%r9)
	addq	%rax, %r10
	adcq	%rdx, %rcx
	adcq	$0, %rsi
	movq	24(%r8), %rax
	mulq	8(%r9)
	addq	%rax, %r10
	adcq	%rdx, %rcx
	adcq	$0, %rsi
	movq	%r10, %rax
	xorq	%r10, %r10
	movq	%rax, 32(%r11)
	movq	16(%r8), %rax
	mulq	24(%r9)
	addq	%rax, %rcx
	adcq	%rdx, %rsi
	adcq	$0, %r10
	movq	24(%r8), %rax
	mulq	16(%r9)
	addq	%rax, %rcx
	adcq	%rdx, %rsi
	adcq	$0, %r10
	xorq	%rbx, %rbx
	movq	%rcx, 40(%r11)
	movq	24(%r8), %rax
	mulq	24(%r9)
	addq	%rax, %rsi
	adcq	%rdx, %r10
	adcq	$0, %rbx
	xorq	%rax, %rax
	movq	%rsi, 48(%r11)
	movq	%r10, 56(%r11)
	movq	(%r11), %rax
	movq	%rax, (%rdi)
	movq	8(%r11), %rax
	movq	%rax, 8(%rdi)
	movq	16(%r11), %rax
	movq	%rax, 16(%rdi)
	movq	24(%r11), %rax
	movq	%rax, 24(%rdi)
	movq	32(%r11), %rax
	movq	%rax, 32(%rdi)
	movq	40(%r11), %rax
	movq	%rax, 40(%rdi)
	movq	48(%r11), %rax
	movq	%rax, 48(%rdi)
	movq	56(%r11), %rax
	movq	%rax, 56(%rdi)
	movq	128(%rsp), %rbx
	movq	136(%rsp), %rsp
	ret 
_bn_subn:
bn_subn:
	movq	%rsp, %r10
	leaq	-64(%rsp), %rsp
	andq	$-8, %rsp
	movq	(%rsi), %rax
	movq	%rax, (%rsp)
	movq	8(%rsi), %rax
	movq	%rax, 8(%rsp)
	movq	16(%rsi), %rax
	movq	%rax, 16(%rsp)
	movq	24(%rsi), %rax
	movq	%rax, 24(%rsp)
	movq	%rsp, %rax
	movq	(%rdx), %rcx
	movq	%rcx, 32(%rsp)
	movq	8(%rdx), %rcx
	movq	%rcx, 40(%rsp)
	movq	16(%rdx), %rcx
	movq	%rcx, 48(%rsp)
	movq	24(%rdx), %rcx
	movq	%rcx, 56(%rsp)
	leaq	32(%rsp), %rcx
	movq	(%rcx), %rdx
	subq	%rdx, (%rax)
	movq	8(%rcx), %rdx
	sbbq	%rdx, 8(%rax)
	movq	16(%rcx), %rdx
	sbbq	%rdx, 16(%rax)
	movq	24(%rcx), %rcx
	sbbq	%rcx, 24(%rax)
	movq	(%rax), %rcx
	movq	%rcx, (%rdi)
	movq	8(%rax), %rcx
	movq	%rcx, 8(%rdi)
	movq	16(%rax), %rcx
	movq	%rcx, 16(%rdi)
	movq	24(%rax), %rax
	movq	%rax, 24(%rdi)
	movq	%r10, %rsp
	ret 
_bn_addn:
bn_addn:
	movq	%rsp, %r10
	leaq	-64(%rsp), %rsp
	andq	$-8, %rsp
	movq	(%rsi), %rax
	movq	%rax, (%rsp)
	movq	8(%rsi), %rax
	movq	%rax, 8(%rsp)
	movq	16(%rsi), %rax
	movq	%rax, 16(%rsp)
	movq	24(%rsi), %rax
	movq	%rax, 24(%rsp)
	movq	%rsp, %rax
	movq	(%rdx), %rcx
	movq	%rcx, 32(%rsp)
	movq	8(%rdx), %rcx
	movq	%rcx, 40(%rsp)
	movq	16(%rdx), %rcx
	movq	%rcx, 48(%rsp)
	movq	24(%rdx), %rcx
	movq	%rcx, 56(%rsp)
	leaq	32(%rsp), %rcx
	movq	(%rcx), %rdx
	addq	%rdx, (%rax)
	movq	8(%rcx), %rdx
	adcq	%rdx, 8(%rax)
	movq	16(%rcx), %rdx
	adcq	%rdx, 16(%rax)
	movq	24(%rcx), %rcx
	adcq	%rcx, 24(%rax)
	movq	(%rax), %rcx
	movq	%rcx, (%rdi)
	movq	8(%rax), %rcx
	movq	%rcx, 8(%rdi)
	movq	16(%rax), %rcx
	movq	%rcx, 16(%rdi)
	movq	24(%rax), %rax
	movq	%rax, 24(%rdi)
	movq	%r10, %rsp
	ret 
_bn_set0:
bn_set0:
	movq	$0, (%rdi)
	movq	$0, 8(%rdi)
	movq	$0, 16(%rdi)
	movq	$0, 24(%rdi)
	ret 
_bn_copy:
bn_copy:
	movq	(%rsi), %rax
	movq	%rax, (%rdi)
	movq	8(%rsi), %rax
	movq	%rax, 8(%rdi)
	movq	16(%rsi), %rax
	movq	%rax, 16(%rdi)
	movq	24(%rsi), %rax
	movq	%rax, 24(%rdi)
	ret 
_bn_test0:
bn_test0:
	movq	%rsp, %r10
	leaq	-32(%rsp), %rsp
	andq	$-8, %rsp
	movq	(%rdi), %rax
	movq	%rax, (%rsp)
	movq	8(%rdi), %rax
	movq	%rax, 8(%rsp)
	movq	16(%rdi), %rax
	movq	%rax, 16(%rsp)
	movq	24(%rdi), %rax
	movq	%rax, 24(%rsp)
	movq	%rsp, %rax
	movq	$0, %rcx
	movq	$1, %rdx
	movq	(%rax), %rsi
	orq 	8(%rax), %rsi
	orq 	16(%rax), %rsi
	orq 	24(%rax), %rsi
	andq	%rsi, %rsi
	cmove	%rdx, %rcx
	movq	%rcx, %rax
	movq	%r10, %rsp
	ret 
_bn_eq:
bn_eq:
	movq	%rsp, %r11
	leaq	-64(%rsp), %rsp
	andq	$-8, %rsp
	movq	(%rdi), %rax
	movq	%rax, (%rsp)
	movq	8(%rdi), %rax
	movq	%rax, 8(%rsp)
	movq	16(%rdi), %rax
	movq	%rax, 16(%rsp)
	movq	24(%rdi), %rax
	movq	%rax, 24(%rsp)
	movq	%rsp, %rax
	movq	(%rsi), %rcx
	movq	%rcx, 32(%rsp)
	movq	8(%rsi), %rcx
	movq	%rcx, 40(%rsp)
	movq	16(%rsi), %rcx
	movq	%rcx, 48(%rsp)
	movq	24(%rsi), %rcx
	movq	%rcx, 56(%rsp)
	leaq	32(%rsp), %rcx
	leaq	Lbn_eq$1(%rip), %r9
	jmp 	L_bn_eq$1
Lbn_eq$1:
	movq	%rdx, %rax
	movq	%r11, %rsp
	ret 
L_fp_toM$1:
	leaq	glob_data + 0(%rip), %r9
	leaq	-96(%rsp), %rsp
	leaq	L_fp_toM$2(%rip), %rbp
	jmp 	L_fp_mulU$1
L_fp_toM$2:
	leaq	96(%rsp), %rsp
	jmp 	*%r14
L_fp_fromM$1:
	movq	%rax, %rsi
	movq	$0, 64(%rsp)
	movq	$0, 72(%rsp)
	movq	$0, 80(%rsp)
	movq	$0, 88(%rsp)
	movq	(%rsi), %rax
	movq	%rax, 32(%rsp)
	movq	8(%rsi), %rax
	movq	%rax, 40(%rsp)
	movq	16(%rsi), %rax
	movq	%rax, 48(%rsp)
	movq	24(%rsi), %rax
	movq	%rax, 56(%rsp)
	leaq	32(%rsp), %r10
	xorq	%r12, %r12
	movq	glob_data + 64(%rip), %r11
	movq	glob_data + 136(%rip), %rbp
	xorq	%r13, %r13
	xorq	%rcx, %rcx
	xorq	%r8, %r8
	movq	(%r10), %rax
	addq	%rax, %r13
	adcq	%r12, %rcx
	adcq	$0, %r8
	movq	%r13, %rax
	mulq	%r11
	movq	%rax, (%rsi)
	mulq	%rbp
	addq	%rax, %r13
	adcq	%rdx, %rcx
	adcq	$0, %r8
	leaq	glob_data + 136(%rip), %rdx
	movq	(%rsi), %rax
	mulq	8(%rdx)
	addq	%rax, %rcx
	adcq	%rdx, %r8
	adcq	$0, %r13
	movq	8(%r10), %rax
	addq	%rax, %rcx
	adcq	%r12, %r8
	adcq	$0, %r13
	movq	%rcx, %rax
	mulq	%r11
	movq	%rax, 8(%rsi)
	mulq	%rbp
	addq	%rax, %rcx
	adcq	%rdx, %r8
	adcq	$0, %r13
	leaq	glob_data + 136(%rip), %rbx
	movq	(%rsi), %rax
	mulq	16(%rbx)
	addq	%rax, %r8
	adcq	%rdx, %r13
	adcq	$0, %rcx
	movq	8(%rsi), %rax
	mulq	8(%rbx)
	addq	%rax, %r8
	adcq	%rdx, %r13
	adcq	$0, %rcx
	movq	16(%r10), %rax
	addq	%rax, %r8
	adcq	%r12, %r13
	adcq	$0, %rcx
	movq	%r8, %rax
	mulq	%r11
	movq	%rax, 16(%rsi)
	mulq	%rbp
	addq	%rax, %r8
	adcq	%rdx, %r13
	adcq	$0, %rcx
	leaq	glob_data + 136(%rip), %rbx
	movq	(%rsi), %rax
	mulq	24(%rbx)
	addq	%rax, %r13
	adcq	%rdx, %rcx
	adcq	$0, %r8
	movq	8(%rsi), %rax
	mulq	16(%rbx)
	addq	%rax, %r13
	adcq	%rdx, %rcx
	adcq	$0, %r8
	movq	16(%rsi), %rax
	mulq	8(%rbx)
	addq	%rax, %r13
	adcq	%rdx, %rcx
	adcq	$0, %r8
	movq	24(%r10), %rax
	addq	%rax, %r13
	adcq	%r12, %rcx
	adcq	$0, %r8
	movq	%r13, %rax
	mulq	%r11
	movq	%rax, 24(%rsi)
	mulq	%rbp
	addq	%rax, %r13
	adcq	%rdx, %rcx
	adcq	$0, %r8
	leaq	glob_data + 136(%rip), %r11
	movq	8(%rsi), %rax
	mulq	24(%r11)
	addq	%rax, %rcx
	adcq	%rdx, %r8
	adcq	$0, %r13
	movq	16(%rsi), %rax
	mulq	16(%r11)
	addq	%rax, %rcx
	adcq	%rdx, %r8
	adcq	$0, %r13
	movq	24(%rsi), %rax
	mulq	8(%r11)
	addq	%rax, %rcx
	adcq	%rdx, %r8
	adcq	$0, %r13
	movq	32(%r10), %rax
	addq	%rax, %rcx
	adcq	%r12, %r8
	adcq	$0, %r13
	movq	%rcx, (%rsi)
	xorq	%rcx, %rcx
	leaq	glob_data + 136(%rip), %r11
	movq	16(%rsi), %rax
	mulq	24(%r11)
	addq	%rax, %r8
	adcq	%rdx, %r13
	adcq	$0, %rcx
	movq	24(%rsi), %rax
	mulq	16(%r11)
	addq	%rax, %r8
	adcq	%rdx, %r13
	adcq	$0, %rcx
	movq	40(%r10), %rax
	addq	%rax, %r8
	adcq	%r12, %r13
	adcq	$0, %rcx
	movq	%r8, 8(%rsi)
	xorq	%r8, %r8
	leaq	glob_data + 136(%rip), %rdx
	movq	24(%rsi), %rax
	mulq	24(%rdx)
	addq	%rax, %r13
	adcq	%rdx, %rcx
	adcq	$0, %r8
	movq	48(%r10), %rax
	addq	%rax, %r13
	adcq	%r12, %rcx
	adcq	$0, %r8
	movq	%r13, 16(%rsi)
	xorq	%rax, %rax
	addq	56(%r10), %rcx
	movq	%rcx, 24(%rsi)
	movq	(%rsi), %rax
	movq	%rax, (%rsp)
	movq	8(%rsi), %rax
	movq	%rax, 8(%rsp)
	movq	16(%rsi), %rax
	movq	%rax, 16(%rsp)
	movq	24(%rsi), %rax
	movq	%rax, 24(%rsp)
	movq	%rsp, %rax
	leaq	glob_data + 104(%rip), %rcx
	movq	(%rcx), %rdx
	addq	%rdx, (%rax)
	movq	8(%rcx), %rdx
	adcq	%rdx, 8(%rax)
	movq	16(%rcx), %rdx
	adcq	%rdx, 16(%rax)
	movq	24(%rcx), %rcx
	adcq	%rcx, 24(%rax)
	movq	(%rsi), %rcx
	cmovb	(%rax), %rcx
	movq	%rcx, (%rsi)
	movq	8(%rsi), %rcx
	cmovb	8(%rax), %rcx
	movq	%rcx, 8(%rsi)
	movq	16(%rsi), %rcx
	cmovb	16(%rax), %rcx
	movq	%rcx, 16(%rsi)
	movq	24(%rsi), %rcx
	cmovb	24(%rax), %rcx
	movq	%rcx, 24(%rsi)
	jmp 	*%r9
L_fp_exp$1:
	leaq	24(%rsp), %rsi
	leaq	glob_data + 32(%rip), %rdi
	movq	(%rax), %r8
	movq	%r8, (%rsi)
	movq	8(%rax), %r8
	movq	%r8, 8(%rsi)
	movq	16(%rax), %r8
	movq	%r8, 16(%rsi)
	movq	24(%rax), %rax
	movq	%rax, 24(%rsi)
	movq	(%rdi), %rax
	movq	%rax, (%rdx)
	movq	8(%rdi), %rax
	movq	%rax, 8(%rdx)
	movq	16(%rdi), %rax
	movq	%rax, 16(%rdx)
	movq	24(%rdi), %rax
	movq	%rax, 24(%rdx)
	movq	%rcx, (%rsp)
	movq	%rdx, 8(%rsp)
	movq	(%rsp), %rax
	movq	(%rax), %r14
	movq	$64, %rax
	jmp 	L_fp_exp$17
L_fp_exp$18:
	movq	%rax, 16(%rsp)
	shrq	$1, %r14
	jnb 	L_fp_exp$20
	movq	8(%rsp), %rax
	leaq	24(%rsp), %r9
	leaq	-96(%rsp), %rsp
	leaq	L_fp_exp$21(%rip), %rbp
	jmp 	L_fp_mulU$1
L_fp_exp$21:
	leaq	96(%rsp), %rsp
L_fp_exp$20:
	leaq	24(%rsp), %rax
	leaq	-104(%rsp), %rsp
	leaq	L_fp_exp$19(%rip), %rcx
	movq	%rcx, 96(%rsp)
	jmp 	L_fp_sqrU$1
L_fp_exp$19:
	leaq	104(%rsp), %rsp
	movq	16(%rsp), %rax
	addq	$-1, %rax
L_fp_exp$17:
	cmpq	$0, %rax
	jne 	L_fp_exp$18
	movq	(%rsp), %rax
	movq	8(%rax), %r14
	movq	$64, %rax
	jmp 	L_fp_exp$12
L_fp_exp$13:
	movq	%rax, 16(%rsp)
	shrq	$1, %r14
	jnb 	L_fp_exp$15
	movq	8(%rsp), %rax
	leaq	24(%rsp), %r9
	leaq	-96(%rsp), %rsp
	leaq	L_fp_exp$16(%rip), %rbp
	jmp 	L_fp_mulU$1
L_fp_exp$16:
	leaq	96(%rsp), %rsp
L_fp_exp$15:
	leaq	24(%rsp), %rax
	leaq	-104(%rsp), %rsp
	leaq	L_fp_exp$14(%rip), %rcx
	movq	%rcx, 96(%rsp)
	jmp 	L_fp_sqrU$1
L_fp_exp$14:
	leaq	104(%rsp), %rsp
	movq	16(%rsp), %rax
	addq	$-1, %rax
L_fp_exp$12:
	cmpq	$0, %rax
	jne 	L_fp_exp$13
	movq	(%rsp), %rax
	movq	16(%rax), %r14
	movq	$64, %rax
	jmp 	L_fp_exp$7
L_fp_exp$8:
	movq	%rax, 16(%rsp)
	shrq	$1, %r14
	jnb 	L_fp_exp$10
	movq	8(%rsp), %rax
	leaq	24(%rsp), %r9
	leaq	-96(%rsp), %rsp
	leaq	L_fp_exp$11(%rip), %rbp
	jmp 	L_fp_mulU$1
L_fp_exp$11:
	leaq	96(%rsp), %rsp
L_fp_exp$10:
	leaq	24(%rsp), %rax
	leaq	-104(%rsp), %rsp
	leaq	L_fp_exp$9(%rip), %rcx
	movq	%rcx, 96(%rsp)
	jmp 	L_fp_sqrU$1
L_fp_exp$9:
	leaq	104(%rsp), %rsp
	movq	16(%rsp), %rax
	addq	$-1, %rax
L_fp_exp$7:
	cmpq	$0, %rax
	jne 	L_fp_exp$8
	movq	(%rsp), %rax
	movq	24(%rax), %r14
	movq	$64, %rax
	jmp 	L_fp_exp$2
L_fp_exp$3:
	movq	%rax, (%rsp)
	shrq	$1, %r14
	jnb 	L_fp_exp$5
	movq	8(%rsp), %rax
	leaq	24(%rsp), %r9
	leaq	-96(%rsp), %rsp
	leaq	L_fp_exp$6(%rip), %rbp
	jmp 	L_fp_mulU$1
L_fp_exp$6:
	leaq	96(%rsp), %rsp
L_fp_exp$5:
	leaq	24(%rsp), %rax
	leaq	-104(%rsp), %rsp
	leaq	L_fp_exp$4(%rip), %rcx
	movq	%rcx, 96(%rsp)
	jmp 	L_fp_sqrU$1
L_fp_exp$4:
	leaq	104(%rsp), %rsp
	movq	(%rsp), %rax
	addq	$-1, %rax
L_fp_exp$2:
	cmpq	$0, %rax
	jne 	L_fp_exp$3
	movq	8(%rsp), %rdx
	jmp 	*56(%rsp)
L_fp_sqrU$1:
	movq	%rax, %r11
	leaq	32(%rsp), %rbp
	movq	(%r11), %rax
	mulq	%rax
	movq	%rax, (%rbp)
	movq	%rdx, %rsi
	xorq	%rdi, %rdi
	xorq	%rcx, %rcx
	movq	(%r11), %rax
	movq	8(%r11), %rdx
	mulq	%rdx
	movq	%rax, %r8
	shlq	$1, %rax
	shldq	$1, %r8, %rdx
	movq	$0, %r8
	adcq	%r8, %r8
	addq	%rax, %rsi
	adcq	%rdx, %rdi
	adcq	%r8, %rcx
	movq	%rsi, %rax
	xorq	%rsi, %rsi
	movq	%rax, 8(%rbp)
	movq	(%r11), %rax
	movq	16(%r11), %rdx
	mulq	%rdx
	movq	%rax, %r8
	shlq	$1, %rax
	shldq	$1, %r8, %rdx
	movq	$0, %r8
	adcq	%r8, %r8
	addq	%rax, %rdi
	adcq	%rdx, %rcx
	adcq	%r8, %rsi
	movq	8(%r11), %rax
	mulq	%rax
	addq	%rax, %rdi
	adcq	%rdx, %rcx
	adcq	$0, %rsi
	movq	%rdi, %rax
	xorq	%rdi, %rdi
	movq	%rax, 16(%rbp)
	movq	(%r11), %rax
	movq	24(%r11), %rdx
	mulq	%rdx
	movq	%rax, %r8
	shlq	$1, %rax
	shldq	$1, %r8, %rdx
	movq	$0, %r8
	adcq	%r8, %r8
	addq	%rax, %rcx
	adcq	%rdx, %rsi
	adcq	%r8, %rdi
	movq	8(%r11), %rax
	movq	16(%r11), %rdx
	mulq	%rdx
	movq	%rax, %r8
	shlq	$1, %rax
	shldq	$1, %r8, %rdx
	movq	$0, %r8
	adcq	%r8, %r8
	addq	%rax, %rcx
	adcq	%rdx, %rsi
	adcq	%r8, %rdi
	movq	%rcx, %rax
	xorq	%rcx, %rcx
	movq	%rax, 24(%rbp)
	movq	8(%r11), %rax
	movq	24(%r11), %rdx
	mulq	%rdx
	movq	%rax, %r8
	shlq	$1, %rax
	shldq	$1, %r8, %rdx
	movq	$0, %r8
	adcq	%r8, %r8
	addq	%rax, %rsi
	adcq	%rdx, %rdi
	adcq	%r8, %rcx
	movq	16(%r11), %rax
	mulq	%rax
	addq	%rax, %rsi
	adcq	%rdx, %rdi
	adcq	$0, %rcx
	movq	%rsi, %rax
	xorq	%rsi, %rsi
	movq	%rax, 32(%rbp)
	movq	16(%r11), %rax
	movq	24(%r11), %rdx
	mulq	%rdx
	movq	%rax, %r8
	shlq	$1, %rax
	shldq	$1, %r8, %rdx
	movq	$0, %r8
	adcq	%r8, %r8
	addq	%rax, %rdi
	adcq	%rdx, %rcx
	adcq	%r8, %rsi
	xorq	%r8, %r8
	movq	%rdi, 40(%rbp)
	movq	24(%r11), %rax
	mulq	%rax
	addq	%rax, %rcx
	adcq	%rdx, %rsi
	adcq	$0, %r8
	xorq	%rax, %rax
	movq	%rcx, 48(%rbp)
	movq	%rsi, 56(%rbp)
	xorq	%r10, %r10
	movq	glob_data + 64(%rip), %rdi
	movq	glob_data + 136(%rip), %r8
	xorq	%r9, %r9
	xorq	%rsi, %rsi
	xorq	%rcx, %rcx
	movq	(%rbp), %rax
	addq	%rax, %r9
	adcq	%r10, %rsi
	adcq	$0, %rcx
	movq	%r9, %rax
	mulq	%rdi
	movq	%rax, (%r11)
	mulq	%r8
	addq	%rax, %r9
	adcq	%rdx, %rsi
	adcq	$0, %rcx
	leaq	glob_data + 136(%rip), %rdx
	movq	(%r11), %rax
	mulq	8(%rdx)
	addq	%rax, %rsi
	adcq	%rdx, %rcx
	adcq	$0, %r9
	movq	8(%rbp), %rax
	addq	%rax, %rsi
	adcq	%r10, %rcx
	adcq	$0, %r9
	movq	%rsi, %rax
	mulq	%rdi
	movq	%rax, 8(%r11)
	mulq	%r8
	addq	%rax, %rsi
	adcq	%rdx, %rcx
	adcq	$0, %r9
	leaq	glob_data + 136(%rip), %rbx
	movq	(%r11), %rax
	mulq	16(%rbx)
	addq	%rax, %rcx
	adcq	%rdx, %r9
	adcq	$0, %rsi
	movq	8(%r11), %rax
	mulq	8(%rbx)
	addq	%rax, %rcx
	adcq	%rdx, %r9
	adcq	$0, %rsi
	movq	16(%rbp), %rax
	addq	%rax, %rcx
	adcq	%r10, %r9
	adcq	$0, %rsi
	movq	%rcx, %rax
	mulq	%rdi
	movq	%rax, 16(%r11)
	mulq	%r8
	addq	%rax, %rcx
	adcq	%rdx, %r9
	adcq	$0, %rsi
	leaq	glob_data + 136(%rip), %rbx
	movq	(%r11), %rax
	mulq	24(%rbx)
	addq	%rax, %r9
	adcq	%rdx, %rsi
	adcq	$0, %rcx
	movq	8(%r11), %rax
	mulq	16(%rbx)
	addq	%rax, %r9
	adcq	%rdx, %rsi
	adcq	$0, %rcx
	movq	16(%r11), %rax
	mulq	8(%rbx)
	addq	%rax, %r9
	adcq	%rdx, %rsi
	adcq	$0, %rcx
	movq	24(%rbp), %rax
	addq	%rax, %r9
	adcq	%r10, %rsi
	adcq	$0, %rcx
	movq	%r9, %rax
	mulq	%rdi
	movq	%rax, 24(%r11)
	mulq	%r8
	addq	%rax, %r9
	adcq	%rdx, %rsi
	adcq	$0, %rcx
	leaq	glob_data + 136(%rip), %rdi
	movq	8(%r11), %rax
	mulq	24(%rdi)
	addq	%rax, %rsi
	adcq	%rdx, %rcx
	adcq	$0, %r9
	movq	16(%r11), %rax
	mulq	16(%rdi)
	addq	%rax, %rsi
	adcq	%rdx, %rcx
	adcq	$0, %r9
	movq	24(%r11), %rax
	mulq	8(%rdi)
	addq	%rax, %rsi
	adcq	%rdx, %rcx
	adcq	$0, %r9
	movq	32(%rbp), %rax
	addq	%rax, %rsi
	adcq	%r10, %rcx
	adcq	$0, %r9
	movq	%rsi, (%r11)
	xorq	%rsi, %rsi
	leaq	glob_data + 136(%rip), %rdi
	movq	16(%r11), %rax
	mulq	24(%rdi)
	addq	%rax, %rcx
	adcq	%rdx, %r9
	adcq	$0, %rsi
	movq	24(%r11), %rax
	mulq	16(%rdi)
	addq	%rax, %rcx
	adcq	%rdx, %r9
	adcq	$0, %rsi
	movq	40(%rbp), %rax
	addq	%rax, %rcx
	adcq	%r10, %r9
	adcq	$0, %rsi
	movq	%rcx, 8(%r11)
	xorq	%rcx, %rcx
	leaq	glob_data + 136(%rip), %rdx
	movq	24(%r11), %rax
	mulq	24(%rdx)
	addq	%rax, %r9
	adcq	%rdx, %rsi
	adcq	$0, %rcx
	movq	48(%rbp), %rax
	addq	%rax, %r9
	adcq	%r10, %rsi
	adcq	$0, %rcx
	movq	%r9, 16(%r11)
	xorq	%rax, %rax
	addq	56(%rbp), %rsi
	movq	%rsi, 24(%r11)
	movq	(%r11), %rax
	movq	%rax, (%rsp)
	movq	8(%r11), %rax
	movq	%rax, 8(%rsp)
	movq	16(%r11), %rax
	movq	%rax, 16(%rsp)
	movq	24(%r11), %rax
	movq	%rax, 24(%rsp)
	movq	%rsp, %rax
	leaq	glob_data + 104(%rip), %rcx
	movq	(%rcx), %rdx
	addq	%rdx, (%rax)
	movq	8(%rcx), %rdx
	adcq	%rdx, 8(%rax)
	movq	16(%rcx), %rdx
	adcq	%rdx, 16(%rax)
	movq	24(%rcx), %rcx
	adcq	%rcx, 24(%rax)
	movq	(%r11), %rcx
	cmovb	(%rax), %rcx
	movq	%rcx, (%r11)
	movq	8(%r11), %rcx
	cmovb	8(%rax), %rcx
	movq	%rcx, 8(%r11)
	movq	16(%r11), %rcx
	cmovb	16(%rax), %rcx
	movq	%rcx, 16(%r11)
	movq	24(%r11), %rcx
	cmovb	24(%rax), %rcx
	movq	%rcx, 24(%r11)
	jmp 	*96(%rsp)
L_fp_sqr$1:
	movq	%rax, %r12
	leaq	32(%rsp), %r13
	movq	(%r8), %rax
	mulq	%rax
	movq	%rax, (%r13)
	movq	%rdx, %r9
	xorq	%rcx, %rcx
	xorq	%rsi, %rsi
	movq	(%r8), %rax
	movq	8(%r8), %rdx
	mulq	%rdx
	movq	%rax, %r10
	shlq	$1, %rax
	shldq	$1, %r10, %rdx
	movq	$0, %r10
	adcq	%r10, %r10
	addq	%rax, %r9
	adcq	%rdx, %rcx
	adcq	%r10, %rsi
	movq	%r9, %rax
	xorq	%r9, %r9
	movq	%rax, 8(%r13)
	movq	(%r8), %rax
	movq	16(%r8), %rdx
	mulq	%rdx
	movq	%rax, %r10
	shlq	$1, %rax
	shldq	$1, %r10, %rdx
	movq	$0, %r10
	adcq	%r10, %r10
	addq	%rax, %rcx
	adcq	%rdx, %rsi
	adcq	%r10, %r9
	movq	8(%r8), %rax
	mulq	%rax
	addq	%rax, %rcx
	adcq	%rdx, %rsi
	adcq	$0, %r9
	movq	%rcx, %rax
	xorq	%rcx, %rcx
	movq	%rax, 16(%r13)
	movq	(%r8), %rax
	movq	24(%r8), %rdx
	mulq	%rdx
	movq	%rax, %r10
	shlq	$1, %rax
	shldq	$1, %r10, %rdx
	movq	$0, %r10
	adcq	%r10, %r10
	addq	%rax, %rsi
	adcq	%rdx, %r9
	adcq	%r10, %rcx
	movq	8(%r8), %rax
	movq	16(%r8), %rdx
	mulq	%rdx
	movq	%rax, %r10
	shlq	$1, %rax
	shldq	$1, %r10, %rdx
	movq	$0, %r10
	adcq	%r10, %r10
	addq	%rax, %rsi
	adcq	%rdx, %r9
	adcq	%r10, %rcx
	movq	%rsi, %rax
	xorq	%rsi, %rsi
	movq	%rax, 24(%r13)
	movq	8(%r8), %rax
	movq	24(%r8), %rdx
	mulq	%rdx
	movq	%rax, %r10
	shlq	$1, %rax
	shldq	$1, %r10, %rdx
	movq	$0, %r10
	adcq	%r10, %r10
	addq	%rax, %r9
	adcq	%rdx, %rcx
	adcq	%r10, %rsi
	movq	16(%r8), %rax
	mulq	%rax
	addq	%rax, %r9
	adcq	%rdx, %rcx
	adcq	$0, %rsi
	movq	%r9, %rax
	xorq	%r9, %r9
	movq	%rax, 32(%r13)
	movq	16(%r8), %rax
	movq	24(%r8), %rdx
	mulq	%rdx
	movq	%rax, %r10
	shlq	$1, %rax
	shldq	$1, %r10, %rdx
	movq	$0, %r10
	adcq	%r10, %r10
	addq	%rax, %rcx
	adcq	%rdx, %rsi
	adcq	%r10, %r9
	xorq	%r10, %r10
	movq	%rcx, 40(%r13)
	movq	24(%r8), %rax
	mulq	%rax
	addq	%rax, %rsi
	adcq	%rdx, %r9
	adcq	$0, %r10
	xorq	%rax, %rax
	movq	%rsi, 48(%r13)
	movq	%r9, 56(%r13)
	xorq	%r8, %r8
	movq	glob_data + 64(%rip), %rcx
	movq	glob_data + 136(%rip), %r11
	xorq	%r9, %r9
	xorq	%rsi, %rsi
	xorq	%r10, %r10
	movq	(%r13), %rax
	addq	%rax, %r9
	adcq	%r8, %rsi
	adcq	$0, %r10
	movq	%r9, %rax
	mulq	%rcx
	movq	%rax, (%r12)
	mulq	%r11
	addq	%rax, %r9
	adcq	%rdx, %rsi
	adcq	$0, %r10
	leaq	glob_data + 136(%rip), %rdx
	movq	(%r12), %rax
	mulq	8(%rdx)
	addq	%rax, %rsi
	adcq	%rdx, %r10
	adcq	$0, %r9
	movq	8(%r13), %rax
	addq	%rax, %rsi
	adcq	%r8, %r10
	adcq	$0, %r9
	movq	%rsi, %rax
	mulq	%rcx
	movq	%rax, 8(%r12)
	mulq	%r11
	addq	%rax, %rsi
	adcq	%rdx, %r10
	adcq	$0, %r9
	leaq	glob_data + 136(%rip), %rbx
	movq	(%r12), %rax
	mulq	16(%rbx)
	addq	%rax, %r10
	adcq	%rdx, %r9
	adcq	$0, %rsi
	movq	8(%r12), %rax
	mulq	8(%rbx)
	addq	%rax, %r10
	adcq	%rdx, %r9
	adcq	$0, %rsi
	movq	16(%r13), %rax
	addq	%rax, %r10
	adcq	%r8, %r9
	adcq	$0, %rsi
	movq	%r10, %rax
	mulq	%rcx
	movq	%rax, 16(%r12)
	mulq	%r11
	addq	%rax, %r10
	adcq	%rdx, %r9
	adcq	$0, %rsi
	leaq	glob_data + 136(%rip), %rbx
	movq	(%r12), %rax
	mulq	24(%rbx)
	addq	%rax, %r9
	adcq	%rdx, %rsi
	adcq	$0, %r10
	movq	8(%r12), %rax
	mulq	16(%rbx)
	addq	%rax, %r9
	adcq	%rdx, %rsi
	adcq	$0, %r10
	movq	16(%r12), %rax
	mulq	8(%rbx)
	addq	%rax, %r9
	adcq	%rdx, %rsi
	adcq	$0, %r10
	movq	24(%r13), %rax
	addq	%rax, %r9
	adcq	%r8, %rsi
	adcq	$0, %r10
	movq	%r9, %rax
	mulq	%rcx
	movq	%rax, 24(%r12)
	mulq	%r11
	addq	%rax, %r9
	adcq	%rdx, %rsi
	adcq	$0, %r10
	leaq	glob_data + 136(%rip), %rcx
	movq	8(%r12), %rax
	mulq	24(%rcx)
	addq	%rax, %rsi
	adcq	%rdx, %r10
	adcq	$0, %r9
	movq	16(%r12), %rax
	mulq	16(%rcx)
	addq	%rax, %rsi
	adcq	%rdx, %r10
	adcq	$0, %r9
	movq	24(%r12), %rax
	mulq	8(%rcx)
	addq	%rax, %rsi
	adcq	%rdx, %r10
	adcq	$0, %r9
	movq	32(%r13), %rax
	addq	%rax, %rsi
	adcq	%r8, %r10
	adcq	$0, %r9
	movq	%rsi, (%r12)
	xorq	%rcx, %rcx
	leaq	glob_data + 136(%rip), %rsi
	movq	16(%r12), %rax
	mulq	24(%rsi)
	addq	%rax, %r10
	adcq	%rdx, %r9
	adcq	$0, %rcx
	movq	24(%r12), %rax
	mulq	16(%rsi)
	addq	%rax, %r10
	adcq	%rdx, %r9
	adcq	$0, %rcx
	movq	40(%r13), %rax
	addq	%rax, %r10
	adcq	%r8, %r9
	adcq	$0, %rcx
	movq	%r10, 8(%r12)
	xorq	%rsi, %rsi
	leaq	glob_data + 136(%rip), %rdx
	movq	24(%r12), %rax
	mulq	24(%rdx)
	addq	%rax, %r9
	adcq	%rdx, %rcx
	adcq	$0, %rsi
	movq	48(%r13), %rax
	addq	%rax, %r9
	adcq	%r8, %rcx
	adcq	$0, %rsi
	movq	%r9, 16(%r12)
	xorq	%rax, %rax
	addq	56(%r13), %rcx
	movq	%rcx, 24(%r12)
	movq	(%r12), %rax
	movq	%rax, (%rsp)
	movq	8(%r12), %rax
	movq	%rax, 8(%rsp)
	movq	16(%r12), %rax
	movq	%rax, 16(%rsp)
	movq	24(%r12), %rax
	movq	%rax, 24(%rsp)
	movq	%rsp, %rax
	leaq	glob_data + 104(%rip), %rcx
	movq	(%rcx), %rdx
	addq	%rdx, (%rax)
	movq	8(%rcx), %rdx
	adcq	%rdx, 8(%rax)
	movq	16(%rcx), %rdx
	adcq	%rdx, 16(%rax)
	movq	24(%rcx), %rcx
	adcq	%rcx, 24(%rax)
	movq	(%r12), %rcx
	cmovb	(%rax), %rcx
	movq	%rcx, (%r12)
	movq	8(%r12), %rcx
	cmovb	8(%rax), %rcx
	movq	%rcx, 8(%r12)
	movq	16(%r12), %rcx
	cmovb	16(%rax), %rcx
	movq	%rcx, 16(%r12)
	movq	24(%r12), %rcx
	cmovb	24(%rax), %rcx
	movq	%rcx, 24(%r12)
	jmp 	*%rbp
L_fp_mulU$1:
	movq	%rax, %r13
	leaq	32(%rsp), %r12
	movq	(%r13), %rax
	mulq	(%r9)
	movq	%rax, (%r12)
	movq	%rdx, %r8
	xorq	%rsi, %rsi
	xorq	%rcx, %rcx
	movq	(%r13), %rax
	mulq	8(%r9)
	addq	%rax, %r8
	adcq	%rdx, %rsi
	adcq	$0, %rcx
	movq	8(%r13), %rax
	mulq	(%r9)
	addq	%rax, %r8
	adcq	%rdx, %rsi
	adcq	$0, %rcx
	movq	%r8, %rax
	xorq	%r8, %r8
	movq	%rax, 8(%r12)
	movq	(%r13), %rax
	mulq	16(%r9)
	addq	%rax, %rsi
	adcq	%rdx, %rcx
	adcq	$0, %r8
	movq	8(%r13), %rax
	mulq	8(%r9)
	addq	%rax, %rsi
	adcq	%rdx, %rcx
	adcq	$0, %r8
	movq	16(%r13), %rax
	mulq	(%r9)
	addq	%rax, %rsi
	adcq	%rdx, %rcx
	adcq	$0, %r8
	movq	%rsi, %rax
	xorq	%rsi, %rsi
	movq	%rax, 16(%r12)
	movq	(%r13), %rax
	mulq	24(%r9)
	addq	%rax, %rcx
	adcq	%rdx, %r8
	adcq	$0, %rsi
	movq	8(%r13), %rax
	mulq	16(%r9)
	addq	%rax, %rcx
	adcq	%rdx, %r8
	adcq	$0, %rsi
	movq	16(%r13), %rax
	mulq	8(%r9)
	addq	%rax, %rcx
	adcq	%rdx, %r8
	adcq	$0, %rsi
	movq	24(%r13), %rax
	mulq	(%r9)
	addq	%rax, %rcx
	adcq	%rdx, %r8
	adcq	$0, %rsi
	movq	%rcx, %rax
	xorq	%rcx, %rcx
	movq	%rax, 24(%r12)
	movq	8(%r13), %rax
	mulq	24(%r9)
	addq	%rax, %r8
	adcq	%rdx, %rsi
	adcq	$0, %rcx
	movq	16(%r13), %rax
	mulq	16(%r9)
	addq	%rax, %r8
	adcq	%rdx, %rsi
	adcq	$0, %rcx
	movq	24(%r13), %rax
	mulq	8(%r9)
	addq	%rax, %r8
	adcq	%rdx, %rsi
	adcq	$0, %rcx
	movq	%r8, %rax
	xorq	%r8, %r8
	movq	%rax, 32(%r12)
	movq	16(%r13), %rax
	mulq	24(%r9)
	addq	%rax, %rsi
	adcq	%rdx, %rcx
	adcq	$0, %r8
	movq	24(%r13), %rax
	mulq	16(%r9)
	addq	%rax, %rsi
	adcq	%rdx, %rcx
	adcq	$0, %r8
	movq	%rsi, %rax
	xorq	%rsi, %rsi
	movq	%rax, 40(%r12)
	movq	24(%r13), %rax
	mulq	24(%r9)
	addq	%rax, %rcx
	adcq	%rdx, %r8
	adcq	$0, %rsi
	xorq	%rax, %rax
	movq	%rcx, 48(%r12)
	movq	%r8, 56(%r12)
	xorq	%r10, %r10
	movq	glob_data + 64(%rip), %r8
	movq	glob_data + 136(%rip), %rcx
	xorq	%r9, %r9
	xorq	%r11, %r11
	xorq	%rsi, %rsi
	movq	(%r12), %rax
	addq	%rax, %r9
	adcq	%r10, %r11
	adcq	$0, %rsi
	movq	%r9, %rax
	mulq	%r8
	movq	%rax, (%r13)
	mulq	%rcx
	addq	%rax, %r9
	adcq	%rdx, %r11
	adcq	$0, %rsi
	leaq	glob_data + 136(%rip), %rdx
	movq	(%r13), %rax
	mulq	8(%rdx)
	addq	%rax, %r11
	adcq	%rdx, %rsi
	adcq	$0, %r9
	movq	8(%r12), %rax
	addq	%rax, %r11
	adcq	%r10, %rsi
	adcq	$0, %r9
	movq	%r11, %rax
	mulq	%r8
	movq	%rax, 8(%r13)
	mulq	%rcx
	addq	%rax, %r11
	adcq	%rdx, %rsi
	adcq	$0, %r9
	leaq	glob_data + 136(%rip), %rbx
	movq	(%r13), %rax
	mulq	16(%rbx)
	addq	%rax, %rsi
	adcq	%rdx, %r9
	adcq	$0, %r11
	movq	8(%r13), %rax
	mulq	8(%rbx)
	addq	%rax, %rsi
	adcq	%rdx, %r9
	adcq	$0, %r11
	movq	16(%r12), %rax
	addq	%rax, %rsi
	adcq	%r10, %r9
	adcq	$0, %r11
	movq	%rsi, %rax
	mulq	%r8
	movq	%rax, 16(%r13)
	mulq	%rcx
	addq	%rax, %rsi
	adcq	%rdx, %r9
	adcq	$0, %r11
	leaq	glob_data + 136(%rip), %rbx
	movq	(%r13), %rax
	mulq	24(%rbx)
	addq	%rax, %r9
	adcq	%rdx, %r11
	adcq	$0, %rsi
	movq	8(%r13), %rax
	mulq	16(%rbx)
	addq	%rax, %r9
	adcq	%rdx, %r11
	adcq	$0, %rsi
	movq	16(%r13), %rax
	mulq	8(%rbx)
	addq	%rax, %r9
	adcq	%rdx, %r11
	adcq	$0, %rsi
	movq	24(%r12), %rax
	addq	%rax, %r9
	adcq	%r10, %r11
	adcq	$0, %rsi
	movq	%r9, %rax
	mulq	%r8
	movq	%rax, 24(%r13)
	mulq	%rcx
	addq	%rax, %r9
	adcq	%rdx, %r11
	adcq	$0, %rsi
	leaq	glob_data + 136(%rip), %rcx
	movq	8(%r13), %rax
	mulq	24(%rcx)
	addq	%rax, %r11
	adcq	%rdx, %rsi
	adcq	$0, %r9
	movq	16(%r13), %rax
	mulq	16(%rcx)
	addq	%rax, %r11
	adcq	%rdx, %rsi
	adcq	$0, %r9
	movq	24(%r13), %rax
	mulq	8(%rcx)
	addq	%rax, %r11
	adcq	%rdx, %rsi
	adcq	$0, %r9
	movq	32(%r12), %rax
	addq	%rax, %r11
	adcq	%r10, %rsi
	adcq	$0, %r9
	movq	%r11, (%r13)
	xorq	%rcx, %rcx
	leaq	glob_data + 136(%rip), %r8
	movq	16(%r13), %rax
	mulq	24(%r8)
	addq	%rax, %rsi
	adcq	%rdx, %r9
	adcq	$0, %rcx
	movq	24(%r13), %rax
	mulq	16(%r8)
	addq	%rax, %rsi
	adcq	%rdx, %r9
	adcq	$0, %rcx
	movq	40(%r12), %rax
	addq	%rax, %rsi
	adcq	%r10, %r9
	adcq	$0, %rcx
	movq	%rsi, 8(%r13)
	xorq	%rsi, %rsi
	leaq	glob_data + 136(%rip), %rdx
	movq	24(%r13), %rax
	mulq	24(%rdx)
	addq	%rax, %r9
	adcq	%rdx, %rcx
	adcq	$0, %rsi
	movq	48(%r12), %rax
	addq	%rax, %r9
	adcq	%r10, %rcx
	adcq	$0, %rsi
	movq	%r9, 16(%r13)
	xorq	%rax, %rax
	addq	56(%r12), %rcx
	movq	%rcx, 24(%r13)
	movq	(%r13), %rax
	movq	%rax, (%rsp)
	movq	8(%r13), %rax
	movq	%rax, 8(%rsp)
	movq	16(%r13), %rax
	movq	%rax, 16(%rsp)
	movq	24(%r13), %rax
	movq	%rax, 24(%rsp)
	movq	%rsp, %rax
	leaq	glob_data + 104(%rip), %rcx
	movq	(%rcx), %rdx
	addq	%rdx, (%rax)
	movq	8(%rcx), %rdx
	adcq	%rdx, 8(%rax)
	movq	16(%rcx), %rdx
	adcq	%rdx, 16(%rax)
	movq	24(%rcx), %rcx
	adcq	%rcx, 24(%rax)
	movq	(%r13), %rcx
	cmovb	(%rax), %rcx
	movq	%rcx, (%r13)
	movq	8(%r13), %rcx
	cmovb	8(%rax), %rcx
	movq	%rcx, 8(%r13)
	movq	16(%r13), %rcx
	cmovb	16(%rax), %rcx
	movq	%rcx, 16(%r13)
	movq	24(%r13), %rcx
	cmovb	24(%rax), %rcx
	movq	%rcx, 24(%r13)
	jmp 	*%rbp
L_fp_mul$1:
	movq	%rax, %r12
	leaq	32(%rsp), %r13
	movq	(%r10), %rax
	mulq	(%r8)
	movq	%rax, (%r13)
	movq	%rdx, %r9
	xorq	%rsi, %rsi
	xorq	%rcx, %rcx
	movq	(%r10), %rax
	mulq	8(%r8)
	addq	%rax, %r9
	adcq	%rdx, %rsi
	adcq	$0, %rcx
	movq	8(%r10), %rax
	mulq	(%r8)
	addq	%rax, %r9
	adcq	%rdx, %rsi
	adcq	$0, %rcx
	movq	%r9, %rax
	xorq	%r9, %r9
	movq	%rax, 8(%r13)
	movq	(%r10), %rax
	mulq	16(%r8)
	addq	%rax, %rsi
	adcq	%rdx, %rcx
	adcq	$0, %r9
	movq	8(%r10), %rax
	mulq	8(%r8)
	addq	%rax, %rsi
	adcq	%rdx, %rcx
	adcq	$0, %r9
	movq	16(%r10), %rax
	mulq	(%r8)
	addq	%rax, %rsi
	adcq	%rdx, %rcx
	adcq	$0, %r9
	movq	%rsi, %rax
	xorq	%rsi, %rsi
	movq	%rax, 16(%r13)
	movq	(%r10), %rax
	mulq	24(%r8)
	addq	%rax, %rcx
	adcq	%rdx, %r9
	adcq	$0, %rsi
	movq	8(%r10), %rax
	mulq	16(%r8)
	addq	%rax, %rcx
	adcq	%rdx, %r9
	adcq	$0, %rsi
	movq	16(%r10), %rax
	mulq	8(%r8)
	addq	%rax, %rcx
	adcq	%rdx, %r9
	adcq	$0, %rsi
	movq	24(%r10), %rax
	mulq	(%r8)
	addq	%rax, %rcx
	adcq	%rdx, %r9
	adcq	$0, %rsi
	movq	%rcx, %rax
	xorq	%rcx, %rcx
	movq	%rax, 24(%r13)
	movq	8(%r10), %rax
	mulq	24(%r8)
	addq	%rax, %r9
	adcq	%rdx, %rsi
	adcq	$0, %rcx
	movq	16(%r10), %rax
	mulq	16(%r8)
	addq	%rax, %r9
	adcq	%rdx, %rsi
	adcq	$0, %rcx
	movq	24(%r10), %rax
	mulq	8(%r8)
	addq	%rax, %r9
	adcq	%rdx, %rsi
	adcq	$0, %rcx
	movq	%r9, %rax
	xorq	%r9, %r9
	movq	%rax, 32(%r13)
	movq	16(%r10), %rax
	mulq	24(%r8)
	addq	%rax, %rsi
	adcq	%rdx, %rcx
	adcq	$0, %r9
	movq	24(%r10), %rax
	mulq	16(%r8)
	addq	%rax, %rsi
	adcq	%rdx, %rcx
	adcq	$0, %r9
	xorq	%r11, %r11
	movq	%rsi, 40(%r13)
	movq	24(%r10), %rax
	mulq	24(%r8)
	addq	%rax, %rcx
	adcq	%rdx, %r9
	adcq	$0, %r11
	xorq	%rax, %rax
	movq	%rcx, 48(%r13)
	movq	%r9, 56(%r13)
	xorq	%r8, %r8
	movq	glob_data + 64(%rip), %r11
	movq	glob_data + 136(%rip), %rsi
	xorq	%r9, %r9
	xorq	%rcx, %rcx
	xorq	%r10, %r10
	movq	(%r13), %rax
	addq	%rax, %r9
	adcq	%r8, %rcx
	adcq	$0, %r10
	movq	%r9, %rax
	mulq	%r11
	movq	%rax, (%r12)
	mulq	%rsi
	addq	%rax, %r9
	adcq	%rdx, %rcx
	adcq	$0, %r10
	leaq	glob_data + 136(%rip), %rdx
	movq	(%r12), %rax
	mulq	8(%rdx)
	addq	%rax, %rcx
	adcq	%rdx, %r10
	adcq	$0, %r9
	movq	8(%r13), %rax
	addq	%rax, %rcx
	adcq	%r8, %r10
	adcq	$0, %r9
	movq	%rcx, %rax
	mulq	%r11
	movq	%rax, 8(%r12)
	mulq	%rsi
	addq	%rax, %rcx
	adcq	%rdx, %r10
	adcq	$0, %r9
	leaq	glob_data + 136(%rip), %rbx
	movq	(%r12), %rax
	mulq	16(%rbx)
	addq	%rax, %r10
	adcq	%rdx, %r9
	adcq	$0, %rcx
	movq	8(%r12), %rax
	mulq	8(%rbx)
	addq	%rax, %r10
	adcq	%rdx, %r9
	adcq	$0, %rcx
	movq	16(%r13), %rax
	addq	%rax, %r10
	adcq	%r8, %r9
	adcq	$0, %rcx
	movq	%r10, %rax
	mulq	%r11
	movq	%rax, 16(%r12)
	mulq	%rsi
	addq	%rax, %r10
	adcq	%rdx, %r9
	adcq	$0, %rcx
	leaq	glob_data + 136(%rip), %rbx
	movq	(%r12), %rax
	mulq	24(%rbx)
	addq	%rax, %r9
	adcq	%rdx, %rcx
	adcq	$0, %r10
	movq	8(%r12), %rax
	mulq	16(%rbx)
	addq	%rax, %r9
	adcq	%rdx, %rcx
	adcq	$0, %r10
	movq	16(%r12), %rax
	mulq	8(%rbx)
	addq	%rax, %r9
	adcq	%rdx, %rcx
	adcq	$0, %r10
	movq	24(%r13), %rax
	addq	%rax, %r9
	adcq	%r8, %rcx
	adcq	$0, %r10
	movq	%r9, %rax
	mulq	%r11
	movq	%rax, 24(%r12)
	mulq	%rsi
	addq	%rax, %r9
	adcq	%rdx, %rcx
	adcq	$0, %r10
	leaq	glob_data + 136(%rip), %rsi
	movq	8(%r12), %rax
	mulq	24(%rsi)
	addq	%rax, %rcx
	adcq	%rdx, %r10
	adcq	$0, %r9
	movq	16(%r12), %rax
	mulq	16(%rsi)
	addq	%rax, %rcx
	adcq	%rdx, %r10
	adcq	$0, %r9
	movq	24(%r12), %rax
	mulq	8(%rsi)
	addq	%rax, %rcx
	adcq	%rdx, %r10
	adcq	$0, %r9
	movq	32(%r13), %rax
	addq	%rax, %rcx
	adcq	%r8, %r10
	adcq	$0, %r9
	movq	%rcx, (%r12)
	xorq	%rcx, %rcx
	leaq	glob_data + 136(%rip), %rsi
	movq	16(%r12), %rax
	mulq	24(%rsi)
	addq	%rax, %r10
	adcq	%rdx, %r9
	adcq	$0, %rcx
	movq	24(%r12), %rax
	mulq	16(%rsi)
	addq	%rax, %r10
	adcq	%rdx, %r9
	adcq	$0, %rcx
	movq	40(%r13), %rax
	addq	%rax, %r10
	adcq	%r8, %r9
	adcq	$0, %rcx
	movq	%r10, 8(%r12)
	xorq	%rsi, %rsi
	leaq	glob_data + 136(%rip), %rdx
	movq	24(%r12), %rax
	mulq	24(%rdx)
	addq	%rax, %r9
	adcq	%rdx, %rcx
	adcq	$0, %rsi
	movq	48(%r13), %rax
	addq	%rax, %r9
	adcq	%r8, %rcx
	adcq	$0, %rsi
	movq	%r9, 16(%r12)
	xorq	%rax, %rax
	addq	56(%r13), %rcx
	movq	%rcx, 24(%r12)
	movq	(%r12), %rax
	movq	%rax, (%rsp)
	movq	8(%r12), %rax
	movq	%rax, 8(%rsp)
	movq	16(%r12), %rax
	movq	%rax, 16(%rsp)
	movq	24(%r12), %rax
	movq	%rax, 24(%rsp)
	movq	%rsp, %rax
	leaq	glob_data + 104(%rip), %rcx
	movq	(%rcx), %rdx
	addq	%rdx, (%rax)
	movq	8(%rcx), %rdx
	adcq	%rdx, 8(%rax)
	movq	16(%rcx), %rdx
	adcq	%rdx, 16(%rax)
	movq	24(%rcx), %rcx
	adcq	%rcx, 24(%rax)
	movq	(%r12), %rcx
	cmovb	(%rax), %rcx
	movq	%rcx, (%r12)
	movq	8(%r12), %rcx
	cmovb	8(%rax), %rcx
	movq	%rcx, 8(%r12)
	movq	16(%r12), %rcx
	cmovb	16(%rax), %rcx
	movq	%rcx, 16(%r12)
	movq	24(%r12), %rcx
	cmovb	24(%rax), %rcx
	movq	%rcx, 24(%r12)
	jmp 	*%rbp
L_fp_sub$1:
	movq	(%rdx), %rsi
	subq	%rsi, (%rax)
	movq	8(%rdx), %rsi
	sbbq	%rsi, 8(%rax)
	movq	16(%rdx), %rsi
	sbbq	%rsi, 16(%rax)
	movq	24(%rdx), %rdx
	sbbq	%rdx, 24(%rax)
	leaq	glob_data + 136(%rip), %rdx
	movq	(%rdx), %rsi
	movq	%rsi, (%rsp)
	movq	8(%rdx), %rsi
	movq	%rsi, 8(%rsp)
	movq	16(%rdx), %rsi
	movq	%rsi, 16(%rsp)
	movq	24(%rdx), %rdx
	movq	%rdx, 24(%rsp)
	movq	$0, %rdx
	movq	(%rsp), %rsi
	cmovnb	%rdx, %rsi
	movq	%rsi, (%rsp)
	movq	8(%rsp), %rsi
	cmovnb	%rdx, %rsi
	movq	%rsi, 8(%rsp)
	movq	16(%rsp), %rsi
	cmovnb	%rdx, %rsi
	movq	%rsi, 16(%rsp)
	movq	24(%rsp), %rsi
	cmovnb	%rdx, %rsi
	movq	%rsi, 24(%rsp)
	movq	%rsp, %rdx
	movq	(%rdx), %rsi
	addq	%rsi, (%rax)
	movq	8(%rdx), %rsi
	adcq	%rsi, 8(%rax)
	movq	16(%rdx), %rsi
	adcq	%rsi, 16(%rax)
	movq	24(%rdx), %rdx
	adcq	%rdx, 24(%rax)
	jmp 	*%rcx
L_fp_add$1:
	movq	(%rdx), %rsi
	addq	%rsi, (%rax)
	movq	8(%rdx), %rsi
	adcq	%rsi, 8(%rax)
	movq	16(%rdx), %rsi
	adcq	%rsi, 16(%rax)
	movq	24(%rdx), %rdx
	adcq	%rdx, 24(%rax)
	movq	(%rax), %rdx
	movq	%rdx, (%rsp)
	movq	8(%rax), %rdx
	movq	%rdx, 8(%rsp)
	movq	16(%rax), %rdx
	movq	%rdx, 16(%rsp)
	movq	24(%rax), %rdx
	movq	%rdx, 24(%rsp)
	movq	%rsp, %rdx
	leaq	glob_data + 104(%rip), %rsi
	movq	(%rsi), %r8
	addq	%r8, (%rdx)
	movq	8(%rsi), %r8
	adcq	%r8, 8(%rdx)
	movq	16(%rsi), %r8
	adcq	%r8, 16(%rdx)
	movq	24(%rsi), %rsi
	adcq	%rsi, 24(%rdx)
	movq	(%rax), %rsi
	cmovb	(%rdx), %rsi
	movq	%rsi, (%rax)
	movq	8(%rax), %rsi
	cmovb	8(%rdx), %rsi
	movq	%rsi, 8(%rax)
	movq	16(%rax), %rsi
	cmovb	16(%rdx), %rsi
	movq	%rsi, 16(%rax)
	movq	24(%rax), %rsi
	cmovb	24(%rdx), %rsi
	movq	%rsi, 24(%rax)
	jmp 	*%rcx
L_bn_sqrn$1:
	movq	(%r8), %rax
	mulq	%rax
	movq	%rax, (%r9)
	movq	%rdx, %r10
	xorq	%rsi, %rsi
	xorq	%rdi, %rdi
	movq	(%r8), %rax
	movq	8(%r8), %rdx
	mulq	%rdx
	movq	%rax, %r11
	shlq	$1, %rax
	shldq	$1, %r11, %rdx
	movq	$0, %r11
	adcq	%r11, %r11
	addq	%rax, %r10
	adcq	%rdx, %rsi
	adcq	%r11, %rdi
	movq	%r10, %rax
	xorq	%r10, %r10
	movq	%rax, 8(%r9)
	movq	(%r8), %rax
	movq	16(%r8), %rdx
	mulq	%rdx
	movq	%rax, %r11
	shlq	$1, %rax
	shldq	$1, %r11, %rdx
	movq	$0, %r11
	adcq	%r11, %r11
	addq	%rax, %rsi
	adcq	%rdx, %rdi
	adcq	%r11, %r10
	movq	8(%r8), %rax
	mulq	%rax
	addq	%rax, %rsi
	adcq	%rdx, %rdi
	adcq	$0, %r10
	movq	%rsi, %rax
	xorq	%rsi, %rsi
	movq	%rax, 16(%r9)
	movq	(%r8), %rax
	movq	24(%r8), %rdx
	mulq	%rdx
	movq	%rax, %r11
	shlq	$1, %rax
	shldq	$1, %r11, %rdx
	movq	$0, %r11
	adcq	%r11, %r11
	addq	%rax, %rdi
	adcq	%rdx, %r10
	adcq	%r11, %rsi
	movq	8(%r8), %rax
	movq	16(%r8), %rdx
	mulq	%rdx
	movq	%rax, %r11
	shlq	$1, %rax
	shldq	$1, %r11, %rdx
	movq	$0, %r11
	adcq	%r11, %r11
	addq	%rax, %rdi
	adcq	%rdx, %r10
	adcq	%r11, %rsi
	movq	%rdi, %rax
	xorq	%rdi, %rdi
	movq	%rax, 24(%r9)
	movq	8(%r8), %rax
	movq	24(%r8), %rdx
	mulq	%rdx
	movq	%rax, %r11
	shlq	$1, %rax
	shldq	$1, %r11, %rdx
	movq	$0, %r11
	adcq	%r11, %r11
	addq	%rax, %r10
	adcq	%rdx, %rsi
	adcq	%r11, %rdi
	movq	16(%r8), %rax
	mulq	%rax
	addq	%rax, %r10
	adcq	%rdx, %rsi
	adcq	$0, %rdi
	movq	%r10, %rax
	xorq	%r10, %r10
	movq	%rax, 32(%r9)
	movq	16(%r8), %rax
	movq	24(%r8), %rdx
	mulq	%rdx
	movq	%rax, %r11
	shlq	$1, %rax
	shldq	$1, %r11, %rdx
	movq	$0, %r11
	adcq	%r11, %r11
	addq	%rax, %rsi
	adcq	%rdx, %rdi
	adcq	%r11, %r10
	xorq	%r11, %r11
	movq	%rsi, 40(%r9)
	movq	24(%r8), %rax
	mulq	%rax
	addq	%rax, %rdi
	adcq	%rdx, %r10
	adcq	$0, %r11
	xorq	%rax, %rax
	movq	%rdi, 48(%r9)
	movq	%r10, 56(%r9)
	jmp 	*%rcx
L_bn_muln$1:
	movq	(%r8), %rax
	mulq	(%rbx)
	movq	%rax, (%r9)
	movq	%rdx, %rsi
	xorq	%rcx, %rcx
	xorq	%rdi, %rdi
	movq	(%r8), %rax
	mulq	8(%rbx)
	addq	%rax, %rsi
	adcq	%rdx, %rcx
	adcq	$0, %rdi
	movq	8(%r8), %rax
	mulq	(%rbx)
	addq	%rax, %rsi
	adcq	%rdx, %rcx
	adcq	$0, %rdi
	xorq	%r11, %r11
	movq	%rsi, 8(%r9)
	movq	(%r8), %rax
	mulq	16(%rbx)
	addq	%rax, %rcx
	adcq	%rdx, %rdi
	adcq	$0, %r11
	movq	8(%r8), %rax
	mulq	8(%rbx)
	addq	%rax, %rcx
	adcq	%rdx, %rdi
	adcq	$0, %r11
	movq	16(%r8), %rax
	mulq	(%rbx)
	addq	%rax, %rcx
	adcq	%rdx, %rdi
	adcq	$0, %r11
	xorq	%rsi, %rsi
	movq	%rcx, 16(%r9)
	movq	(%r8), %rax
	mulq	24(%rbx)
	addq	%rax, %rdi
	adcq	%rdx, %r11
	adcq	$0, %rsi
	movq	8(%r8), %rax
	mulq	16(%rbx)
	addq	%rax, %rdi
	adcq	%rdx, %r11
	adcq	$0, %rsi
	movq	16(%r8), %rax
	mulq	8(%rbx)
	addq	%rax, %rdi
	adcq	%rdx, %r11
	adcq	$0, %rsi
	movq	24(%r8), %rax
	mulq	(%rbx)
	addq	%rax, %rdi
	adcq	%rdx, %r11
	adcq	$0, %rsi
	xorq	%rcx, %rcx
	movq	%rdi, 24(%r9)
	movq	8(%r8), %rax
	mulq	24(%rbx)
	addq	%rax, %r11
	adcq	%rdx, %rsi
	adcq	$0, %rcx
	movq	16(%r8), %rax
	mulq	16(%rbx)
	addq	%rax, %r11
	adcq	%rdx, %rsi
	adcq	$0, %rcx
	movq	24(%r8), %rax
	mulq	8(%rbx)
	addq	%rax, %r11
	adcq	%rdx, %rsi
	adcq	$0, %rcx
	xorq	%rdi, %rdi
	movq	%r11, 32(%r9)
	movq	16(%r8), %rax
	mulq	24(%rbx)
	addq	%rax, %rsi
	adcq	%rdx, %rcx
	adcq	$0, %rdi
	movq	24(%r8), %rax
	mulq	16(%rbx)
	addq	%rax, %rsi
	adcq	%rdx, %rcx
	adcq	$0, %rdi
	xorq	%r11, %r11
	movq	%rsi, 40(%r9)
	movq	24(%r8), %rax
	mulq	24(%rbx)
	addq	%rax, %rcx
	adcq	%rdx, %rdi
	adcq	$0, %r11
	xorq	%rax, %rax
	movq	%rcx, 48(%r9)
	movq	%rdi, 56(%r9)
	jmp 	*%r10
L_bn_subc$1:
	movq	(%rcx), %rax
	subq	%rax, (%rdx)
	movq	8(%rcx), %rax
	sbbq	%rax, 8(%rdx)
	movq	16(%rcx), %rax
	sbbq	%rax, 16(%rdx)
	movq	24(%rcx), %rax
	sbbq	%rax, 24(%rdx)
	jmp 	*%rsi
L_bn_addc$1:
	movq	(%rcx), %rax
	addq	%rax, (%rdx)
	movq	8(%rcx), %rax
	adcq	%rax, 8(%rdx)
	movq	16(%rcx), %rax
	adcq	%rax, 16(%rdx)
	movq	24(%rcx), %rax
	adcq	%rax, 24(%rdx)
	jmp 	*%rsi
L_bn_test0$1:
	movq	(%rcx), %rax
	orq 	8(%rcx), %rax
	orq 	16(%rcx), %rax
	orq 	24(%rcx), %rax
	andq	%rax, %rax
	jmp 	*%rdx
L_bn_eq$1:
	movq	$0, %rdx
	movq	$1, %rsi
	movq	$0, %rdi
	movq	(%rax), %r8
	xorq	(%rcx), %r8
	orq 	%r8, %rdi
	movq	8(%rax), %r8
	xorq	8(%rcx), %r8
	orq 	%r8, %rdi
	movq	16(%rax), %r8
	xorq	16(%rcx), %r8
	orq 	%r8, %rdi
	movq	24(%rax), %rax
	xorq	24(%rcx), %rax
	orq 	%rax, %rdi
	andq	%rdi, %rdi
	cmove	%rsi, %rdx
	jmp 	*%r9
	.data
	.p2align	5
_glob_data:
glob_data:
      .byte 0
      .byte 0
      .byte 0
      .byte 0
      .byte 0
      .byte 0
      .byte 0
      .byte 0
      .byte 0
      .byte 0
      .byte 16
      .byte -32
      .byte 15
      .byte 0
      .byte 0
      .byte 0
      .byte 0
      .byte 0
      .byte 0
      .byte 0
      .byte 0
      .byte 0
      .byte 0
      .byte 0
      .byte 0
      .byte 0
      .byte 0
      .byte 0
      .byte 0
      .byte 0
      .byte 0
      .byte 0
      .byte 0
      .byte 0
      .byte 0
      .byte 0
      .byte 0
      .byte -4
      .byte 3
      .byte 0
      .byte 0
      .byte 0
      .byte 0
      .byte 0
      .byte 0
      .byte 0
      .byte 0
      .byte 0
      .byte 0
      .byte 0
      .byte 0
      .byte 0
      .byte 0
      .byte 0
      .byte 0
      .byte 0
      .byte 0
      .byte 0
      .byte 0
      .byte 0
      .byte 0
      .byte 0
      .byte 0
      .byte 0
      .byte -1
      .byte -2
      .byte -2
      .byte -2
      .byte -2
      .byte -2
      .byte -2
      .byte -2
      .byte -1
      .byte -2
      .byte -1
      .byte -1
      .byte -1
      .byte -1
      .byte -1
      .byte -1
      .byte -1
      .byte -1
      .byte -1
      .byte -1
      .byte -1
      .byte -1
      .byte -1
      .byte -1
      .byte -1
      .byte -1
      .byte -1
      .byte -1
      .byte -1
      .byte -1
      .byte -1
      .byte -1
      .byte -1
      .byte -1
      .byte 63
      .byte 0
      .byte 0
      .byte 0
      .byte 0
      .byte 0
      .byte -1
      .byte 0
      .byte 0
      .byte 0
      .byte 0
      .byte 0
      .byte 0
      .byte 0
      .byte 0
      .byte 0
      .byte 0
      .byte 0
      .byte 0
      .byte 0
      .byte 0
      .byte 0
      .byte 0
      .byte 0
      .byte 0
      .byte 0
      .byte 0
      .byte 0
      .byte 0
      .byte 0
      .byte 0
      .byte 0
      .byte -64
      .byte -1
      .byte -1
      .byte -1
      .byte -1
      .byte -1
      .byte 1
      .byte -1
      .byte -1
      .byte -1
      .byte -1
      .byte -1
      .byte -1
      .byte -1
      .byte -1
      .byte -1
      .byte -1
      .byte -1
      .byte -1
      .byte -1
      .byte -1
      .byte -1
      .byte -1
      .byte -1
      .byte -1
      .byte -1
      .byte -1
      .byte -1
      .byte -1
      .byte -1
      .byte -1
      .byte -1
      .byte 63
      .byte 0
      .byte 0
      .byte 0
      .byte 0
      .byte 0
