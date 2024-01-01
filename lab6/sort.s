	.file	"sort.c"
	.intel_syntax noprefix
	.text
	.globl	quick_sort
	.type	quick_sort, @function
quick_sort:
.LFB39:
	.cfi_startproc
	endbr64
	cmp	esi, edx
	jge	.L7
	push	r12
	.cfi_def_cfa_offset 16
	.cfi_offset 12, -16
	push	rbp
	.cfi_def_cfa_offset 24
	.cfi_offset 6, -24
	push	rbx
	.cfi_def_cfa_offset 32
	.cfi_offset 3, -32
	mov	rbp, rdi
	mov	r12d, edx
	movsx	rax, edx
	lea	r8, [rdi+rax*8]
	movsx	rcx, esi
	lea	rax, [rdi+rcx*8]
	sub	edx, esi
	add	rdx, rcx
	lea	rdi, 8[rdi+rdx*8]
	mov	ebx, esi
	jmp	.L4
.L3:
	add	rax, 8
	cmp	rax, rdi
	je	.L10
.L4:
	mov	rdx, QWORD PTR [rax]
	cmp	rdx, QWORD PTR [r8]
	jg	.L3
	movsx	rcx, ebx
	lea	rcx, 0[rbp+rcx*8]
	mov	r9, QWORD PTR [rcx]
	mov	QWORD PTR [rcx], rdx
	mov	QWORD PTR [rax], r9
	add	ebx, 1
	jmp	.L3
.L10:
	lea	edx, -2[rbx]
	mov	rdi, rbp
	call	quick_sort
	mov	edx, r12d
	mov	esi, ebx
	mov	rdi, rbp
	call	quick_sort
	pop	rbx
	.cfi_def_cfa_offset 24
	pop	rbp
	.cfi_def_cfa_offset 16
	pop	r12
	.cfi_def_cfa_offset 8
	ret
.L7:
	.cfi_restore 3
	.cfi_restore 6
	.cfi_restore 12
	ret
	.cfi_endproc
.LFE39:
	.size	quick_sort, .-quick_sort
	.globl	sort
	.type	sort, @function
sort:
.LFB40:
	.cfi_startproc
	endbr64
	sub	rsp, 8
	.cfi_def_cfa_offset 16
	lea	edx, -1[rsi]
	mov	esi, 0
	call	quick_sort
	add	rsp, 8
	.cfi_def_cfa_offset 8
	ret
	.cfi_endproc
.LFE40:
	.size	sort, .-sort
	.ident	"GCC: (Ubuntu 11.3.0-1ubuntu1~22.04) 11.3.0"
	.section	.note.GNU-stack,"",@progbits
	.section	.note.gnu.property,"a"
	.align 8
	.long	1f - 0f
	.long	4f - 1f
	.long	5
0:
	.string	"GNU"
1:
	.align 8
	.long	0xc0000002
	.long	3f - 2f
2:
	.long	0x3
3:
	.align 8
4:
