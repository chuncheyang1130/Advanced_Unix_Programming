    call sort

quick_sort:
	push	r15

	movsx	rax, edx
	push	r14

	push	r13

	push	r12

	push	rbp

	push	rbx

	sub	rsp, 136

	mov	DWORD PTR 56[rsp], eax
	cmp	eax, esi
	jle	.L1
	lea	rax, [rdi+rax*8]
	mov	r10, rdi
	mov	r11d, esi
	mov	QWORD PTR 48[rsp], rax
.L7:
	movsx	rbp, r11d
	mov	edx, r11d
	mov	rax, rbp
.L4:
	mov	rdi, QWORD PTR 48[rsp]
	mov	rsi, QWORD PTR [r10+rax*8]
	cmp	rsi, QWORD PTR [rdi]
	jg	.L3
	movsx	rcx, edx
	add	edx, 1
	lea	rcx, [r10+rcx*8]
	mov	rdi, QWORD PTR [rcx]
	mov	QWORD PTR [rcx], rsi
	mov	QWORD PTR [r10+rax*8], rdi
.L3:
	add	rax, 1
	cmp	DWORD PTR 56[rsp], eax
	jge	.L4
	lea	eax, -2[rdx]
	mov	DWORD PTR 60[rsp], edx
	mov	DWORD PTR 20[rsp], eax
	cmp	eax, r11d
	jle	.L11
	movsx	rax, DWORD PTR 20[rsp]
	lea	rax, [r10+rax*8]
	mov	QWORD PTR 64[rsp], rax
.L12:
	mov	rax, rbp
	mov	edx, r11d
.L9:
	mov	rdi, QWORD PTR 64[rsp]
	mov	rsi, QWORD PTR [r10+rax*8]
	cmp	rsi, QWORD PTR [rdi]
	jg	.L8
	movsx	rcx, edx
	add	edx, 1
	lea	rcx, [r10+rcx*8]
	mov	rdi, QWORD PTR [rcx]
	mov	QWORD PTR [rcx], rsi
	mov	QWORD PTR [r10+rax*8], rdi
.L8:
	add	rax, 1
	cmp	DWORD PTR 20[rsp], eax
	jge	.L9
	lea	eax, -2[rdx]
	mov	DWORD PTR 80[rsp], edx
	mov	DWORD PTR 24[rsp], eax
	cmp	eax, r11d
	jle	.L16
	movsx	rax, DWORD PTR 24[rsp]
	lea	rax, [r10+rax*8]
	mov	QWORD PTR 72[rsp], rax
	mov	eax, r11d
	mov	r11, r10
	mov	r10d, eax
.L17:
	mov	rax, rbp
	mov	edx, r10d
.L14:
	mov	rdi, QWORD PTR 72[rsp]
	mov	rsi, QWORD PTR [r11+rax*8]
	cmp	rsi, QWORD PTR [rdi]
	jg	.L13
	movsx	rcx, edx
	add	edx, 1
	lea	rcx, [r11+rcx*8]
	mov	rdi, QWORD PTR [rcx]
	mov	QWORD PTR [rcx], rsi
	mov	QWORD PTR [r11+rax*8], rdi
.L13:
	add	rax, 1
	cmp	DWORD PTR 24[rsp], eax
	jge	.L14
	lea	eax, -2[rdx]
	mov	DWORD PTR 84[rsp], edx
	mov	DWORD PTR 28[rsp], eax
	cmp	eax, r10d
	jle	.L21
	movsx	rax, DWORD PTR 28[rsp]
	lea	rax, [r11+rax*8]
	mov	QWORD PTR 88[rsp], rax
	mov	eax, r10d
	mov	r10, r11
	mov	r11d, eax
.L22:
	mov	rax, rbp
	mov	edx, r11d
.L19:
	mov	rdi, QWORD PTR 88[rsp]
	mov	rsi, QWORD PTR [r10+rax*8]
	cmp	rsi, QWORD PTR [rdi]
	jg	.L18
	movsx	rcx, edx
	add	edx, 1
	lea	rcx, [r10+rcx*8]
	mov	rdi, QWORD PTR [rcx]
	mov	QWORD PTR [rcx], rsi
	mov	QWORD PTR [r10+rax*8], rdi
.L18:
	add	rax, 1
	cmp	DWORD PTR 28[rsp], eax
	jge	.L19
	lea	eax, -2[rdx]
	mov	DWORD PTR 104[rsp], edx
	mov	DWORD PTR 32[rsp], eax
	cmp	eax, r11d
	jle	.L26
	movsx	rax, DWORD PTR 32[rsp]
	mov	rbx, r10
	lea	rax, [r10+rax*8]
	mov	QWORD PTR 96[rsp], rax
	mov	rax, rbp
.L27:
	lea	rdx, [rbx+rax*8]
	mov	r10d, r11d
	mov	esi, r11d
.L24:
	mov	rdi, QWORD PTR 96[rsp]
	mov	r8, QWORD PTR [rdx]
	cmp	r8, QWORD PTR [rdi]
	jg	.L23
	movsx	rcx, r10d
	add	r10d, 1
	lea	rcx, [rbx+rcx*8]
	mov	rdi, QWORD PTR [rcx]
	mov	QWORD PTR [rcx], r8
	mov	QWORD PTR [rdx], rdi
.L23:
	add	esi, 1
	add	rdx, 8
	cmp	DWORD PTR 32[rsp], esi
	jge	.L24
	lea	r9d, -2[r10]
	cmp	r9d, r11d
	jle	.L31
	movsx	rdx, r9d
	mov	DWORD PTR 108[rsp], r10d
	mov	esi, r11d
	lea	rdi, [rbx+rdx*8]
	mov	QWORD PTR 40[rsp], rdi
.L32:
	mov	r10, QWORD PTR 40[rsp]
	mov	rdx, rax
	mov	r13d, esi
.L29:
	mov	rdi, QWORD PTR [rbx+rdx*8]
	cmp	rdi, QWORD PTR [r10]
	jg	.L28
	movsx	rcx, r13d
	add	r13d, 1
	lea	rcx, [rbx+rcx*8]
	mov	r8, QWORD PTR [rcx]
	mov	QWORD PTR [rcx], rdi
	mov	QWORD PTR [rbx+rdx*8], r8
.L28:
	add	rdx, 1
	cmp	r9d, edx
	jge	.L29
	lea	r15d, -2[r13]
	cmp	r15d, esi
	jle	.L36
	movsx	rdx, r15d
	mov	DWORD PTR 112[rsp], r9d
	lea	rdi, [rbx+rdx*8]
	mov	DWORD PTR 116[rsp], r13d
	mov	r13d, r15d
	mov	QWORD PTR 8[rsp], rdi
.L37:
	mov	rdx, rax
	mov	ebp, esi
.L34:
	mov	rcx, QWORD PTR 8[rsp]
	mov	rdi, QWORD PTR [rbx+rdx*8]
	cmp	rdi, QWORD PTR [rcx]
	jg	.L33
	movsx	rcx, ebp
	add	ebp, 1
	lea	rcx, [rbx+rcx*8]
	mov	r8, QWORD PTR [rcx]
	mov	QWORD PTR [rcx], rdi
	mov	QWORD PTR [rbx+rdx*8], r8
.L33:
	add	rdx, 1
	cmp	r13d, edx
	jge	.L34
	lea	r14d, -2[rbp]
	cmp	r14d, esi
	jle	.L41
	movsx	rdx, r14d
	mov	DWORD PTR 120[rsp], r13d
	lea	r9, [rbx+rdx*8]
	mov	DWORD PTR 124[rsp], ebp
	mov	rbp, r9
.L42:
	mov	rdx, rax
	mov	r15d, esi
.L39:
	mov	rcx, QWORD PTR [rbx+rdx*8]
	cmp	rcx, QWORD PTR 0[rbp]
	jg	.L38
	movsx	rdi, r15d
	add	r15d, 1
	lea	rdi, [rbx+rdi*8]
	mov	r8, QWORD PTR [rdi]
	mov	QWORD PTR [rdi], rcx
	mov	QWORD PTR [rbx+rdx*8], r8
.L38:
	add	rdx, 1
	cmp	r14d, edx
	jge	.L39
	lea	ecx, -2[r15]
	cmp	ecx, esi
	jle	.L45
	movsx	rdx, ecx
	mov	r12d, esi
	lea	r13, [rbx+rdx*8]
	mov	rdi, r13
	mov	r13d, ecx
	mov	ecx, r15d
	mov	r15, rbp
	mov	rbp, rdi
.L44:
	mov	rdi, QWORD PTR [rbx+rax*8]
	cmp	rdi, QWORD PTR 0[rbp]
	jg	.L43
	movsx	rdx, r12d
	add	r12d, 1
	lea	rdx, [rbx+rdx*8]
	mov	r8, QWORD PTR [rdx]
	mov	QWORD PTR [rdx], rdi
	mov	QWORD PTR [rbx+rax*8], r8
.L43:
	add	rax, 1
	cmp	r13d, eax
	jge	.L44
	lea	edx, -2[r12]
	mov	rdi, rbx
	mov	DWORD PTR 36[rsp], ecx
	call	quick_sort
	cmp	r13d, r12d
	mov	ecx, DWORD PTR 36[rsp]
	jle	.L63
	movsx	rax, r12d
	mov	rsi, rax
	mov	r12d, esi
	jmp	.L44
.L11:
	mov	r11d, DWORD PTR 60[rsp]
	mov	eax, DWORD PTR 56[rsp]
	cmp	r11d, eax
	jl	.L7
.L1:
	add	rsp, 136

	pop	rbx

	pop	rbp

	pop	r12

	pop	r13

	pop	r14

	pop	r15

	ret

.L63:

	mov	rbp, r15
	mov	r15d, ecx
.L45:
	cmp	r14d, r15d
	jle	.L62
	movsx	rax, r15d
	mov	rsi, rax
	jmp	.L42
.L62:
	mov	r13d, DWORD PTR 120[rsp]
	mov	ebp, DWORD PTR 124[rsp]
.L41:
	cmp	r13d, ebp
	jle	.L61
	movsx	rax, ebp
	mov	rsi, rax
	jmp	.L37
.L61:
	mov	r9d, DWORD PTR 112[rsp]
	mov	r13d, DWORD PTR 116[rsp]
.L36:
	cmp	r9d, r13d
	jle	.L60
	movsx	rax, r13d
	mov	rsi, rax
	jmp	.L32
.L60:
	mov	r10d, DWORD PTR 108[rsp]
.L31:
	cmp	DWORD PTR 32[rsp], r10d
	jle	.L59
	movsx	rax, r10d
	mov	r11, rax
	jmp	.L27
.L59:
	mov	r10, rbx
.L26:
	mov	r11d, DWORD PTR 104[rsp]
	cmp	DWORD PTR 28[rsp], r11d
	jle	.L58
	movsx	rbp, r11d
	jmp	.L22
.L58:
	mov	r11, r10
.L21:
	mov	r10d, DWORD PTR 84[rsp]
	cmp	DWORD PTR 24[rsp], r10d
	jle	.L57
	movsx	rbp, r10d
	jmp	.L17
.L57:
	mov	r10, r11
.L16:
	mov	r11d, DWORD PTR 80[rsp]
	cmp	DWORD PTR 20[rsp], r11d
	jle	.L11
	movsx	rbp, r11d
	jmp	.L12
	.cfi_endproc

sort:
.LFB40:

	endbr64
	push	r13

	push	r12

	lea	r12d, -1[rsi]
	push	rbp

	push	rbx

	sub	rsp, 8

	test	r12d, r12d
	jle	.L66
	movsx	rax, r12d
	mov	rbx, rdi
	xor	r8d, r8d
	lea	r13, [rdi+rax*8]
.L70:
	movsx	rax, r8d
	mov	ebp, r8d

.L69:
	mov	rdx, QWORD PTR [rbx+rax*8]
	cmp	rdx, QWORD PTR 0[r13]
	jg	.L68
	movsx	rcx, ebp
	add	ebp, 1
	lea	rcx, [rbx+rcx*8]
	mov	rsi, QWORD PTR [rcx]
	mov	QWORD PTR [rcx], rdx
	mov	QWORD PTR [rbx+rax*8], rsi
.L68:
	add	rax, 1
	cmp	r12d, eax
	jge	.L69
	lea	edx, -2[rbp]
	mov	esi, r8d
	mov	rdi, rbx
	call	quick_sort
	cmp	r12d, ebp
	jle	.L66
	mov	r8d, ebp
	jmp	.L70

.L66:
	add	rsp, 8
	pop	rbx
	pop	rbp
	pop	r12
	pop	r13
	ret
