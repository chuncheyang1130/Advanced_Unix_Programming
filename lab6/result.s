	call sort

quick_sort:
	cmp	esi, edx
	jge	return

	push r11
	push	rbp

	mov	r10, rdi
	mov	r11d, edx
	movsx	rax, edx
	lea	r8, [rdi+rax*8]
	movsx	rcx, esi
	lea	rax, [rdi+rcx*8]

	sub	edx, esi
	add	rdx, rcx

	lea	rdi, [8+rdi+rdx*8]
	mov	ebx, esi
	jmp	loop
	
ADD:
	add	rax, 8
	cmp	rax, rdi
	je	loop_fin

loop:
	mov	rdx, QWORD PTR [rax]
	cmp	rdx, QWORD PTR [r8]
	jg	ADD

	movsx	rcx, ebx
	lea	rcx, [0+r10+rcx*8]
	mov	r9, QWORD PTR [rcx]
	mov	QWORD PTR [rcx], rdx
	mov	QWORD PTR [rax], r9
	add	ebx, 1
	jmp	ADD

loop_fin:
	lea	edx, [rbx-2]
	mov	rdi, r10
	call	quick_sort

	mov	edx, r11d
	mov	esi, ebx
	call	quick_sort
	
	pop	rbp
	pop r11

	ret

return:
	ret

sort:

	sub	rsp, 8

	lea	edx, [rsi-1]
	mov	esi, 0
	call	quick_sort
	add	rsp, 8

	ret
