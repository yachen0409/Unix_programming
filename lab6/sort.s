        call    sort_func
        mov	eax, 0
	    leave
	    ret
swap:
        push    rbp
        mov     rbp, rsp
        mov     QWORD PTR [rbp-24], rdi
        mov     QWORD PTR [rbp-32], rsi
        mov     rax, QWORD PTR [rbp-24]
        mov     rax, QWORD PTR [rax]
        mov     QWORD PTR [rbp-8], rax
        mov     rax, QWORD PTR [rbp-32]
        mov     rdx, QWORD PTR [rax]
        mov     rax, QWORD PTR [rbp-24]
        mov     QWORD PTR [rax], rdx
        mov     rax, QWORD PTR [rbp-32]
        mov     rdx, QWORD PTR [rbp-8]
        mov     QWORD PTR [rax], rdx
        pop     rbp
	    ret
partition:
        push    rbp
        mov     rbp, rsp
        sub     rsp, 32
        mov     QWORD PTR [rbp-24], rdi
        mov     DWORD PTR [rbp-28], esi
        mov     DWORD PTR [rbp-32], edx
        mov     eax, DWORD PTR [rbp-32]
        cdqe
        lea     rdx, [0+rax*8]
        mov     rax, QWORD PTR [rbp-24]
        add     rax, rdx
        mov     rax, QWORD PTR [rax]
        mov     QWORD PTR [rbp-16], rax
        mov     eax, DWORD PTR [rbp-28]
        sub     eax, 1
        mov     DWORD PTR [rbp-4], eax
        mov     eax, DWORD PTR [rbp-28]
        mov     DWORD PTR [rbp-8], eax
        jmp     .L3
.L5:
        mov     eax, DWORD PTR [rbp-8]
        cdqe
        lea     rdx, [0+rax*8]
        mov     rax, QWORD PTR [rbp-24]
        add     rax, rdx
        mov     rax, QWORD PTR [rax]
        cmp     QWORD PTR [rbp-16], rax
        jle     .L4
        add     DWORD PTR [rbp-4], 1
        mov     eax, DWORD PTR [rbp-8]
        cdqe
        lea     rdx, [0+rax*8]
        mov     rax, QWORD PTR [rbp-24]
        add     rdx, rax
        mov     eax, DWORD PTR [rbp-4]
        cdqe
        lea     rcx, [0+rax*8]
        mov     rax, QWORD PTR [rbp-24]
        add     rax, rcx
        mov     rsi, rdx
        mov     rdi, rax
        call    swap
.L4:
        add     DWORD PTR [rbp-8], 1
.L3:
        mov     eax, DWORD PTR [rbp-32]
        cmp     eax, DWORD PTR [rbp-8]
        jg      .L5
        mov     eax, DWORD PTR [rbp-32]
        cdqe
        lea     rdx, [0+rax*8]
        mov     rax, QWORD PTR [rbp-24]
        add     rdx, rax
        mov     eax, DWORD PTR [rbp-4]
        cdqe
        add     rax, 1
        lea     rcx, [0+rax*8]
        mov     rax, QWORD PTR [rbp-24]
        add     rax, rcx
        mov     rsi, rdx
        mov     rdi, rax
        call    swap
        mov     eax, DWORD PTR [rbp-4]
        add     eax, 1
        leave
	    ret
quickSort:
        push    rbp
        mov     rbp, rsp
        sub     rsp, 32
        mov     QWORD PTR [rbp-24], rdi
        mov     DWORD PTR [rbp-28], esi
        mov     DWORD PTR [rbp-32], edx
        mov     eax, DWORD PTR [rbp-28]
        cmp     eax, DWORD PTR [rbp-32]
        jge     .L9
        mov     edx, DWORD PTR [rbp-32]
        mov     ecx, DWORD PTR [rbp-28]
        mov     rax, QWORD PTR [rbp-24]
        mov     esi, ecx
        mov     rdi, rax
        call    partition
        mov     DWORD PTR [rbp-4], eax
        mov     eax, DWORD PTR [rbp-4]
        lea     edx, [rax-1]
        mov     ecx, DWORD PTR [rbp-28]
        mov     rax, QWORD PTR [rbp-24]
        mov     esi, ecx
        mov     rdi, rax
        call    quickSort
        mov     eax, DWORD PTR [rbp-4]
        lea     ecx, [rax+1]
        mov     edx, DWORD PTR [rbp-32]
        mov     rax, QWORD PTR [rbp-24]
        mov     esi, ecx
        mov     rdi, rax
        call    quickSort
.L9:
	    leave
        ret
sort_func:
        push    rbp
        mov     rbp, rsp
        sub     rsp, 16
        mov     QWORD PTR [rbp-8], rdi
        mov     DWORD PTR [rbp-12], esi
        mov     eax, DWORD PTR [rbp-12]
        lea     edx, [rax-1]
        mov     rax, QWORD PTR [rbp-8]
        mov     esi, 0
        mov     rdi, rax
        call    quickSort
        leave
        ret
