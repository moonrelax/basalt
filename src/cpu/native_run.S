.section .note.GNU-stack, "", @progbits

.bss
.align 32
.global basalt_guest_ymm
basalt_guest_ymm:
    .zero 512
.global basalt_host_ymm
basalt_host_ymm:
    .zero 512
.align 8
.global basalt_host_rsp
basalt_host_rsp:
    .quad 0
.global basalt_host_fs
basalt_host_fs:
    .quad 0
.global basalt_host_gs
basalt_host_gs:
    .quad 0
basalt_target:
    .quad 0
basalt_gpr:
    .quad 0
.global basalt_in_guest
basalt_in_guest:
    .byte 0
.global basalt_syscall_sel
basalt_syscall_sel:
    .byte 0
.global basalt_stop
basalt_stop:
    .byte 0
.align 8
.global basalt_regs_ptr
basalt_regs_ptr:
    .quad 0

.section .rodata
basalt_sig_msg:
    .ascii "SIG\n"
.equ basalt_sig_len, 4

.text
.global basalt_native_enter
.global basalt_native_return
.global basalt_sig_entry

.macro SAVE_YMM sym
    vmovdqu %ymm0,  \sym+0(%rip)
    vmovdqu %ymm1,  \sym+32(%rip)
    vmovdqu %ymm2,  \sym+64(%rip)
    vmovdqu %ymm3,  \sym+96(%rip)
    vmovdqu %ymm4,  \sym+128(%rip)
    vmovdqu %ymm5,  \sym+160(%rip)
    vmovdqu %ymm6,  \sym+192(%rip)
    vmovdqu %ymm7,  \sym+224(%rip)
    vmovdqu %ymm8,  \sym+256(%rip)
    vmovdqu %ymm9,  \sym+288(%rip)
    vmovdqu %ymm10, \sym+320(%rip)
    vmovdqu %ymm11, \sym+352(%rip)
    vmovdqu %ymm12, \sym+384(%rip)
    vmovdqu %ymm13, \sym+416(%rip)
    vmovdqu %ymm14, \sym+448(%rip)
    vmovdqu %ymm15, \sym+480(%rip)
.endm

.macro LOAD_YMM sym
    vmovdqu \sym+0(%rip),   %ymm0
    vmovdqu \sym+32(%rip),  %ymm1
    vmovdqu \sym+64(%rip),  %ymm2
    vmovdqu \sym+96(%rip),  %ymm3
    vmovdqu \sym+128(%rip), %ymm4
    vmovdqu \sym+160(%rip), %ymm5
    vmovdqu \sym+192(%rip), %ymm6
    vmovdqu \sym+224(%rip), %ymm7
    vmovdqu \sym+256(%rip), %ymm8
    vmovdqu \sym+288(%rip), %ymm9
    vmovdqu \sym+320(%rip), %ymm10
    vmovdqu \sym+352(%rip), %ymm11
    vmovdqu \sym+384(%rip), %ymm12
    vmovdqu \sym+416(%rip), %ymm13
    vmovdqu \sym+448(%rip), %ymm14
    vmovdqu \sym+480(%rip), %ymm15
.endm

# rdi = guest gprs (rax..r15, rip, rflags), rsi = fs base, rdx = gs base.
# Does not return until a signal lands on basalt_native_return.
basalt_native_enter:
    push %rbx
    push %rbp
    push %r12
    push %r13
    push %r14
    push %r15
    mov %rsp, basalt_host_rsp(%rip)
    mov %rdi, basalt_gpr(%rip)
    rdfsbase %rax
    mov %rax, basalt_host_fs(%rip)
    rdgsbase %rax
    mov %rax, basalt_host_gs(%rip)
    SAVE_YMM basalt_host_ymm
    movb $1, basalt_in_guest(%rip)
    wrfsbase %rsi
    wrgsbase %rdx
    mov basalt_gpr(%rip), %rdi
    mov 128(%rdi), %rax
    mov %rax, basalt_target(%rip)
    mov 136(%rdi), %rax
    or $2, %rax
    and $~0x100, %rax
    push %rax
    popfq
    LOAD_YMM basalt_guest_ymm
    mov basalt_gpr(%rip), %rax
    mov 8(%rax), %rcx
    mov 16(%rax), %rdx
    mov 32(%rax), %rsp
    mov 40(%rax), %rbp
    mov 48(%rax), %rsi
    mov 64(%rax), %r8
    mov 72(%rax), %r9
    mov 80(%rax), %r10
    mov 88(%rax), %r11
    mov 96(%rax), %r12
    mov 104(%rax), %r13
    mov 112(%rax), %r14
    mov 120(%rax), %r15
    mov 24(%rax), %rbx
    mov 56(%rax), %rdi
    mov 0(%rax), %rax
    movb $1, basalt_syscall_sel(%rip)
    jmp *basalt_target(%rip)

basalt_native_return:
    movb $0, basalt_in_guest(%rip)
    movb $0, basalt_syscall_sel(%rip)
    # The title's SIMD state is still in these registers. Keep it before
    # the host values are put back, including when a signal landed here.
    SAVE_YMM basalt_guest_ymm
    mov basalt_host_rsp(%rip), %rsp
    pop %r15
    pop %r14
    pop %r13
    pop %r12
    pop %rbp
    pop %rbx
    mov basalt_host_fs(%rip), %rax
    wrfsbase %rax
    mov basalt_host_gs(%rip), %rax
    wrgsbase %rax
    LOAD_YMM basalt_host_ymm
    ret

# int, siginfo*, ucontext*. Saves ymm first, then the C handler.
# edi = signal, rdx = ucontext. Copies the guest registers and returns to
# basalt_native_return. No C call: that call was faulting on this stack.
basalt_sig_entry:
    cmpb $0, basalt_in_guest(%rip)
    jne 6f
    # Timer tick while the host is between slices. Ignoring it keeps the
    # guest registers. Any other signal here is a host fault.
    cmp $26, %edi
    je 4f
    jmp host_fault_exit
4:
    ret
6:
    cmp $8, %edi
    jne 8f
    # Integer divide by zero is also SIGFPE. Retrying it never finishes.
    cmpl $2, 8(%rsi)
    jbe 8f
    mov 224(%rdx), %rax
    test %rax, %rax
    jz 8f
    movl 24(%rax), %ecx
    orl $0x1f80, %ecx
    movl %ecx, 24(%rax)
    ret
8:
    movb $0, basalt_syscall_sel(%rip)
    movb $0, basalt_in_guest(%rip)
    mov basalt_regs_ptr(%rip), %rax
    test %rax, %rax
    jz 9f
    # A signal that interrupted this handler must not replace the guest
    # registers with this function's address. A guest jump outside the
    # title is not that case: those registers have to reach the scheduler.
    mov 168(%rdx), %rcx
    lea basalt_sig_entry(%rip), %r11
    cmp %r11, %rcx
    jb 5f
    lea basalt_sig_end(%rip), %r11
    cmp %r11, %rcx
    jae 5f
    ret
5:
    mov 144(%rdx), %rcx
    mov %rcx, 0(%rax)
    mov 152(%rdx), %rcx
    mov %rcx, 8(%rax)
    mov 136(%rdx), %rcx
    mov %rcx, 16(%rax)
    mov 128(%rdx), %rcx
    mov %rcx, 24(%rax)
    mov 160(%rdx), %rcx
    mov %rcx, 32(%rax)
    mov 120(%rdx), %rcx
    mov %rcx, 40(%rax)
    mov 112(%rdx), %rcx
    mov %rcx, 48(%rax)
    mov 104(%rdx), %rcx
    mov %rcx, 56(%rax)
    mov 40(%rdx), %rcx
    mov %rcx, 64(%rax)
    mov 48(%rdx), %rcx
    mov %rcx, 72(%rax)
    mov 56(%rdx), %rcx
    mov %rcx, 80(%rax)
    mov 64(%rdx), %rcx
    mov %rcx, 88(%rax)
    mov 72(%rdx), %rcx
    mov %rcx, 96(%rax)
    mov 80(%rdx), %rcx
    mov %rcx, 104(%rax)
    mov 88(%rdx), %rcx
    mov %rcx, 112(%rax)
    mov 96(%rdx), %rcx
    mov %rcx, 120(%rax)
    mov 168(%rdx), %rcx
    mov %rcx, 128(%rax)
    mov 176(%rdx), %rcx
    mov %rcx, 136(%rax)
    movb $3, basalt_stop(%rip)
    cmp $5, %edi
    jne 1f
    movb $1, basalt_stop(%rip)
1:
    cmp $26, %edi
    jne 2f
    movb $2, basalt_stop(%rip)
2:
    cmp $31, %edi
    jne 3f
    movb $4, basalt_stop(%rip)
3:
    lea basalt_native_return(%rip), %rcx
    mov %rcx, 168(%rdx)
    mov basalt_host_rsp(%rip), %rcx
    mov %rcx, 160(%rdx)
    ret
9:
    jmp host_fault_exit

# edi = signal, rdx = ucontext. One line on stderr, then stop.
host_fault_exit:
    mov %rdx, %r8
    mov %edi, %eax
    mov $10, %ecx
    xor %edx, %edx
    div %ecx
    add $'0', %eax
    add $'0', %edx
    lea hmsg(%rip), %rcx
    mov %al, 13(%rcx)
    mov %dl, 14(%rcx)
    mov 168(%r8), %rax
    lea 36(%rcx), %rdi
    mov $16, %ecx
1:
    dec %rdi
    mov %rax, %rdx
    and $15, %edx
    shr $4, %rax
    cmp $10, %edx
    jb 2f
    add $39, %edx
2:
    add $'0', %edx
    mov %dl, (%rdi)
    dec %ecx
    jnz 1b
    mov $1, %eax
    mov $2, %edi
    lea hmsg(%rip), %rsi
    mov $(hmsg_end - hmsg), %edx
    syscall
    mov $231, %eax
    mov $1, %edi
    syscall
    hlt

.section .data
.align 8
hmsg: .ascii "\n[host] sig=000 rip=0000000000000000\n"
hmsg_end:
.section .text

basalt_sig_end:
