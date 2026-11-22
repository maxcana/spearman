cmp     qword ptr cs:0x147CA2FA, 0
jne     0x65
push    rax
push    rbx
push    rcx
push    rdx
push    rdi
push    rsi
push    r8
push    r9
push    r10
push    r11
push    r12
push    r13
push    r14
push    r15
push    rbp
mov     rbp, rsp
sub     rsp, 0x4F0
mov    QWORD PTR [rsp+0x8],rcx
mov    QWORD PTR [rsp+0x10],rdx
mov     rcx, rsp
add     rcx, 8
xor     rcx, 0x0FFFFFFFFFFFFFFFF
sub     rsp, 0x4F0
call   0xffffffffffed5130 ; KiUserDispatcher_In_C = the 'AegisVehDispatcher'. VEH handler; calls ProtMem::enter (decrypt) / ProtMem::leave (re-encrypt).
cmp     rax, 0
je     0x28
add     rsp, 0x4F0
add     rsp, 0x4F0
pop     rbp
pop     r15
pop     r14
pop     r13
pop     r12
pop     r11
pop     r10
pop     r9
pop     r8
pop     rsi
pop     rdi
pop     rdx
pop     rcx
pop     rbx
pop     rax
ret