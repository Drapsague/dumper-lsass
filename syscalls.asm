default rel

extern wNtOpenProcess
extern sysAddrNtOpenProcess

global NtOpenProcess

section .text
NtOpenProcess:
    mov r10, rcx
    mov eax, dword [wNtOpenProcess]
    jmp qword [sysAddrNtOpenProcess]
