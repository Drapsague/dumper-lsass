EXTERN wNtOpenProcess:DWORD
EXTERN sysAddrNtOpenProcess:QWORD



.CODE  ; To Start the code section

; Need to be commented !!
NtOpenProcess PROC
	mov r10, rcx
	mov eax, wNtOpenProcess
	jmp QWORD PTR [sysAddrNtOpenProcess]
NtOpenProcess ENDP


END
