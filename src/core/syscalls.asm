OPTION CASEMAP:NONE

.data
    PUBLIC g_SsnNtReadVirtualMemory
    PUBLIC g_SsnNtWriteVirtualMemory
    PUBLIC g_SsnNtProtectVirtualMemory
    PUBLIC g_SsnNtQueryVirtualMemory
    g_SsnNtReadVirtualMemory     DWORD 0
    g_SsnNtWriteVirtualMemory    DWORD 0
    g_SsnNtProtectVirtualMemory  DWORD 0
    g_SsnNtQueryVirtualMemory    DWORD 0

.code
    PUBLIC SyscallNtReadVirtualMemory
    SyscallNtReadVirtualMemory PROC
        mov r10, rcx
        mov eax, g_SsnNtReadVirtualMemory
        syscall
        ret
    SyscallNtReadVirtualMemory ENDP

    PUBLIC SyscallNtWriteVirtualMemory
    SyscallNtWriteVirtualMemory PROC
        mov r10, rcx
        mov eax, g_SsnNtWriteVirtualMemory
        syscall
        ret
    SyscallNtWriteVirtualMemory ENDP

    PUBLIC SyscallNtProtectVirtualMemory
    SyscallNtProtectVirtualMemory PROC
        mov r10, rcx
        mov eax, g_SsnNtProtectVirtualMemory
        syscall
        ret
    SyscallNtProtectVirtualMemory ENDP

    PUBLIC SyscallNtQueryVirtualMemory
    SyscallNtQueryVirtualMemory PROC
        mov r10, rcx
        mov eax, g_SsnNtQueryVirtualMemory
        syscall
        ret
    SyscallNtQueryVirtualMemory ENDP
END