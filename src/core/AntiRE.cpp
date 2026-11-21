#include "AntiRE.h"
#include <winternl.h>
#pragma comment(lib, "ntdll.lib")

namespace AntiRE {
    bool IsDebuggerAttached() {
        // 1. Standard Windows API check
        if (IsDebuggerPresent()) return true;

        // 2. Remote debugger check
        BOOL isRemote = FALSE;
        CheckRemoteDebuggerPresent(GetCurrentProcess(), &isRemote);
        if (isRemote) return true;

        // 3. PEB Check (Bypasses basic API hooks)
        if (CheckPEB()) return true;

        return false;
    }

    bool CheckPEB() {
#ifdef _WIN64
        PPEB peb = (PPEB)__readgsqword(0x60);
#else
        PPEB peb = (PPEB)__readfsdword(0x30);
#endif
        if (peb->BeingDebugged) return true;

        // Check NtGlobalFlag (Often set when a debugger launches the process)
        DWORD ntGlobalFlag = *(DWORD*)((BYTE*)peb + 0xBC);
        if ((ntGlobalFlag & 0x70) != 0) return true;

        return false;
    }
}