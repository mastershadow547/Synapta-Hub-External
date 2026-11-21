#pragma once
#include <windows.h>
#include <cstdint>
#include "AntiRE.h"

extern "C" intptr_t SyscallNtReadVirtualMemory(
    HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer,
    SIZE_T NumberOfBytesToRead, PSIZE_T NumberOfBytesRead);

extern "C" intptr_t SyscallNtWriteVirtualMemory(
    HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer,
    SIZE_T NumberOfBytesToWrite, PSIZE_T NumberOfBytesWritten);

// FIX: second parameter of NtProtectVirtualMemory is PSIZE_T on x64, not PULONG.
// The original code passed a 4-byte ULONG where the kernel read 8 bytes,
// causing the upper 32 bits of the size to be stack garbage.
extern "C" intptr_t SyscallNtProtectVirtualMemory(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T NumberOfBytesToProtect,
    ULONG  NewAccessProtection,
    PULONG OldAccessProtection);

extern "C" intptr_t SyscallNtQueryVirtualMemory(
    HANDLE ProcessHandle,
    PVOID  BaseAddress,
    ULONG  MemoryInformationClass,
    PVOID  Buffer,
    SIZE_T Length,
    PSIZE_T ResultLength);

extern "C" DWORD g_SsnNtReadVirtualMemory;
extern "C" DWORD g_SsnNtWriteVirtualMemory;
extern "C" DWORD g_SsnNtProtectVirtualMemory;
extern "C" DWORD g_SsnNtQueryVirtualMemory;

inline DWORD GetSyscallNumber(const char* funcName) {
    HMODULE hNtdll = GetModuleHandleA(OBF("ntdll.dll"));
    if (!hNtdll) return 0;
    BYTE* funcAddr = reinterpret_cast<BYTE*>(GetProcAddress(hNtdll, funcName));
    if (!funcAddr) return 0;
    for (int i = 0; i < 15; ++i) {
        if (funcAddr[i] == 0xB8) {
            return *reinterpret_cast<DWORD*>(funcAddr + i + 1);
        }   
    }
    return 0;
}