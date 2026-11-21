#include "Memory.h"
#include "syscalls.h"

#include <iostream>
#include <TlHelp32.h>
#include <windows.h>

#include <vector>
#include <string>
#include <memory>
#include <cstring>
#include <chrono>
#include <algorithm>
#include "AntiRE.h"

// =====================================================================
// Syscall bootstrap
// =====================================================================
static void InitializeSyscalls() {
    g_SsnNtReadVirtualMemory = GetSyscallNumber(OBF("NtReadVirtualMemory"));
    g_SsnNtWriteVirtualMemory = GetSyscallNumber(OBF("NtWriteVirtualMemory"));
    g_SsnNtProtectVirtualMemory = GetSyscallNumber(OBF("NtProtectVirtualMemory"));
    g_SsnNtQueryVirtualMemory = GetSyscallNumber(OBF("NtQueryVirtualMemory"));
}

static std::wstring StringToWString(const std::string& str) {
    if (str.empty()) return std::wstring();
    int size_needed = MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), NULL, 0);
    std::wstring wstrTo(size_needed, 0);
    MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), &wstrTo[0], size_needed);
    return wstrTo;
}

// =====================================================================
// Process / module discovery
// =====================================================================
std::uint32_t memory_t::find_process_id(const std::string& process_name) {
    std::uint32_t local_process_id = 0;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
    if (snapshot == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32W process_entry{};
    process_entry.dwSize = sizeof(PROCESSENTRY32W);
    std::wstring target_process = StringToWString(process_name);

    if (Process32FirstW(snapshot, &process_entry)) {
        do {
            if (_wcsicmp(target_process.c_str(), process_entry.szExeFile) == 0) {
                local_process_id = process_entry.th32ProcessID;
                process_id = local_process_id;
                break;
            }
        } while (Process32NextW(snapshot, &process_entry));
    }
    CloseHandle(snapshot);
    return local_process_id;
}

std::uint64_t memory_t::find_module_address(const std::string& module_name) {
    std::uint64_t module_address = 0;
    if (!process_handle) return 0;

    DWORD pid = GetProcessId(process_handle);
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snapshot == INVALID_HANDLE_VALUE) return 0;

    MODULEENTRY32W module_entry{};
    module_entry.dwSize = sizeof(MODULEENTRY32W);
    std::wstring target_module = StringToWString(module_name);

    if (Module32FirstW(snapshot, &module_entry)) {
        do {
            if (_wcsicmp(target_module.c_str(), module_entry.szModule) == 0) {
                module_address = reinterpret_cast<uint64_t>(module_entry.modBaseAddr);
                base_address = module_address;
                break;
            }
        } while (Module32NextW(snapshot, &module_entry));
    }
    CloseHandle(snapshot);
    return module_address;
}

// =====================================================================
// Attach / detach
// =====================================================================
bool memory_t::attach_to_process(const std::string& process_name) {
    if (process_handle != nullptr && process_handle != INVALID_HANDLE_VALUE) {
        CloseHandle(process_handle);
        process_handle = nullptr;
    }
    writeCache_.clear();

    std::uint32_t pid = find_process_id(process_name);
    if (pid == 0) return false;

    process_handle = OpenProcess(
        PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION,
        FALSE, pid);

    if (process_handle == nullptr || process_handle == INVALID_HANDLE_VALUE) {
        return false;
    }

    find_module_address(process_name);
    InitializeSyscalls();
    return true;
}

void memory_t::Detach() {
    std::lock_guard<std::mutex> lk(writeMutex_);
    if (process_handle != nullptr && process_handle != INVALID_HANDLE_VALUE) {
        CloseHandle(process_handle);
        process_handle = nullptr;
    }
    writeCache_.clear();
    process_id = 0;        // NEW
    base_address = 0;      // NEW
}


// =====================================================================
// NEW: batched raw read — one syscall for N bytes
// =====================================================================
bool memory_t::read_raw(std::uint64_t address, void* buffer, SIZE_T size) {
    if (!process_handle || address == 0 || !buffer || size == 0)
        return false;
    SIZE_T bytesRead = 0;
    intptr_t status = SyscallNtReadVirtualMemory(
        process_handle,
        reinterpret_cast<void*>(address),
        buffer,
        size,
        &bytesRead);
    return status == 0 && bytesRead == size;
}

// =====================================================================
// String reading (MSVC std::string layout)
// =====================================================================
std::string memory_t::read_string(std::uint64_t address) {
    if (!process_handle || address == 0) return {};

    // MSVC std::string layout (x64):
    //   +0x00  _Bx       (union: char[16] inline, or char* heap)
    //   +0x10  _Mysize   (size_t)
    //   +0x18  _Myres    (size_t)
    struct StringHeader {
        std::uint64_t bx0;        // +0x00
        std::uint64_t bx1;        // +0x08
        std::uint64_t size;       // +0x10
        std::uint64_t capacity;   // +0x18
    } hdr{};

    if (!read_raw(address, &hdr, sizeof(hdr))) return {};

    std::int32_t length = static_cast<std::int32_t>(hdr.size);
    if (length <= 0 || length > 256) return {};

    std::uint64_t string_address = (length >= 16) ? hdr.bx0 : address;
    if (string_address == 0) return {};

    std::vector<char> buffer(length + 1, 0);
    if (!read_raw(string_address, buffer.data(), static_cast<SIZE_T>(length)))
        return {};

    return std::string(buffer.data(), static_cast<size_t>(length));
}

// =====================================================================
// Write path — skip read-back verify when we already wrote here recently
// =====================================================================
bool memory_t::write_raw(std::uint64_t address, const void* buffer, SIZE_T size) {
    std::lock_guard<std::mutex> lk(writeMutex_);
    if (!process_handle || address == 0 || !buffer || size == 0)
        return false;

    if (address < 0x10000 || address > 0x7FFFFFFFFFFFULL)
        return false;

    constexpr SIZE_T       kMaxCacheSize = 32;
    constexpr std::int64_t kVerifyIntervalMs = 500;   // same-value skip window
    constexpr std::int64_t kTrustedWriteWindowMs = 1000; // skip read-back after a recent write

    if (writeCache_.size() > 1024) writeCache_.clear();

    const auto nowMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();

    // --- same-value short-circuit + recently-written tracking (NEW) ---
    bool recentlyWritten = false;
    if (size <= kMaxCacheSize) {
        auto it = writeCache_.find(address);
        if (it != writeCache_.end() && it->second.size == size) {
            const std::int64_t ageMs = nowMs - it->second.lastVerifyMs;
            if (std::memcmp(it->second.bytes, buffer, size) == 0
                && ageMs < kVerifyIntervalMs) {
                return true;                              // same value, no-op
            }
            if (ageMs < kTrustedWriteWindowMs) {
                recentlyWritten = true;                   // trust page — skip read-back
            }
        }
    }

    // --- read-back verify (only when we have no recent trust for this addr) ---
    if (!recentlyWritten && size <= kMaxCacheSize) {
        unsigned char current[32];
        SIZE_T readBytes = 0;
        if (SyscallNtReadVirtualMemory(
            process_handle,
            reinterpret_cast<PVOID>(address),
            current, size, &readBytes) == 0
            && readBytes == size
            && std::memcmp(current, buffer, size) == 0)
        {
            auto& rec = writeCache_[address];
            std::memcpy(rec.bytes, buffer, size);
            rec.size = size;
            rec.lastVerifyMs = nowMs;
            return true;
        }
    }

    SIZE_T bytesWritten = 0;
    intptr_t status = SyscallNtWriteVirtualMemory(
        process_handle,
        reinterpret_cast<PVOID>(address),
        const_cast<void*>(buffer),
        size,
        &bytesWritten);

    bool success = (status == 0 && bytesWritten == size);

    if (!success) {
        success = WriteWithProtectFlip(address, buffer, size);
    }

    if (success && size <= kMaxCacheSize) {
        auto& rec = writeCache_[address];
        std::memcpy(rec.bytes, buffer, size);
        rec.size = size;
        rec.lastVerifyMs = nowMs;
    }

    return success;
}

// =====================================================================
// Write path
// =====================================================================
static ULONG ComputeWritableProtection(ULONG current) {
    ULONG base = current & 0xFFUL;
    ULONG modifiers = current & ~0xFFUL;

    ULONG newBase = 0;
    if (base == PAGE_READONLY || base == PAGE_WRITECOPY) {
        newBase = PAGE_READWRITE;
    }
    else if (base == PAGE_EXECUTE ||
        base == PAGE_EXECUTE_READ ||
        base == PAGE_EXECUTE_WRITECOPY) {
        newBase = PAGE_EXECUTE_READWRITE;
    }
    else {
        // Already writable (PAGE_READWRITE / PAGE_EXECUTE_READWRITE),
        // PAGE_NOACCESS, or anything we don't know how to handle.
        return 0;
    }

    return newBase | (modifiers & ~(ULONG)PAGE_GUARD);
}

bool memory_t::WriteWithProtectFlip(std::uint64_t address, const void* buffer, SIZE_T size) {
    constexpr std::uint64_t kPageSize = 0x1000;
    constexpr std::uint64_t kPageMask = kPageSize - 1;

    std::uint64_t pageStart = address & ~kPageMask;
    std::uint64_t pageEnd = (address + size - 1) & ~kPageMask;
    uint64_t      numPages = ((pageEnd - pageStart) / kPageSize) + 1;

    if (numPages == 0 || numPages > 4) return false;

    // Save old protection for EACH page individually. NtProtectVirtualMemory
    // returns a single oldProtect for the whole range; applying that to every
    // page in the range would clobber pages whose protection differs and
    // later crash the target process. This is the crash fix.
    std::vector<ULONG> oldProtects(numPages, 0);
    std::vector<ULONG> newProtects(numPages, 0);

    for (uint64_t i = 0; i < numPages; ++i) {
        uint64_t page = pageStart + i * kPageSize;
        MEMORY_BASIC_INFORMATION mbi{};
        SIZE_T retLen = 0;
        if (SyscallNtQueryVirtualMemory(
            process_handle,
            reinterpret_cast<PVOID>(page),
            0,
            &mbi,
            sizeof(mbi),
            &retLen) != 0)
            return false;

        if (mbi.State != MEM_COMMIT) return false;

        ULONG newProt = ComputeWritableProtection(mbi.Protect);
        if (newProt == 0) return false;

        oldProtects[i] = mbi.Protect;
        newProtects[i] = newProt;
    }

    for (uint64_t i = 0; i < numPages; ++i) {
        uint64_t page = pageStart + i * kPageSize;
        PVOID  base = reinterpret_cast<PVOID>(page);
        SIZE_T psize = kPageSize;
        ULONG  old = 0;

        if (SyscallNtProtectVirtualMemory(
            process_handle, &base, &psize, newProtects[i], &old) != 0)
        {
            for (uint64_t j = 0; j < i; ++j) {
                uint64_t prevPage = pageStart + j * kPageSize;
                PVOID  rbase = reinterpret_cast<PVOID>(prevPage);
                SIZE_T rsize = kPageSize;
                ULONG  dummy = 0;
                SyscallNtProtectVirtualMemory(
                    process_handle, &rbase, &rsize, oldProtects[j], &dummy);
            }
            return false;
        }
    }

    SIZE_T bytesWritten = 0;
    intptr_t status = SyscallNtWriteVirtualMemory(
        process_handle,
        reinterpret_cast<PVOID>(address),
        const_cast<void*>(buffer),
        size,
        &bytesWritten);

    for (uint64_t i = 0; i < numPages; ++i) {
        uint64_t page = pageStart + i * kPageSize;
        PVOID  rbase = reinterpret_cast<PVOID>(page);
        SIZE_T rsize = kPageSize;  
        ULONG  dummy = 0;
        SyscallNtProtectVirtualMemory(
            process_handle, &rbase, &rsize, oldProtects[i], &dummy);
    }

    return status == 0 && bytesWritten == size;
}