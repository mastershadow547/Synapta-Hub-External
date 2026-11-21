#pragma once
#include <windows.h>
#include <TlHelp32.h>
#include <vector>
#include <string>
#include <memory>
#include <mutex>
#include <unordered_map>
#include "syscalls.h"

class memory_t final {
public:
    memory_t() = default;
    ~memory_t() { Detach(); }

    memory_t(const memory_t&) = delete;
    memory_t& operator=(const memory_t&) = delete;

    std::uint32_t find_process_id(const std::string& process_name);
    std::uint64_t find_module_address(const std::string& module_name);
    bool          attach_to_process(const std::string& process_name);
    void          Detach();

    std::string   read_string(std::uint64_t address);

    template <typename T>
    T read(std::uint64_t address) {
        T buffer{};
        SIZE_T bytesRead = 0;
        if (process_handle && address != 0) {
            SyscallNtReadVirtualMemory(
                process_handle,
                reinterpret_cast<void*>(address),
                &buffer,
                sizeof(T),
                &bytesRead);
        }
        return buffer;
    }

    // ---- NEW: batched raw read, one syscall for N bytes ----
    bool read_raw(std::uint64_t address, void* buffer, SIZE_T size);

    template <typename T, size_t N>
    bool read_array(std::uint64_t address, T(&arr)[N]) {
        return read_raw(address, arr, sizeof(T) * N);
    }

    bool write_raw(std::uint64_t address, const void* buffer, SIZE_T size);

    template <typename T>
    bool write(std::uint64_t address, T value) {
        return write_raw(address, &value, sizeof(T));
    }

    std::uint32_t get_process_id()     const { return process_id; }
    std::uint64_t get_module_address() const { return base_address; }
    HANDLE        get_process_handle() const { return process_handle; }

private:
    bool WriteWithProtectFlip(std::uint64_t address, const void* buffer, SIZE_T size);

    struct WriteRecord {
        unsigned char bytes[32]{};          // <-- was: unsigned char bytes[32];
        SIZE_T        size = 0;
        std::int64_t  lastVerifyMs = 0;
    };

    std::mutex    writeMutex_;              // ← ADD: protects writeCache_ + process_handle lifecycle
    std::uint32_t process_id = 0;
    std::uint64_t base_address = 0;
    HANDLE        process_handle = nullptr;
    std::unordered_map<std::uint64_t, WriteRecord> writeCache_;
};

inline std::unique_ptr<memory_t> memory = std::make_unique<memory_t>();