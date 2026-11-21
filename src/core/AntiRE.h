#pragma once
#include <windows.h>
#include <string>
#include <cstdint>

// =====================================================================
// Compile-time String Encryption (XOR)
// =====================================================================
// We use both N (length) and K (line number) as template parameters
// so every line gets its own unique static buffer.
template <uint32_t N, uint32_t K>
class XorString {
    char data[N];
public:
    constexpr XorString(const char* str) {
        for (uint32_t i = 0; i < N; ++i) {
            data[i] = str[i] ^ (K + i);
        }
    }

    const char* decrypt() const {
        // K ensures this buffer is unique per line of code
        static char buf[N];
        for (uint32_t i = 0; i < N; ++i) {
            buf[i] = data[i] ^ (K + i);
        }
        return buf;
    }
};

// __LINE__ is passed as K to make the type unique
#define OBF(str) XorString<sizeof(str), __LINE__>(str).decrypt()

// Add this right below your existing OBF macro
template <uint32_t N, uint32_t K>
class XorWString {
    wchar_t data[N];
public:
    constexpr XorWString(const wchar_t* str) {
        for (uint32_t i = 0; i < N; ++i) data[i] = str[i] ^ (K + i);
    }
    const wchar_t* decrypt() const {
        static wchar_t buf[N];
        for (uint32_t i = 0; i < N; ++i) buf[i] = data[i] ^ (K + i);
        return buf;
    }
};
#define OBF_W(str) XorWString<sizeof(str)/sizeof(wchar_t), __LINE__>(str).decrypt()

namespace AntiRE {
    bool IsDebuggerAttached();
    bool CheckPEB();
}