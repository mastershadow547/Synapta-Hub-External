#pragma once
#include <string>
#include <cstdint>

namespace KeyAuth {
    // The global token that acts as our "unlocked" flag
    extern uint32_t g_authToken;

    // Checks if the cheat is allowed to run
    bool IsAuthorized();

    // The main verification function
    bool Verify(const std::string& token, std::string& errorMsg);
}