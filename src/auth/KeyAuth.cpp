#include "KeyAuth.h"
#include "embedded_public_key.h"
#include "../core/AntiRE.h" // Required for OBF()

#include <sodium.h>
#include <nlohmann/json.hpp>
#include <vector>
#include <cstring>
#include <cctype>
#include <ctime>

namespace {
    bool Base64UrlDecode(const std::string& in, std::vector<unsigned char>& out) {
        out.clear();
        out.reserve(in.size() * 3 / 4 + 4);
        int val = 0, bits = 0;
        for (char c : in) {
            if (c == '=') break;
            int d;
            if (c >= 'A' && c <= 'Z') d = c - 'A';
            else if (c >= 'a' && c <= 'z') d = c - 'a' + 26;
            else if (c >= '0' && c <= '9') d = c - '0' + 52;
            else if (c == '-')             d = 62;
            else if (c == '_')             d = 63;
            else return false;
            val = (val << 6) | d;
            bits += 6;
            if (bits >= 8) { bits -= 8; out.push_back((unsigned char)(val >> bits)); }
        }
        return true;
    }

    std::vector<std::string> Split(const std::string& s, char sep) {
        std::vector<std::string> r;
        size_t start = 0;
        for (size_t i = 0; i <= s.size(); ++i) {
            if (i == s.size() || s[i] == sep) {
                r.push_back(s.substr(start, i - start));
                start = i + 1;
            }
        }
        return r;
    }

    std::string ExtractToken(const std::string& raw) {
        size_t bestLen = 0;
        std::string best, cur;
        auto flush = [&]() {
            if (cur.size() > bestLen) {
                int dots = 0;
                for (char c : cur) if (c == '.') ++dots;
                if (dots == 3) { best = cur; bestLen = cur.size(); }
            }
            cur.clear();
            };
        for (unsigned char c : raw) {
            if (std::isalnum(c) || c == '.' || c == '-' || c == '_') cur += (char)c;
            else flush();
        }
        flush();
        return best.empty() ? raw : best;
    }
} // namespace

// ==========================================
// NEW: Global Auth Variables
// ==========================================
namespace KeyAuth {
    uint32_t g_authToken = 0;
    constexpr uint32_t kAuthMagic = 0xDEADBEEF;

    bool IsAuthorized() {
        return g_authToken == kAuthMagic;
    }

    bool Verify(const std::string& token, std::string& errorMsg) {
        errorMsg.clear();
        std::string t = ExtractToken(token);

        if (t.empty()) { errorMsg = OBF("No key entered."); return false; }

        auto parts = Split(t, '.');
        if (parts.size() != 4) {
            errorMsg = OBF("Malformed key (expected 4 parts separated by '.').");
            return false;
        }

        std::vector<unsigned char> payload, sig, intPub, cert;
        if (!Base64UrlDecode(parts[0], payload) ||
            !Base64UrlDecode(parts[1], sig) ||
            !Base64UrlDecode(parts[2], intPub) ||
            !Base64UrlDecode(parts[3], cert))
        {
            errorMsg = OBF("Key contains invalid base64 data.");
            return false;
        }

        if (sig.size() != crypto_sign_BYTES) { errorMsg = OBF("Signature size is wrong."); return false; }
        if (intPub.size() != crypto_sign_PUBLICKEYBYTES) { errorMsg = OBF("Intermediate public key size is wrong."); return false; }
        if (cert.size() != crypto_sign_BYTES) { errorMsg = OBF("Certificate size is wrong."); return false; }

        // 1. Verify Certificate (Root -> Intermediate)
        if (crypto_sign_verify_detached(cert.data(), intPub.data(), intPub.size(),
            g_embeddedRootPublicKey) != 0)
        {
            errorMsg = OBF("Certificate invalid - this key was not issued by the official root.");
            return false;
        }

        // 2. Verify Token Signature (Intermediate -> Payload)
        if (crypto_sign_verify_detached(sig.data(), payload.data(), payload.size(),
            intPub.data()) != 0)
        {
            errorMsg = OBF("Signature invalid - the key has been forged or tampered with.");
            return false;
        }

        // 3. Parse Payload & Expiry
        try {
            auto j = nlohmann::json::parse(payload.begin(), payload.end());
            if (!j.contains("exp")) { errorMsg = OBF("Key payload is missing 'exp'."); return false; }
            int64_t exp = j["exp"].get<int64_t>();
            int64_t now = static_cast<int64_t>(time(nullptr));

            if (now > exp + 60) {
                int64_t ageSec = now - exp;
                errorMsg = OBF("Key has expired. Request a fresh one from Discord.");
                return false;
            }
        }
        catch (...) {
            errorMsg = OBF("Key payload is not valid JSON.");
            return false;
        }

        // ==========================================
        // NEW: Key is valid! Unlock the cheat.
        // ==========================================
        g_authToken = kAuthMagic;
        return true;
    }
}