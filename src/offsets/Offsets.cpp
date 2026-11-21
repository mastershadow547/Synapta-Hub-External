#include "Offsets.h"

#include <windows.h>
#include <winhttp.h>

#include <mutex>
#include <stdexcept>
#include <vector>
#include <fstream>
#include <cctype>
#include <atomic> 
#include <unordered_map>
#include "../core/AntiRE.h"

#pragma comment(lib, "winhttp.lib")

namespace fs = std::filesystem;
using json = nlohmann::json;

// =====================================================================
// HTTP (HTTPS) GET
// =====================================================================
static std::string HttpGet(const wchar_t* host, const wchar_t* path) {
    HINTERNET hSession = WinHttpOpen(
        L"OffsetsClient/1.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) throw std::runtime_error("WinHttpOpen failed");

    WinHttpSetTimeouts(hSession, 5000, 5000, 10000, 10000);

    HINTERNET hConnect = WinHttpConnect(hSession, host, INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (!hConnect) { WinHttpCloseHandle(hSession); throw std::runtime_error("WinHttpConnect failed"); }

    HINTERNET hRequest = WinHttpOpenRequest(
        hConnect, L"GET", path, nullptr, WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
    if (!hRequest) {
        WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession);
        throw std::runtime_error("WinHttpOpenRequest failed");
    }

    if (!WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
        WINHTTP_NO_REQUEST_DATA, 0, 0, 0) ||
        !WinHttpReceiveResponse(hRequest, nullptr)) {
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        throw std::runtime_error("Request failed");
    }

    DWORD status = 0, statusSize = sizeof(status);
    WinHttpQueryHeaders(hRequest,
        WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
        WINHTTP_HEADER_NAME_BY_INDEX, &status, &statusSize, WINHTTP_NO_HEADER_INDEX);

    if (status != 200) {
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        throw std::runtime_error("HTTP " + std::to_string(status));
    }

    std::string body;
    DWORD available = 0;
    while (WinHttpQueryDataAvailable(hRequest, &available) && available > 0) {
        std::vector<char> buf(available);
        DWORD read = 0;
        if (!WinHttpReadData(hRequest, buf.data(), available, &read)) break;
        body.append(buf.data(), read);
    }

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    return body;
}

static std::string Trim(const std::string& s) {
    size_t a = 0, b = s.size();
    while (a < b && std::isspace((unsigned char)s[a])) ++a;
    while (b > a && std::isspace((unsigned char)s[b - 1])) --b;
    return s.substr(a, b - a);
}

static fs::path DefaultCacheDir() {
    wchar_t buf[MAX_PATH];
    DWORD n = GetModuleFileNameW(nullptr, buf, MAX_PATH);
    if (n == 0 || n == MAX_PATH) return fs::current_path();
    return fs::path(buf).parent_path();
}

// =====================================================================
// Internal state
// =====================================================================
namespace {
    struct State {
        std::mutex mtx;
        bool       initialized = false;
        json       data;
    };

    State& S() { static State s; return s; }
    std::atomic<uint32_t> g_offsetsVersion{ 0 };

    struct Cache {
        fs::path versionFile, offsetsFile;

        explicit Cache(const fs::path& dir)
            : versionFile(dir / "offsets.version"),
            offsetsFile(dir / "offsets.json") {
        }

        std::string ReadVersion() const {
            std::ifstream f(versionFile);
            if (!f) return {};
            std::string v; std::getline(f, v);
            return Trim(v);
        }
        void WriteVersion(const std::string& v) const {
            std::ofstream f(versionFile, std::ios::trunc);
            f << v;
        }
        void WriteOffsets(const std::string& b) const {
            std::ofstream f(offsetsFile, std::ios::trunc | std::ios::binary);
            f << b;
        }
        json Load() const {
            std::ifstream f(offsetsFile);
            if (!f) throw std::runtime_error("offsets.json missing");
            return json::parse(f);
        }
    };
}

// =====================================================================
// Public API
// =====================================================================
namespace Offsets {

    static std::string ReadFileText(const fs::path& p) {
        std::ifstream f(p);
        if (!f) return {};
        std::string s((std::istreambuf_iterator<char>(f)),
            std::istreambuf_iterator<char>());
        return s;
    }

    void Initialize(const fs::path& cacheDir, bool forceRefresh) {
        auto& s = S();
        std::lock_guard lk(s.mtx);
        if (s.initialized && !forceRefresh) return;

        fs::path dir = cacheDir.empty() ? DefaultCacheDir() : cacheDir;
        Cache cache(dir);

        // Only hit the version endpoint if our cache is > 30 seconds old.
        auto versionFile = cache.versionFile;
        bool cacheFresh = false;
        if (fs::exists(versionFile)) {
            auto mtime = fs::last_write_time(versionFile);
            auto age = fs::file_time_type::clock::now() - mtime;
            if (age < std::chrono::seconds(30)) cacheFresh = true;
        }

        std::string live, cached;
        if (cacheFresh) {
            live = Trim(ReadFileText(versionFile));
            cached = live;
        }
        else {
            live = Trim(HttpGet(OBF_W(L"offsets.imtheo.lol"), OBF_W(L"/roblox/version")));
            cached = cache.ReadVersion();
        }

        if (forceRefresh || live != cached || !fs::exists(cache.offsetsFile)) {
            std::string body = HttpGet(OBF_W(L"offsets.imtheo.lol"), OBF_W(L"/offsets.json"));
            (void)json::parse(body);          // validate before writing
            cache.WriteOffsets(body);
            cache.WriteVersion(live);
        }

        s.data = cache.Load();
        s.initialized = true;
        g_offsetsVersion.fetch_add(1);
    }

    bool IsInitialized() {
        auto& s = S();
        std::lock_guard lk(s.mtx);
        return s.initialized;
    }

    uintptr_t Get(const char* category, const char* field) {
        if (!category || !field) return 0;

        // Per-thread cache. Cleared automatically when offsets reload.
        thread_local std::unordered_map<std::string, uintptr_t> cache;
        thread_local uint32_t cachedVer = UINT32_MAX;

        const uint32_t curVer = g_offsetsVersion.load(std::memory_order_acquire);
        if (cachedVer != curVer) {
            cache.clear();
            cachedVer = curVer;
        }

        std::string key(category);
        key += '\x1F';
        key += field;

        auto it = cache.find(key);
        if (it != cache.end()) return it->second;

        auto& s = S();
        uintptr_t result = 0;
        if (s.initialized && s.data.contains("Offsets")) {
            const auto& offs = s.data["Offsets"];
            if (offs.contains(category)) {
                const auto& entry = offs[category];
                if (entry.contains(field)) result = entry[field].get<uintptr_t>();
            }
        }
        cache[key] = result;
        return result;
    }

    std::string RobloxVersion() {
        auto& s = S();
        if (!s.initialized) return {};
        return s.data.value("Roblox Version", std::string{});
    }

    int Total() {
        auto& s = S();
        if (!s.initialized) return 0;
        return s.data.value("Total Offsets", 0);
    }


    const json& Raw() {
        return S().data;
    }

} // namespace Offsets