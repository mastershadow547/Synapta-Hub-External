#pragma once

#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#define _SILENCE_CXX20_OLD_SHARED_PTR_ATOMIC_SUPPORT_DEPRECATION_WARNING

#include <windows.h>
#include <d3d11.h>
#include <dxgi.h>
#include <winhttp.h>
#include <psapi.h>
#include <string>
#include <vector>
#include <cmath>
#include <algorithm>
#include <unordered_map>
#include <unordered_set>
#include <functional>
#include <chrono>
#include <thread>
#include <fstream>
#include <filesystem>
#include <csignal>
#include <exception>
#include <cstdlib>
#include <cfloat>
#include <cstdio>
#include <cstdarg>
#include <cstring>
#include <ctime>
#include <atomic>
#include <mutex>
#include <imgui.h>
#include <imgui_impl_win32.h>
#include <imgui_impl_dx11.h>
#include <sodium.h>
#include "auth/KeyAuth.h"
#include "offsets/Offsets.h"
#include "core/Memory.h"
#include "sdk/SDK.h"
#include "sdk/instance/InstanceAPI.h"
#include "core/AntiRE.h"

bool Peek(const Process& /*p*/, uintptr_t addr, void* out, SIZE_T sz) {
    return memory->read_raw(addr, out, sz);
}

#pragma comment(lib, "d3d11.lib")
#pragma comment(lib, "dxgi.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "winhttp.lib")
#pragma comment(linker, "/SUBSYSTEM:windows /ENTRY:mainCRTStartup")

// =====================================================================
// InstanceAPI globals
// =====================================================================
static Process g_proc{};
static InstanceConfig g_instanceConfig;
static std::unique_ptr<InstanceAPI> g_instanceAPI;

// =====================================================================
// Crash handling + logging
// =====================================================================
static std::atomic<bool> g_crashActive{ false };
DWORD g_mainThreadId = 0;
static bool g_verboseLog = true;

static std::filesystem::path ExeDir() {
    wchar_t buf[MAX_PATH] = {};
    DWORD n = GetModuleFileNameW(nullptr, buf, MAX_PATH);
    return (n > 0 && n < MAX_PATH) ? std::filesystem::path(buf).parent_path()
        : std::filesystem::path(L".");
}
static std::filesystem::path CrashLogPath() { return ExeDir() / L"crash.txt"; }

static std::ofstream* g_logStream = nullptr;

static void DebugLog(const char* fmt, ...) {
    static std::ofstream s_log;
    static std::once_flag s_once;
    std::call_once(s_once, []() {
        s_log.open(ExeDir() / L"esp_debug.txt", std::ios::trunc);
        g_logStream = &s_log;
        });
    if (!s_log.is_open()) return;
    SYSTEMTIME st; GetLocalTime(&st);
    char body[1024];
    va_list a; va_start(a, fmt); vsnprintf(body, sizeof(body), fmt, a); va_end(a);
    s_log << "[" << st.wHour << ":" << st.wMinute << ":" << st.wSecond << "." << st.wMilliseconds << "] " << body << "\n";
}

static void DebugLogFlush() {
    if (g_logStream && g_logStream->is_open()) g_logStream->flush();
}

static void WriteCrashFile(EXCEPTION_POINTERS* ep, const char* source) {
    if (g_crashActive.exchange(true)) return;
    std::ofstream f(CrashLogPath());
    if (!f.is_open()) return;
    f << "========== CRASH ==========\nSource: " << source << "\n";
    if (ep && ep->ExceptionRecord) {
        f << "Code: 0x" << std::hex << ep->ExceptionRecord->ExceptionCode << "\n";
        f << "Address: 0x" << std::hex << (uintptr_t)ep->ExceptionRecord->ExceptionAddress << "\n";
    }
    if (ep && ep->ContextRecord) {
#ifdef _M_X64
        auto c = ep->ContextRecord;
        f << "RIP: 0x" << std::hex << c->Rip << "  RSP: 0x" << c->Rsp << "\n";
#endif
    }
    f.flush();
    DebugLog("CRASH: %s code=0x%X", source,
        ep && ep->ExceptionRecord ? ep->ExceptionRecord->ExceptionCode : 0u);
}

static LONG WINAPI CrashFilter(EXCEPTION_POINTERS* ep) {
    WriteCrashFile(ep, "Unhandled");
    return EXCEPTION_EXECUTE_HANDLER;
}
static LONG WINAPI VectoredHandler(EXCEPTION_POINTERS* ep) {
    if (GetCurrentThreadId() != g_mainThreadId) {
        HMODULE self = GetModuleHandleW(nullptr);
        MODULEINFO mi{};
        if (self && GetModuleInformation(GetCurrentProcess(), self, &mi, sizeof(mi))) {
            auto base = (uintptr_t)mi.lpBaseOfDll;
            auto addr = (uintptr_t)ep->ExceptionRecord->ExceptionAddress;
            if (addr < base || addr >= base + mi.SizeOfImage)
                return EXCEPTION_CONTINUE_SEARCH;
        }
    }
    return EXCEPTION_CONTINUE_SEARCH;
}
static void OnTerminate() { WriteCrashFile(nullptr, "Terminate"); abort(); }
static void OnPurecall() { WriteCrashFile(nullptr, "Purecall"); _exit(3); }
static void OnInvalidParam(const wchar_t*, const wchar_t*, const wchar_t*, unsigned int, uintptr_t) { WriteCrashFile(nullptr, "InvalidParam"); }
static void OnSigAbrt(int) { WriteCrashFile(nullptr, "SIGABRT"); _exit(3); }

// =====================================================================
// D3D globals
// =====================================================================
static ID3D11Device* g_pd3dDevice = nullptr;
static ID3D11DeviceContext* g_pd3dDeviceContext = nullptr;
static IDXGISwapChain* g_pSwapChain = nullptr;
static ID3D11RenderTargetView* g_mainRenderTargetView = nullptr;
static std::atomic<bool> g_WindowRunning{ true };

// =====================================================================
// Feature state
// =====================================================================
static std::atomic<bool> isAttached{ false };
static bool showMenu = true;
static float g_menuAnim = 0.0f;
static HWND g_overlayHwnd = nullptr;

struct KeyBind { int mod = 0; int key = 0; };
static KeyBind g_menuToggleBind{ 0, VK_OEM_4 };
static KeyBind g_exitBind{ VK_SHIFT, VK_OEM_6 };
enum class BindTarget { None, MenuToggle, Exit };
static BindTarget g_bindTarget = BindTarget::None;
static bool s_prevKeyState[256] = {};
static bool s_prevLMB = false;
static int s_pendingMod = 0;
static uint64_t s_armTime = 0;
static bool s_armed = false;
static constexpr uint64_t kArmGraceMs = 300;
static bool g_menuKeyWas = false, g_exitKeyWas = false;
static bool hideFromRecording = true;

static bool s_gameFocused = true;
static std::chrono::steady_clock::time_point s_lastFocusCheck{};

// ImGui < 1.90 has no ImFont::FontSize — track our baked sizes manually.
// Index 0 = default UI, 1 = small ESP, 2 = medium ESP, 3 = large ESP.
static constexpr float kEspFontSizes[4] = { 13.0f, 18.0f, 26.0f, 34.0f };

// --- ESP ---
static bool espEnabled = true;
static bool showHealthBar = true;
static bool showDistance = true;
static bool showSelfEsp = false;
static bool toggleTeamCheck = false;
static bool useTeamColor = false;
static bool skeletonEnabled = true;
static bool skeletonHeadCircle = true;
static float skeletonThickness = 1.5f;
static float maxDistanceCull = 1000.0f;
static ImVec4 espColor = ImVec4(0.0f, 1.0f, 0.0f, 1.0f);
static ImVec4 espFillColor = ImVec4(0.0f, 0.0f, 0.0f, 0.4f);

// --- Aimbot ---
static bool aimbotEnabled = false;
static bool triggerbotEnabled = false;
static bool showFOV = true;
static float aimbotFOV = 300.0f;
static float aimbotMaxRange = 5000.0f;
static float aimbotSmoothness = 5.0f;
static int triggerbotDelay = 20;
static std::chrono::steady_clock::time_point lastTriggerTime;
static int aimbotKey = VK_RBUTTON;
static int aimbotPriority = 0;
static int aimbotPart = 0;
static bool aimbotSticky = true;
static int aimbotLockTimeMs = 300;
static float aimbotDeadzone = 2.0f;
static float aimbotMaxStep = 40.0f;

struct TargetLock {
    uintptr_t targetAddress = 0;
    std::chrono::steady_clock::time_point acquiredAt{};
};
static TargetLock g_lock;

// --- Dual-character filter ---
enum class DualFilter { CharacterTag, RealPlayerChar, HumanoidAlive, HasHead, ShowAll };
static DualFilter g_dualFilter = DualFilter::CharacterTag;
static int g_dualZeroTicks = 0;

// ---- Offset health check ----
enum class OffsetHealth { Unknown, OK, Stale };
static OffsetHealth g_offsetHealth = OffsetHealth::Unknown;
static bool g_staleOffsetsWarned = false;

// --- Movement ---
static bool flyEnabled = false, noclipEnabled = false;
static float flySpeed = 50.0f;
static float jumpPowerVal = 50.0f;
static float gravityVal = 196.2f;
static bool applyJumpPower = false, applyGravity = false;
static float walkspeedVal = 16.0f;
static bool applyWalkspeed = false;
static bool wasFlying = false, wasNoclipping = false;

static int tickRate = 30; // they can change if they want but better then 60
static std::string cachedJobId;

// ---- Service cache (invalidated on JobId change) ----
struct ServiceCache {
    uintptr_t players = 0;
    uintptr_t workspace = 0;
    uintptr_t teams = 0;
    std::string jobId;
};
static ServiceCache g_serviceCache;

// --- Checkpoints ---
struct Checkpoint { std::string name; Vector3 position = { 0, 0, 0 }; };
static std::vector<Checkpoint> g_checkpoints;
static char g_checkpointNameBuf[64] = { 0 };
static char g_checkpointRenameBuf[64] = { 0 };
static int g_checkpointRenameIdx = -1;
static int g_selectedCheckpointIndex = -1;

static std::int64_t g_currentPlaceId = 0;
static std::int64_t g_currentGameId = 0;

// =====================================================================
// Game-specific constants
// =====================================================================
static constexpr std::int64_t kOperationsSiegePlaceId = 13997018456LL;
static constexpr std::int64_t kOperationsSiegeUniverseId = 4849157113LL;
static constexpr std::int64_t kDualCharacterGameId = 8307114974LL;
static std::int64_t g_operationsSiegeUniverseId = kOperationsSiegeUniverseId;
static bool g_universeIdLookupDone = false;

// =====================================================================
// Universe cache
// =====================================================================
static std::unordered_map<std::int64_t, std::int64_t> g_universeCache;
static bool g_universeCacheDirty = false;

static std::filesystem::path UniverseCachePath() { return ExeDir() / L"universe_cache.json"; }

static void LoadUniverseCache() {
    g_universeCache.clear(); g_universeCacheDirty = false;
    std::ifstream f(UniverseCachePath());
    if (!f.is_open()) return;
    try {
        auto j = nlohmann::json::parse(f);
        for (auto it = j.begin(); it != j.end(); ++it) {
            try {
                std::int64_t pid = std::stoll(it.key());
                std::int64_t uid = it.value().get<std::int64_t>();
                if (pid > 0 && uid > 0) g_universeCache[pid] = uid;
            }
            catch (...) {}
        }
    }
    catch (...) { g_universeCache.clear(); }
}
static void SaveUniverseCache() {
    if (!g_universeCacheDirty) return;
    try {
        nlohmann::json j = nlohmann::json::object();
        for (auto& [p, u] : g_universeCache) j[std::to_string(p)] = u;
        std::ofstream f(UniverseCachePath(), std::ios::trunc);
        if (f.is_open()) { f << j.dump(2); g_universeCacheDirty = false; }
    }
    catch (...) {}
}
static void CacheUniverseId(std::int64_t p, std::int64_t u) {
    if (p <= 0 || u <= 0) return;
    auto it = g_universeCache.find(p);
    if (it != g_universeCache.end() && it->second == u) return;
    g_universeCache[p] = u; g_universeCacheDirty = true; SaveUniverseCache();
}
static std::int64_t GetCachedUniverseId(std::int64_t p) {
    auto it = g_universeCache.find(p);
    return (it != g_universeCache.end()) ? it->second : 0;
}
static inline bool IsMovementBlocked(std::int64_t p, std::int64_t g) noexcept {
    if (p == kOperationsSiegePlaceId) return true;
    if (g_operationsSiegeUniverseId && g == g_operationsSiegeUniverseId) return true;
    if (g == kDualCharacterGameId) return true;
    if (p == kDualCharacterGameId) return true;
    return false;
}

// =====================================================================
// Universe API
// =====================================================================
static std::int64_t FetchUniverseIdFromApi(std::int64_t placeId) {
    if (placeId <= 0) return 0;
    constexpr int kMaxRetries = 2;
    constexpr std::int64_t kMaxWaitPerTryMs = 10000;
    std::int64_t backoffMs = 2000;
    std::wstring path = OBF_W(L"/universes/v1/places/") + std::to_wstring(placeId) + OBF_W(L"/universe");
    for (int attempt = 0; attempt <= kMaxRetries; ++attempt) {
        HINTERNET s = WinHttpOpen(OBF_W(L"OffsetsClient/1.0"), WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
        if (!s) return 0;
        WinHttpSetTimeouts(s, 5000, 5000, 10000, 10000);
        HINTERNET c = WinHttpConnect(s, OBF_W(L"apis.roblox.com"), INTERNET_DEFAULT_HTTPS_PORT, 0);
        if (!c) { WinHttpCloseHandle(s); return 0; }
        HINTERNET r = WinHttpOpenRequest(c, L"GET", path.c_str(), nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
        if (!r) { WinHttpCloseHandle(c); WinHttpCloseHandle(s); return 0; }
        WinHttpAddRequestHeaders(r, L"Accept: application/json", (DWORD)-1L, WINHTTP_ADDREQ_FLAG_ADD);

        DWORD status = 0;
        std::string body;
        bool gotResponse = false;
        DWORD retryAfterSec = 0;
        std::int64_t rateLimitResetEpoch = 0;
        bool haveRetryAfter = false, haveReset = false;

        if (WinHttpSendRequest(r, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0) &&
            WinHttpReceiveResponse(r, nullptr)) {
            gotResponse = true;
            DWORD statusSize = sizeof(status);
            WinHttpQueryHeaders(r, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                WINHTTP_HEADER_NAME_BY_INDEX, &status, &statusSize, WINHTTP_NO_HEADER_INDEX);
            DWORD raSize = sizeof(retryAfterSec);
            if (WinHttpQueryHeaders(r, WINHTTP_QUERY_RETRY_AFTER | WINHTTP_QUERY_FLAG_NUMBER,
                WINHTTP_HEADER_NAME_BY_INDEX, &retryAfterSec, &raSize, WINHTTP_NO_HEADER_INDEX))
                haveRetryAfter = true;
            wchar_t resetBuf[64] = {};
            DWORD resetSize = sizeof(resetBuf);
            if (WinHttpQueryHeaders(r, WINHTTP_QUERY_CUSTOM, L"X-RateLimit-Reset", resetBuf, &resetSize, WINHTTP_NO_HEADER_INDEX)) {
                try { rateLimitResetEpoch = std::stoll(resetBuf); haveReset = true; }
                catch (...) {}
            }
            DWORD avail = 0;
            while (WinHttpQueryDataAvailable(r, &avail) && avail > 0) {
                std::vector<char> buf(avail);
                DWORD read = 0;
                if (!WinHttpReadData(r, buf.data(), avail, &read)) break;
                body.append(buf.data(), read);
            }
        }
        WinHttpCloseHandle(r); WinHttpCloseHandle(c); WinHttpCloseHandle(s);

        if (!gotResponse) {
            std::this_thread::sleep_for(std::chrono::milliseconds(backoffMs));
            backoffMs *= 2; continue;
        }
        if (status == 200) {
            auto pos = body.find("\"universeId\"");
            if (pos != std::string::npos) {
                pos = body.find(':', pos);
                if (pos != std::string::npos) {
                    auto start = body.find_first_of("0123456789", pos);
                    if (start != std::string::npos) {
                        auto end = body.find_first_not_of("0123456789", start);
                        try { return std::stoll(body.substr(start, end - start)); }
                        catch (...) { return 0; }
                    }
                }
            }
            return 0;
        }
        if (status == 429) {
            std::int64_t waitMs = -1;
            if (haveRetryAfter && retryAfterSec > 0) waitMs = static_cast<std::int64_t>(retryAfterSec) * 1000;
            if (waitMs < 0 && haveReset) {
                std::time_t now = std::time(nullptr);
                if (rateLimitResetEpoch > (std::int64_t)now) waitMs = (rateLimitResetEpoch - (std::int64_t)now) * 1000 + 500;
            }
            if (waitMs < 0) waitMs = backoffMs;
            if (waitMs > kMaxWaitPerTryMs) waitMs = kMaxWaitPerTryMs;
            std::this_thread::sleep_for(std::chrono::milliseconds(waitMs));
            backoffMs *= 2; continue;
        }
        return 0;
    }
    return 0;
}

// ---- Async universe fetch ----
static std::atomic<bool>          g_asyncFetchInFlight{ false };
static std::atomic<std::int64_t>  g_asyncFetchResult{ 0 };
static std::atomic<std::int64_t>  g_asyncFetchPlace{ 0 };

static void StartAsyncUniverseFetch(std::int64_t placeId) {
    g_asyncFetchPlace = placeId;
    g_asyncFetchResult = 0;
    g_asyncFetchInFlight = true;
    std::thread([placeId]() {
        std::int64_t f = FetchUniverseIdFromApi(placeId);
        g_asyncFetchPlace = placeId;
        g_asyncFetchResult = (f > 0) ? f : -1;
        g_asyncFetchInFlight = false;
        }).detach();
}

static void ResolveOperationsSiegeUniverseId() {
    if (g_universeIdLookupDone) return;
    g_universeIdLookupDone = true;
    std::int64_t c = GetCachedUniverseId(kOperationsSiegePlaceId);
    if (c > 0) { g_operationsSiegeUniverseId = c; return; }
    if (kOperationsSiegeUniverseId > 0) {
        g_operationsSiegeUniverseId = kOperationsSiegeUniverseId;
        CacheUniverseId(kOperationsSiegePlaceId, kOperationsSiegeUniverseId);
        return;
    }
    std::int64_t fetched = FetchUniverseIdFromApi(kOperationsSiegePlaceId);
    if (fetched > 0) {
        CacheUniverseId(kOperationsSiegePlaceId, fetched);
        g_operationsSiegeUniverseId = fetched;
    }
}

static std::int64_t ForceRefreshUniverseId(std::int64_t placeId) {
    if (placeId <= 0) return 0;
    std::int64_t f = FetchUniverseIdFromApi(placeId);
    if (f > 0) {
        CacheUniverseId(placeId, f);
        if (placeId == kOperationsSiegePlaceId) g_operationsSiegeUniverseId = f;
    }
    return f;
}

// =====================================================================
// Keybind helpers
// =====================================================================
static inline int NormalizeModifier(int vk) noexcept {
    if (vk == VK_SHIFT || vk == VK_LSHIFT || vk == VK_RSHIFT)   return VK_SHIFT;
    if (vk == VK_CONTROL || vk == VK_LCONTROL || vk == VK_RCONTROL) return VK_CONTROL;
    if (vk == VK_MENU || vk == VK_LMENU || vk == VK_RMENU)      return VK_MENU;
    return 0;
}

static const char* VkName(int vk) {
    thread_local char bufs[4][24];
    static thread_local int idx = 0;
    char* b = bufs[idx]; idx = (idx + 1) & 3;
    if (vk >= 'A' && vk <= 'Z') { b[0] = (char)vk; b[1] = 0; return b; }
    if (vk >= '0' && vk <= '9') { b[0] = (char)vk; b[1] = 0; return b; }
    switch (vk) {
    case VK_LBUTTON: return "LMB"; case VK_RBUTTON: return "RMB"; case VK_MBUTTON: return "MMB";
    case VK_XBUTTON1: return "X1"; case VK_XBUTTON2: return "X2";
    case VK_SHIFT: return "Shift"; case VK_CONTROL: return "Ctrl"; case VK_MENU: return "Alt";
    case VK_SPACE: return "Space"; case VK_TAB: return "Tab"; case VK_ESCAPE: return "Esc";
    case VK_RETURN: return "Enter"; case VK_BACK: return "Bksp"; case VK_INSERT: return "Ins";
    case VK_DELETE: return "Del"; case VK_HOME: return "Home"; case VK_END: return "End";
    case VK_PRIOR: return "PgUp"; case VK_NEXT: return "PgDn";
    case VK_LEFT: return "Left"; case VK_RIGHT: return "Right"; case VK_UP: return "Up"; case VK_DOWN: return "Down";
    case VK_OEM_4: return "["; case VK_OEM_6: return "]"; case VK_OEM_1: return ";"; case VK_OEM_2: return "/";
    case VK_OEM_3: return "`"; case VK_OEM_5: return "\\"; case VK_OEM_7: return "'";
    case VK_OEM_PLUS: return "="; case VK_OEM_MINUS: return "-"; case VK_OEM_COMMA: return ","; case VK_OEM_PERIOD: return ".";
    }
    if (vk >= VK_F1 && vk <= VK_F24) { snprintf(b, 24, "F%d", vk - VK_F1 + 1); return b; }
    if (vk >= VK_NUMPAD0 && vk <= VK_NUMPAD9) { snprintf(b, 24, "Num%d", vk - VK_NUMPAD0); return b; }
    snprintf(b, 24, "0x%02X", vk); return b;
}

static void FormatBindLabel(const KeyBind& b, char* out, size_t n) {
    if (!b.key) { snprintf(out, n, "<unbound>"); return; }
    if (b.mod) {
        const char* m = (b.mod == VK_SHIFT) ? "Shift" : (b.mod == VK_CONTROL) ? "Ctrl" : "Alt";
        snprintf(out, n, "%s + %s", m, VkName(b.key));
    }
    else snprintf(out, n, "%s", VkName(b.key));
}

static inline bool IsBindDown(const KeyBind& b) noexcept {
    if (!b.key) return false;
    if (b.mod && !(GetAsyncKeyState(b.mod) & 0x8000)) return false;
    return (GetAsyncKeyState(b.key) & 0x8000) != 0;
}

static void ApplyCaptureProtection(HWND h, bool e) { SetWindowDisplayAffinity(h, e ? WDA_EXCLUDEFROMCAPTURE : WDA_NONE); }

static const char* BindStatusText(BindTarget t) {
    if (g_bindTarget != t) return nullptr;
    if (!s_armed) return "<release all keys...>";
    if (s_pendingMod) return "<press main key (Esc to cancel)>";
    return "<press a key or click (Esc to cancel)>";
}

// =====================================================================
// Process disguise
// =====================================================================
static void DisguiseProcessOnce(const wchar_t* name) {
    wchar_t cur[MAX_PATH]{};
    if (!GetModuleFileNameW(nullptr, cur, MAX_PATH)) return;
    std::filesystem::path src(cur);
    std::filesystem::path dst = src.parent_path() / name;
    if (_wcsicmp(src.filename().c_str(), name) == 0) return;
    std::error_code ec;
    std::filesystem::remove(dst, ec);
    std::filesystem::copy_file(src, dst, ec);
    if (ec) return;
    std::wstring cmd = L"\"" + dst.wstring() + L"\"";
    STARTUPINFOW si{ sizeof(si) }; PROCESS_INFORMATION pi{};
    if (CreateProcessW(nullptr, cmd.data(), nullptr, nullptr, FALSE, 0, nullptr, src.parent_path().c_str(), &si, &pi)) {
        CloseHandle(pi.hProcess); CloseHandle(pi.hThread); Sleep(200); ExitProcess(0);
    }
}

// =====================================================================
// Cached offsets
// =====================================================================
struct CachedOffsets {
    uintptr_t bpPrimitive, primPosition, primSize, primFlags, bpTransparency;
    uintptr_t instNameCont, instClassDesc, instClassName, instChildren, instParent;
    uintptr_t humHealth, humMaxHealth, humWalkSpeed, humWalkCheck, humJumpPower, humUseJumpPow;
    uintptr_t playerTeam, playerLocal, playerModel;
    uintptr_t wsCamera, wsWorld, worldGravity, worldPrims;
    uintptr_t camPosition, camRotation;
    uintptr_t vePointer, veViewMatrix;
    uintptr_t fakeDMPointer, fakeDMReal, dmJobId, dmPlaceId, dmGameId;
    uintptr_t teamColor;
};
static CachedOffsets O{};

static inline uintptr_t Off(const char* cat, const char* f, uintptr_t fallback) {
    uintptr_t v = Offsets::Get(cat, f); return v ? v : fallback;
}
static void PopulateCachedOffsets() {
    O.bpPrimitive = Off("BasePart", "Primitive", 0x178);
    O.primPosition = Off("Primitive", "Position", 0xD4);
    O.primSize = Off("Primitive", "Size", 0x1C4);
    O.primFlags = Off("Primitive", "Flags", 0x1BE);
    O.bpTransparency = Off("BasePart", "Transparency", 0x118);
    O.instNameCont = Off("Instance", "NameContainer", 0x68);
    O.instClassDesc = Off("Instance", "ClassDescriptor", 0x18);
    O.instClassName = Off("Instance", "ClassName", 0x08);
    O.instChildren = Off("Instance", "ChildrenStart", 0x70);
    O.instParent = Off("Instance", "Parent", 0x60);
    O.humHealth = Off("Humanoid", "Health", 0x184);
    O.humMaxHealth = Off("Humanoid", "MaxHealth", 0x19C);
    O.humWalkSpeed = Off("Humanoid", "Walkspeed", 0x1C4);
    O.humWalkCheck = Off("Humanoid", "WalkspeedCheck", 0x39C);
    O.humJumpPower = Off("Humanoid", "JumpPower", 0x198);
    O.humUseJumpPow = Off("Humanoid", "UseJumpPower", 0x1D5);
    O.playerTeam = Off("Player", "Team", 0x2D0);
    O.playerLocal = Off("Player", "LocalPlayer", 0x118);
    O.playerModel = Off("Player", "ModelInstance", 0x290);
    O.wsCamera = Off("Workspace", "CurrentCamera", 0x4A0);
    O.wsWorld = Off("Workspace", "World", 0x3F8);
    O.worldGravity = Off("World", "Gravity", 0x220);
    O.worldPrims = Off("World", "Primitives", 0x2A8);
    O.camPosition = Off("Camera", "Position", 0xE4);
    O.camRotation = Off("Camera", "Rotation", 0xC0);
    O.vePointer = Off("VisualEngine", "Pointer", 0x89DC1A0);
    O.veViewMatrix = Off("VisualEngine", "ViewMatrix", 0x1B0);
    O.fakeDMPointer = Off("FakeDataModel", "Pointer", 0x8F59810);
    O.fakeDMReal = Off("FakeDataModel", "RealDataModel", 0x1F8);
    O.dmJobId = Off("DataModel", "JobId", 0x108);
    O.dmPlaceId = Off("DataModel", "PlaceId", 0x180);
    O.dmGameId = Off("DataModel", "GameId", 0);
    O.teamColor = Off("Team", "TeamColor", 0xA0);
    {
        auto vf = ExeDir() / L"offsets.version";
        if (std::filesystem::exists(vf)) {
            auto age = std::filesystem::file_time_type::clock::now()
                - std::filesystem::last_write_time(vf);
            auto days = std::chrono::duration_cast<std::chrono::hours>(age).count() / 24;
            if (days > 2)
                DebugLog("WARNING: offsets cache is %lld days old", (long long)days);
        }
    }
}

// Verifies live offsets against the attached Roblox process.
static void CheckOffsetHealth() {
    g_offsetHealth = OffsetHealth::Stale;
    if (!memory->get_process_handle()) return;

    uintptr_t base = memory->get_module_address();
    if (!base) { DebugLog("[HEALTH] base=0"); return; }

    uintptr_t fd = memory->read<uintptr_t>(base + O.fakeDMPointer);
    if (!fd) { DebugLog("[HEALTH] STALE: fakeDMPointer=0 (off 0x%llX)", (unsigned long long)O.fakeDMPointer); return; }

    uintptr_t rd = memory->read<uintptr_t>(fd + O.fakeDMReal);
    if (!rd) { DebugLog("[HEALTH] STALE: realDM=0 (off 0x%llX)", (unsigned long long)O.fakeDMReal); return; }

    Instance dm(rd);
    std::string dmCls = dm.GetClass();
    if (dmCls != "DataModel") {
        DebugLog("[HEALTH] STALE: realDM class='%s' (want 'DataModel')", dmCls.c_str());
        return;
    }

    uintptr_t ps = g_serviceCache.players;
    if (!ps) ps = dm.FindFirstChildByClass("Players");
    if (!ps) { DebugLog("[HEALTH] STALE: Players service not found"); return; }

    uintptr_t lp = memory->read<uintptr_t>(ps + O.playerLocal);
    if (lp > 0x10000) {
        std::string lpCls = Instance(lp).GetClass();
        if (lpCls != "Player") {
            DebugLog("[HEALTH] STALE: localPlayer class='%s' (off 0x%llX)",
                lpCls.c_str(), (unsigned long long)O.playerLocal);
            return;
        }
        uintptr_t lm = memory->read<uintptr_t>(lp + O.playerModel);
        if (lm > 0x10000) {
            std::string lmCls = Instance(lm).GetClass();
            if (lmCls != "Model") {
                DebugLog("[HEALTH] STALE: playerModel class='%s' (off 0x%llX)",
                    lmCls.c_str(), (unsigned long long)O.playerModel);
                return;
            }
        }
    }

    g_offsetHealth = OffsetHealth::OK;
    if (g_staleOffsetsWarned) {
        DebugLog("[HEALTH] OK (was stale, now fixed)");
        g_staleOffsetsWarned = false;
    }
}

// =====================================================================
// Checkpoints
// =====================================================================
static std::filesystem::path CheckpointFilePath() {
    if (g_currentPlaceId != 0) return ExeDir() / (L"checkpoints_" + std::to_wstring(g_currentPlaceId) + L".txt");
    return ExeDir() / L"checkpoints.txt";
}
static void SaveCheckpoints() {
    std::ofstream f(CheckpointFilePath(), std::ios::trunc);
    if (!f.is_open()) return;
    for (auto& cp : g_checkpoints) {
        std::string n = cp.name;
        n.erase(std::remove(n.begin(), n.end(), '|'), n.end());
        if (n.empty()) n = "CP";
        f << n << '|' << cp.position.x << '|' << cp.position.y << '|' << cp.position.z << '\n';
    }
}
static void LoadCheckpoints() {
    g_checkpoints.clear();
    std::ifstream f(CheckpointFilePath());
    if (!f.is_open()) return;
    std::string line;
    while (std::getline(f, line)) {
        if (line.empty()) continue;
        auto p1 = line.find('|'); if (p1 == std::string::npos) continue;
        auto p2 = line.find('|', p1 + 1); if (p2 == std::string::npos) continue;
        auto p3 = line.find('|', p2 + 1); if (p3 == std::string::npos) continue;
        try {
            Checkpoint cp;
            cp.name = line.substr(0, p1);
            cp.position.x = std::stof(line.substr(p1 + 1, p2 - p1 - 1));
            cp.position.y = std::stof(line.substr(p2 + 1, p3 - p2 - 1));
            cp.position.z = std::stof(line.substr(p3 + 1));
            if (!cp.name.empty()) g_checkpoints.push_back(cp);
        }
        catch (...) {}
    }
}

static uintptr_t GetLocalHRPAddress() {
    if (!memory->get_process_handle()) return 0;
    uintptr_t p = g_serviceCache.players;
    if (!p) {
        uintptr_t base = memory->get_module_address(); if (!base) return 0;
        uintptr_t fakeDM = memory->read<uintptr_t>(base + O.fakeDMPointer); if (!fakeDM) return 0;
        uintptr_t realDM = memory->read<uintptr_t>(fakeDM + O.fakeDMReal); if (!realDM) return 0;
        p = Instance(realDM).FindFirstChildByClass("Players");
    }
    if (!p) return 0;
    uintptr_t lp = memory->read<uintptr_t>(p + O.playerLocal); if (!lp) return 0;
    uintptr_t ch = memory->read<uintptr_t>(lp + O.playerModel); if (!ch) return 0;
    return Instance(ch).FindFirstChild("HumanoidRootPart");
}

// =====================================================================
// Data structs
// =====================================================================
struct PlayerData {
    uintptr_t playerAddress = 0;
    std::string name = "Unknown";
    Vector3 rootPos = { 0, 0, 0 };
    Vector3 headPos = { 0, 0, 0 };
    float health = 100.0f, maxHealth = 100.0f, distance = 0.0f;
    bool hasSkeleton = false, isR15 = false;
    ImU32 teamColor = 0;
    Vector3 head = { 0, 0, 0 };
    Vector3 upperTorso = { 0, 0, 0 }, lowerTorso = { 0, 0, 0 };
    Vector3 leftUpperArm = { 0, 0, 0 }, leftLowerArm = { 0, 0, 0 }, leftHand = { 0, 0, 0 };
    Vector3 rightUpperArm = { 0, 0, 0 }, rightLowerArm = { 0, 0, 0 }, rightHand = { 0, 0, 0 };
    Vector3 leftUpperLeg = { 0, 0, 0 }, leftLowerLeg = { 0, 0, 0 }, leftFoot = { 0, 0, 0 };
    Vector3 rightUpperLeg = { 0, 0, 0 }, rightLowerLeg = { 0, 0, 0 }, rightFoot = { 0, 0, 0 };
    Vector3 torso = { 0, 0, 0 };
    Vector3 leftArm = { 0, 0, 0 }, rightArm = { 0, 0, 0 }, leftLeg = { 0, 0, 0 }, rightLeg = { 0, 0, 0 };
};
struct CachedPlayerInfo {
    uintptr_t character = 0, hrp = 0, head = 0, humanoid = 0;
    std::string name = "Unknown";
    uintptr_t team = 0;
    uintptr_t hrpPrimitive = 0, headPrimitive = 0;
    uintptr_t upperTorsoPrim = 0, lowerTorsoPrim = 0;
    uintptr_t luaPrim = 0, llaPrim = 0, lhPrim = 0;
    uintptr_t ruaPrim = 0, rlaPrim = 0, rhPrim = 0;
    uintptr_t lulPrim = 0, lllPrim = 0, lfPrim = 0;
    uintptr_t rulPrim = 0, rllPrim = 0, rfPrim = 0;
    uintptr_t torsoPrim = 0, leftArmPrim = 0, rightArmPrim = 0, leftLegPrim = 0, rightLegPrim = 0;
    bool isR15 = false, partsCached = false;
    std::int64_t lastParentCheckMs = 0;
};
struct TeamData { uintptr_t address = 0; std::string name; ImU32 color = 0xFFFFFFFF; };
struct DualModelParts {
    std::unordered_map<std::string, uintptr_t> byName;
    std::unordered_map<std::string, uintptr_t> byClass;
    std::int64_t cachedAtMs = 0;
};

// Reader-only state (single-writer, no locks needed)
static std::unordered_map<uintptr_t, CachedPlayerInfo> playerCache;
static std::unordered_map<uintptr_t, DualModelParts> dualPartsCache;
static std::unordered_map<uintptr_t, TeamData> teamByPtr;
static std::vector<uintptr_t> teamPtrOrder;

// UI-writable, reader-readable (both need mutex)
static std::mutex g_hiddenTeamsMutex;
static std::unordered_set<uintptr_t> g_hiddenTeams;

// =====================================================================
// Snapshot
// =====================================================================
struct Snapshot {
    std::vector<PlayerData> players;
    std::vector<std::pair<uintptr_t, TeamData>> teams;
    std::vector<uintptr_t> teamOrder;
    Matrix4x4 viewMatrix{};
    std::int64_t placeId = 0;
    std::int64_t gameId = 0;
    std::string jobId;
    uintptr_t localPlayer = 0;
    uintptr_t localHRP = 0;
    uintptr_t localHumanoid = 0;
    uint64_t captureMs = 0;
};

static std::shared_ptr<const Snapshot> g_currentSnapshot;
static std::atomic<bool> g_readerBusy{ false };
static std::atomic<bool> g_readerStop{ false };
static std::thread g_readerThread;

// =====================================================================
// Small helpers
// =====================================================================
static inline void SendRelativeMove(int dx, int dy) { if (dx || dy) mouse_event(MOUSEEVENTF_MOVE, (DWORD)dx, (DWORD)dy, 0, 0); }
static inline void SendMouseClick() {
    mouse_event(MOUSEEVENTF_LEFTDOWN, 0, 0, 0, 0);
    std::this_thread::sleep_for(std::chrono::milliseconds(5));
    mouse_event(MOUSEEVENTF_LEFTUP, 0, 0, 0, 0);
}
static inline bool IsMatrixSane(const Matrix4x4& m) {
    for (int i = 0; i < 16; ++i) {
        float v = (&m.m[0][0])[i];
        if (!std::isfinite(v) || fabsf(v) > 1e6f) return false;
    }
    return fabsf(m.m[3][3]) > 1e-6f;
}
static inline uintptr_t GetPrimitivePtr(uintptr_t p) { return p ? memory->read<uintptr_t>(p + O.bpPrimitive) : 0; }
static inline Vector3 ReadPrimitivePos(uintptr_t p) { return p ? memory->read<Vector3>(p + O.primPosition) : Vector3{ 0, 0, 0 }; }

// ---- Per-target velocity tracking for aim prediction ----
struct VelTrack {
    Vector3  pos{};
    Vector3  vel{};
    uint64_t atMs = 0;
};
static std::unordered_map<uintptr_t, VelTrack> g_velTrack;

static Vector3 PredictPos(uintptr_t addr, Vector3 curPos, float predictMs) {
    auto it = g_velTrack.find(addr);
    if (it == g_velTrack.end()) {
        g_velTrack[addr] = { curPos,{ 0,0,0 }, GetTickCount64() };
        return curPos;
    }
    auto& v = it->second;
    uint64_t now = GetTickCount64();
    float dt = (now - v.atMs) / 1000.0f;
    if (dt > 0.001f && dt < 0.5f) {
        Vector3 instVel = {
            (curPos.x - v.pos.x) / dt,
            (curPos.y - v.pos.y) / dt,
            (curPos.z - v.pos.z) / dt
        };
        // EMA smooth — prevents jitter from single-frame position noise
        const float a = 0.4f;
        v.vel.x = v.vel.x * (1 - a) + instVel.x * a;
        v.vel.y = v.vel.y * (1 - a) + instVel.y * a;
        v.vel.z = v.vel.z * (1 - a) + instVel.z * a;
    }
    v.pos = curPos;
    v.atMs = now;

    float s = predictMs / 1000.0f;
    return { curPos.x + v.vel.x * s,
             curPos.y + v.vel.y * s,
             curPos.z + v.vel.z * s };
}

// =====================================================================
// Forward decls
// =====================================================================
extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND, UINT, WPARAM, LPARAM);
static bool CreateDeviceD3D(HWND hWnd);
static void CleanupDeviceD3D();
static void CreateRenderTarget();
static void CleanupRenderTarget();
static LRESULT WINAPI WndProc(HWND, UINT, WPARAM, LPARAM);

static HHOOK g_mouseHook = NULL;
static LRESULT CALLBACK MouseHookProc(int nCode, WPARAM wParam, LPARAM lParam) {
    if (nCode == HC_ACTION && showMenu) {
        if (wParam == WM_MOUSEWHEEL) {
            MSLLHOOKSTRUCT* p = (MSLLHOOKSTRUCT*)lParam;
            ImGuiIO& io = ImGui::GetIO();
            // If the mouse is hovering over the menu, redirect the scroll to ImGui
            if (io.WantCaptureMouse) {
                float wheel = (float)GET_WHEEL_DELTA_WPARAM(p->mouseData) / WHEEL_DELTA;
                io.AddMouseWheelEvent(0.0f, wheel);
                return 1; // Consume the event so Roblox doesn't zoom in/out
            }
        }
    }
    return CallNextHookEx(g_mouseHook, nCode, wParam, lParam);
}

static bool RunKeyAuthModal(HWND hwnd, int sw, int sh) {
    static char keyBuf[4096] = { 0 };
    std::string errorMsg;
    bool verified = false;
    bool shouldQuit = false;
    bool showFail = false;
    bool showSuccess = false;
    std::chrono::steady_clock::time_point failTime{};
    std::chrono::steady_clock::time_point successTime{};
    bool firstFrame = true;

    while (g_WindowRunning.load() && !verified && !shouldQuit) {
        MSG msg;
        while (::PeekMessage(&msg, nullptr, 0, 0, PM_REMOVE)) {
            ::TranslateMessage(&msg); ::DispatchMessage(&msg);
            if (msg.message == WM_QUIT) g_WindowRunning = false;
        }
        if (!g_WindowRunning.load()) break;

        if (firstFrame) {
            SetForegroundWindow(hwnd);
            firstFrame = false;
        }

        ImGui_ImplDX11_NewFrame();
        ImGui_ImplWin32_NewFrame();
        ImGui::NewFrame();

        ImGui::SetNextWindowPos(ImVec2(sw * 0.5f, sh * 0.5f), ImGuiCond_FirstUseEver, ImVec2(0.5f, 0.5f));
        // Set a fixed width (650) so the text box knows exactly how wide it is
        ImGui::SetNextWindowSize(ImVec2(650, 0), ImGuiCond_Always);

        ImGui::Begin(OBF("Authentication Required"), nullptr,
            ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_AlwaysAutoResize);

        if (showSuccess) {
            ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.0f, 1.0f, 0.0f, 1.0f));
            ImGui::Text(OBF("KEY VERIFIED!"));
            ImGui::PopStyleColor();
            ImGui::Spacing();
            ImGui::TextWrapped(OBF("Authentication successful. Loading client..."));

            auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - successTime).count();
            if (elapsed > 1500) verified = true;
        }
        else if (!showFail) {
            ImGui::TextWrapped(OBF("Paste your access key below to unlock the client."));
            ImGui::Spacing();
            ImGui::TextDisabled(OBF("Get the current key from the Discord #keys channel."));
            ImGui::Spacing();

            // -FLT_MIN fills the available window width. Multiline wraps the text automatically.
            ImGui::InputTextMultiline("##key", keyBuf, sizeof(keyBuf), ImVec2(-FLT_MIN, 120));
            ImGui::Spacing();

            if (ImGui::Button(OBF("Verify & Launch"), ImVec2(200, 40))) {
                std::string key(keyBuf);
                key.erase(0, key.find_first_not_of(" \t\r\n"));
                if (!key.empty()) key.erase(key.find_last_not_of(" \t\r\n") + 1);

                errorMsg.clear();
                if (KeyAuth::Verify(key, errorMsg)) {
                    showSuccess = true;
                    successTime = std::chrono::steady_clock::now();
                }
                else {
                    showFail = true;
                    failTime = std::chrono::steady_clock::now();
                }
            }
            ImGui::SameLine();
            if (ImGui::Button(OBF("Exit"), ImVec2(120, 40))) shouldQuit = true;
        }
        else {
            ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1.0f, 0.30f, 0.30f, 1.0f));
            ImGui::Text(OBF("KEY VERIFICATION FAILED"));
            ImGui::PopStyleColor();
            ImGui::Spacing();
            ImGui::TextWrapped(OBF("%s"), errorMsg.c_str());
            ImGui::Spacing();
            ImGui::Separator();
            ImGui::Spacing();

            auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::steady_clock::now() - failTime).count();
            int remaining = 5 - (int)elapsed;
            if (remaining < 0) remaining = 0;

            ImGui::TextWrapped(
                OBF("The application will now close in %d second%s. Please reopen it and try a valid key."),
                remaining, remaining == 1 ? "" : "s");

            if (remaining == 0) shouldQuit = true;
        }

        ImGui::End();
        ImGui::Render();

        LONG_PTR es = GetWindowLongPtr(hwnd, GWL_EXSTYLE);
        if (es & WS_EX_TRANSPARENT) {
            es &= ~WS_EX_TRANSPARENT;
            SetWindowLongPtr(hwnd, GWL_EXSTYLE, es);
        }

        const float clr[4] = { 0, 0, 0, 0 };
        g_pd3dDeviceContext->OMSetRenderTargets(1, &g_mainRenderTargetView, nullptr);
        g_pd3dDeviceContext->ClearRenderTargetView(g_mainRenderTargetView, clr);
        ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());
        g_pSwapChain->Present(1, 0);
    }

    return verified;
}

// =====================================================================
// READER TICK
// =====================================================================
static std::int64_t g_lastIdentityCheckMs = 0;
static std::int64_t g_lastReadTimeMs = 0;
static uintptr_t s_readerLocalChar = 0, s_readerLocalHRP = 0, s_readerLocalHumanoid = 0;
static bool s_readerWasFlying = false, s_readerWasNoclipping = false;

static Snapshot ReaderTick() {
    Snapshot snap;
    snap.captureMs = GetTickCount64();

    const bool needPS = espEnabled || aimbotEnabled || triggerbotEnabled;
    const bool needTS = true;
    const bool needMV = flyEnabled || noclipEnabled || applyJumpPower || applyWalkspeed || applyGravity;
    const bool needLP = needPS || needMV;
    const bool needAP = needLP || needTS;

    std::vector<PlayerData> snapPlayers;
    snapPlayers.reserve(playerCache.size() + 8);

    uintptr_t base = memory->get_module_address();
    uintptr_t fd = memory->read<uintptr_t>(base + O.fakeDMPointer);
    if (!fd) return snap;

    uintptr_t rd = memory->read<uintptr_t>(fd + O.fakeDMReal);
    if (!rd) return snap;

    Instance dm(rd);

    const auto nowMs = snap.captureMs;
    if (nowMs - g_lastIdentityCheckMs >= 1000) {
        g_lastIdentityCheckMs = nowMs;
        CheckOffsetHealth();
        std::int64_t p = memory->read<std::int64_t>(rd + O.dmPlaceId);
        if (p > 0 && p < 1000000000000000LL && p != g_currentPlaceId) {
            g_currentPlaceId = p;
            g_checkpoints.clear(); g_selectedCheckpointIndex = -1; g_checkpointRenameIdx = -1;
            LoadCheckpoints();
            DebugLog("Place: %lld", (long long)p);
        }
        if (O.dmGameId) {
            std::int64_t g = memory->read<std::int64_t>(rd + O.dmGameId);
            if (g > 0 && g < 1000000000000000LL) g_currentGameId = g;
        }
        if (g_currentGameId == 0 && g_currentPlaceId > 0) {
            std::int64_t c = GetCachedUniverseId(g_currentPlaceId);
            if (c > 0) {
                g_currentGameId = c;
            }
            else {
                std::int64_t r = g_asyncFetchResult.load();
                std::int64_t rp = g_asyncFetchPlace.load();
                if (r > 0 && rp == g_currentPlaceId) {
                    CacheUniverseId(rp, r);
                    g_currentGameId = r;
                    g_asyncFetchResult = 0;
                    DebugLog("Universe (async): %lld", (long long)r);
                }
                else if (r == -1 && rp == g_currentPlaceId) {
                    g_asyncFetchResult = 0;
                    DebugLog("Universe fetch FAILED (async)");
                }
                if (!g_asyncFetchInFlight.load() && g_asyncFetchPlace.load() != g_currentPlaceId) {
                    DebugLog("Fetching universe async for %lld", (long long)g_currentPlaceId);
                    StartAsyncUniverseFetch(g_currentPlaceId);
                }
            }
        }
        if (needPS) {
            std::string j = memory->read_string(rd + O.dmJobId);
            if (j != cachedJobId && !j.empty()) {
                playerCache.clear(); dualPartsCache.clear(); teamByPtr.clear(); teamPtrOrder.clear();

                ClearTagCache();
                g_lock.targetAddress = 0; cachedJobId = j;
                s_readerLocalChar = s_readerLocalHRP = s_readerLocalHumanoid = 0;
                DebugLog("JobId: %s", j.c_str());
            }
        }
    }

    const bool mvBlocked = IsMovementBlocked(g_currentPlaceId, g_currentGameId);
    if (mvBlocked && (flyEnabled || noclipEnabled || applyJumpPower || applyWalkspeed || applyGravity))
        flyEnabled = noclipEnabled = applyJumpPower = applyWalkspeed = applyGravity = false;

    if (g_serviceCache.jobId != cachedJobId) {
        g_serviceCache = {};
        g_serviceCache.jobId = cachedJobId;
    }

    uintptr_t ap = 0;
    if (needAP) {
        if (g_serviceCache.players) ap = g_serviceCache.players;
        else { ap = dm.FindFirstChildByClass(OBF("Players")); g_serviceCache.players = ap; }
    }

    uintptr_t aw = 0;
    if (needLP) {
        if (g_serviceCache.workspace) aw = g_serviceCache.workspace;
        else { aw = dm.FindFirstChildByClass(OBF("Workspace")); g_serviceCache.workspace = aw; }
    }

    if (needTS) {
        uintptr_t at = g_serviceCache.teams;
        if (!at) { at = dm.FindFirstChildByClass(OBF("Teams")); g_serviceCache.teams = at; }
        if (at) {
            Instance ts(at);
            for (auto& t : ts.GetChildren()) {
                std::string tn = t.GetName();
                if (tn.empty() || tn == "Unknown") continue;
                ImU32 col = IM_COL32(255, 255, 255, 255);
                if (O.teamColor) {
                    Vector3 cv = memory->read<Vector3>(t.address + O.teamColor);
                    col = IM_COL32((int)(cv.x * 255), (int)(cv.y * 255), (int)(cv.z * 255), 255);
                    if (col == IM_COL32(0, 0, 0, 255)) col = IM_COL32(255, 255, 255, 255);
                }
                if (!teamByPtr.count(t.address)) {
                    teamByPtr[t.address] = { t.address, tn, col };
                    teamPtrOrder.push_back(t.address);
                }
            }
        }
        if (ap && O.playerTeam) {
            Instance ps(ap);
            for (auto& p : ps.GetChildren()) {
                uintptr_t tp = memory->read<uintptr_t>(p.address + O.playerTeam);
                if (tp <= 0x10000) continue;
                if (teamByPtr.count(tp)) continue;
                Instance teamInst(tp);
                std::string tn = teamInst.GetName();
                if (tn.empty() || tn == "Unknown") tn = "Team_" + std::to_string(tp & 0xFFFFF);
                ImU32 col = IM_COL32(255, 255, 255, 255);
                if (O.teamColor) {
                    Vector3 cv = memory->read<Vector3>(tp + O.teamColor);
                    col = IM_COL32((int)(cv.x * 255), (int)(cv.y * 255), (int)(cv.z * 255), 255);
                    if (col == IM_COL32(0, 0, 0, 255)) col = IM_COL32(255, 255, 255, 255);
                }
                TeamData td; td.address = tp; td.name = tn; td.color = col;
                teamByPtr[tp] = td; teamPtrOrder.push_back(tp);
            }
        }
    }

    if (aw) {
        uintptr_t cc = 0;
        Vector3 lpos = { 0, 0, 0 };
        if (flyEnabled || needPS) {
            cc = memory->read<uintptr_t>(aw + O.wsCamera);
            if (cc) {
                Vector3 cp = memory->read<Vector3>(cc + O.camPosition);
                lpos = cp;
            }
        }


        uintptr_t lp = 0, lt = 0, lc = 0, lh = 0, lu = 0;
        if (ap && needLP) {
            lp = memory->read<uintptr_t>(ap + O.playerLocal);
            if (lp) {
                if (O.playerTeam) lt = memory->read<uintptr_t>(lp + O.playerTeam);
                lc = memory->read<uintptr_t>(lp + O.playerModel);
                if (lc != s_readerLocalChar) { s_readerLocalChar = lc; s_readerLocalHRP = s_readerLocalHumanoid = 0; }
                if (lc && !s_readerLocalHRP) {
                    Instance ci(lc);
                    s_readerLocalHRP = ci.FindFirstChild("HumanoidRootPart");
                    s_readerLocalHumanoid = ci.FindFirstChildByClass("Humanoid");
                }
                lh = s_readerLocalHRP; lu = s_readerLocalHumanoid;
                if (lh && needPS) lpos = Instance(lh).GetPosition();
            }
        }

        // ---- Fly ----
        if (!mvBlocked && flyEnabled && lh && cc) {
            uintptr_t cr = cc + O.camRotation;
            float rot[8] = {}; memory->read_raw(cr, rot, sizeof(rot));
            Vector3 fwd = { -rot[2], -rot[4], -rot[6] };
            Vector3 rt = { rot[0], rot[3], rot[7] };
            Vector3 nv = { 0, 0, 0 };
            if (GetAsyncKeyState('W') & 0x8000) { nv.x += fwd.x * flySpeed; nv.y += fwd.y * flySpeed; nv.z += fwd.z * flySpeed; }
            if (GetAsyncKeyState('S') & 0x8000) { nv.x -= fwd.x * flySpeed; nv.y -= fwd.y * flySpeed; nv.z -= fwd.z * flySpeed; }
            if (GetAsyncKeyState('D') & 0x8000) { nv.x += rt.x * flySpeed; nv.y += rt.y * flySpeed; nv.z += rt.z * flySpeed; }
            if (GetAsyncKeyState('A') & 0x8000) { nv.x -= rt.x * flySpeed; nv.y -= rt.y * flySpeed; nv.z -= rt.z * flySpeed; }
            if (GetAsyncKeyState(VK_SPACE) & 0x8000) nv.y += flySpeed;
            if (GetAsyncKeyState(VK_LCONTROL) & 0x8000) nv.y -= flySpeed;
            Instance(lh).SetVelocity(nv);
            s_readerWasFlying = true;
        }
        else if ((!flyEnabled || mvBlocked) && s_readerWasFlying) {
            if (lh) Instance(lh).SetVelocity({ 0, 0, 0 });
            s_readerWasFlying = false;
        }

        // ---- Noclip ----
        if (!mvBlocked && noclipEnabled && lc) {
            if (!s_readerWasNoclipping) {
                for (auto& pt : Instance(lc).GetChildren()) pt.SetCanCollide(false);
                s_readerWasNoclipping = true;
            }
        }
        else if ((!noclipEnabled || mvBlocked) && s_readerWasNoclipping) {
            if (lc) for (auto& pt : Instance(lc).GetChildren()) pt.SetCanCollide(true);
            s_readerWasNoclipping = false;
        }

        // ---- Humanoid / World writes ----
        if (!mvBlocked) {
            if (applyJumpPower && lu) {
                memory->write<float>(lu + O.humJumpPower, jumpPowerVal);
                memory->write<bool>(lu + O.humUseJumpPow, true);
            }
            if (applyWalkspeed && lu) {
                if (O.humWalkSpeed) memory->write<float>(lu + O.humWalkSpeed, walkspeedVal);
                if (O.humWalkCheck) memory->write<float>(lu + O.humWalkCheck, walkspeedVal);
            }
            if (applyGravity && aw) {
                uintptr_t w = memory->read<uintptr_t>(aw + O.wsWorld);
                if (w) memory->write<float>(w + O.worldGravity, gravityVal);
            }
        }

        const bool isDual = (g_currentGameId == kDualCharacterGameId) || (g_currentPlaceId == kDualCharacterGameId);

        // ---- Player scan ----
        if (needPS && ap) {
            const bool readSk = espEnabled && skeletonEnabled;
            const bool readHP = espEnabled && showHealthBar;
            const float sr = aimbotEnabled ? (std::max)(maxDistanceCull, aimbotMaxRange) : maxDistanceCull;
            const float srSq = sr * sr;

            if (isDual && aw) {
                Instance ps(ap);
                Instance ws(aw);

                struct RealCharEntry {
                    std::string name;
                    uintptr_t   playerAddr = 0;
                    uintptr_t   teamPtr = 0;
                };
                std::unordered_map<uintptr_t, RealCharEntry> realChars;
                std::unordered_map<std::string, RealCharEntry> nameToPlayer;
                for (auto& p : ps.GetChildren()) {
                    std::string pn = p.GetName();
                    if (pn.empty() || pn == "Unknown") continue;
                    RealCharEntry e; e.name = pn; e.playerAddr = p.address;
                    e.teamPtr = O.playerTeam ? memory->read<uintptr_t>(p.address + O.playerTeam) : 0;
                    nameToPlayer[pn] = e;
                    uintptr_t ch = memory->read<uintptr_t>(p.address + O.playerModel);
                    if (ch > 0x10000) realChars[ch] = e;
                }

                auto wsChildren = ws.GetChildren();

                std::unordered_set<uintptr_t> taggedModels;
                if (g_dualFilter == DualFilter::CharacterTag && g_instanceAPI) {
                    for (const auto& child : wsChildren) {
                        if (child.GetClass() != "Model") continue;
                        if (g_instanceAPI->HasTag(child.address, "Character"))
                            taggedModels.insert(child.address);
                    }
                }

                int added = 0, iter = 0;
                for (const auto& child : wsChildren) {
                    if (child.GetClass() != "Model") continue;
                    ++iter;
                    auto rcIt = realChars.find(child.address);
                    bool passFilter = false;
                    std::string displayName;

                    if (g_dualFilter == DualFilter::CharacterTag) {
                        if (taggedModels.count(child.address)) {
                            displayName = child.GetName();
                            if (displayName.empty() || displayName == "Unknown") displayName = "Character";
                            passFilter = true;
                        }
                    }
                    else if (g_dualFilter == DualFilter::RealPlayerChar) {
                        if (rcIt != realChars.end()) { passFilter = true; displayName = rcIt->second.name; }
                    }
                    else {
                        displayName = child.GetName();
                        if (displayName.empty() || displayName == "Unknown") continue;
                        if (g_dualFilter == DualFilter::ShowAll) passFilter = true;
                        else {
                            auto parts = child.GetChildren();
                            std::unordered_map<std::string, uintptr_t> bn, bc;
                            for (auto& pt : parts) {
                                std::string n = pt.GetName(), c = pt.GetClass();
                                if (!n.empty() && n != "Unknown") bn[n] = pt.address;
                                if (!c.empty() && c != "Unknown") bc[c] = pt.address;
                            }
                            if (g_dualFilter == DualFilter::HasHead) passFilter = bn.count("Head") > 0;
                            else if (g_dualFilter == DualFilter::HumanoidAlive) {
                                auto it = bc.find("Humanoid");
                                if (it != bc.end()) {
                                    float hp = memory->read<float>(it->second + O.humHealth);
                                    passFilter = (hp > 0.0f && hp < 1e6f && !std::isnan(hp));
                                }
                            }
                        }
                    }

                    if (!passFilter) continue;

                    const RealCharEntry* playerEntry = nullptr;
                    if (rcIt != realChars.end()) playerEntry = &rcIt->second;
                    if (!playerEntry) {
                        auto nit = nameToPlayer.find(displayName);
                        if (nit != nameToPlayer.end()) playerEntry = &nit->second;
                    }

                    if (playerEntry && playerEntry->teamPtr != 0) {
                        std::lock_guard lk(g_hiddenTeamsMutex);
                        if (g_hiddenTeams.count(playerEntry->teamPtr)) continue;
                    }
                    if (toggleTeamCheck && playerEntry && lt != 0 && playerEntry->teamPtr == lt) continue;

                    const std::int64_t partsNowMs = GetTickCount64();
                    DualModelParts* dp = nullptr;
                    auto dpIt = dualPartsCache.find(child.address);
                    if (dpIt != dualPartsCache.end() && partsNowMs - dpIt->second.cachedAtMs < 2000) {
                        dp = &dpIt->second;
                    }
                    else {
                        DualModelParts fresh;
                        for (auto& pt : child.GetChildren()) {
                            std::string n = pt.GetName(), c = pt.GetClass();
                            if (!n.empty() && n != "Unknown") fresh.byName[n] = pt.address;
                            if (!c.empty() && c != "Unknown") fresh.byClass[c] = pt.address;
                        }
                        fresh.cachedAtMs = partsNowMs;
                        auto& slot = dualPartsCache[child.address];
                        slot = std::move(fresh);
                        dp = &slot;
                    }
                    auto& byName = dp->byName;
                    auto& byClass = dp->byClass;
                    auto pn = [&](const char* k) -> uintptr_t { auto i = byName.find(k); return i != byName.end() ? i->second : 0; };
                    auto pc = [&](const char* k) -> uintptr_t { auto i = byClass.find(k); return i != byClass.end() ? i->second : 0; };

                    uintptr_t hrp = pn("HumanoidRootPart");
                    uintptr_t head = pn("Head");
                    uintptr_t hum = pc("Humanoid");
                    if (!hrp) continue;
                    if (!showSelfEsp && s_readerLocalHRP != 0 && hrp == s_readerLocalHRP) continue;

                    Vector3 pos = Instance(hrp).GetPosition();
                    if (pos.x == 0.0f && pos.y == 0.0f && pos.z == 0.0f) continue;

                    float dx = pos.x - lpos.x, dy = pos.y - lpos.y, dz = pos.z - lpos.z;
                    float dSq = dx * dx + dy * dy + dz * dz;
                    if (dSq > srSq) continue;

                    Vector3 hPos = head ? Instance(head).GetPosition() : Vector3{ pos.x, pos.y + 3.2f, pos.z };

                    float hp = 100.0f, mxhp = 100.0f;
                    if (hum) {
                        if (readHP) {
                            struct HP { float h; char pad[0x18 - sizeof(float)]; float mh; };
                            HP v = memory->read<HP>(hum + O.humHealth);
                            hp = v.h; mxhp = v.mh;
                        }
                        else hp = memory->read<float>(hum + O.humHealth);
                        if (hp <= 0.0f || std::isnan(hp) || hp > 1e6f) continue;
                    }

                    PlayerData pd;
                    pd.playerAddress = child.address;
                    pd.name = displayName;
                    pd.rootPos = pos; pd.headPos = hPos; pd.head = hPos;
                    pd.health = hp; pd.maxHealth = mxhp;
                    pd.distance = sqrtf(dSq);
                    pd.hasSkeleton = false; pd.isR15 = false;

                    if (readSk) {
                        auto gp = [&](const char* n) -> Vector3 {
                            uintptr_t a = pn(n); if (!a) return { 0, 0, 0 };
                            uintptr_t pr = GetPrimitivePtr(a);
                            return pr ? ReadPrimitivePos(pr) : Instance(a).GetPosition();
                            };
                        if (byName.count("UpperTorso")) {
                            pd.isR15 = true;
                            pd.upperTorso = gp("UpperTorso"); pd.lowerTorso = gp("LowerTorso");
                            pd.leftUpperArm = gp("LeftUpperArm"); pd.leftLowerArm = gp("LeftLowerArm"); pd.leftHand = gp("LeftHand");
                            pd.rightUpperArm = gp("RightUpperArm"); pd.rightLowerArm = gp("RightLowerArm"); pd.rightHand = gp("RightHand");
                            pd.leftUpperLeg = gp("LeftUpperLeg"); pd.leftLowerLeg = gp("LeftLowerLeg"); pd.leftFoot = gp("LeftFoot");
                            pd.rightUpperLeg = gp("RightUpperLeg"); pd.rightLowerLeg = gp("RightLowerLeg"); pd.rightFoot = gp("RightFoot");
                            pd.hasSkeleton = true;
                        }
                        else if (byName.count("Torso")) {
                            pd.torso = gp("Torso");
                            pd.leftArm = gp("Left Arm"); pd.rightArm = gp("Right Arm");
                            pd.leftLeg = gp("Left Leg"); pd.rightLeg = gp("Right Leg");
                            pd.hasSkeleton = true;
                        }
                    }

                    if (useTeamColor && playerEntry && playerEntry->teamPtr != 0) {
                        auto tit = teamByPtr.find(playerEntry->teamPtr);
                        if (tit != teamByPtr.end()) pd.teamColor = tit->second.color;
                    }

                    snapPlayers.push_back(std::move(pd));
                    ++added;
                }
            }
            else {
                Instance ps(ap);
                std::vector<uintptr_t> seenAddrs;
                seenAddrs.reserve(playerCache.size() + 8);

                for (const auto& player : ps.GetChildren()) {
                    seenAddrs.push_back(player.address);
                    if (!showSelfEsp && lp != 0 && player.address == lp) continue;
                    uintptr_t pTeam = O.playerTeam ? memory->read<uintptr_t>(player.address + O.playerTeam) : 0;
                    if (toggleTeamCheck && lt != 0 && pTeam == lt) continue;
                    if (pTeam != 0) {
                        std::lock_guard lk(g_hiddenTeamsMutex);
                        if (g_hiddenTeams.count(pTeam)) continue;
                    }
                    uintptr_t cc = memory->read<uintptr_t>(player.address + O.playerModel);
                    if (!cc) { playerCache.erase(player.address); continue; }

                    const std::int64_t nowMs2 = (std::int64_t)std::chrono::duration_cast<std::chrono::milliseconds>(
                        std::chrono::steady_clock::now().time_since_epoch()).count();
                    CachedPlayerInfo* cp = nullptr;
                    {
                        auto it = playerCache.find(player.address);
                        if (it != playerCache.end() && it->second.character == cc) {
                            bool valid = false;
                            if (nowMs2 - it->second.lastParentCheckMs <= 1000) valid = true;
                            else {
                                uintptr_t par = memory->read<uintptr_t>(cc + O.instParent);
                                if (par == aw) { valid = true; it->second.lastParentCheckMs = nowMs2; }
                            }
                            if (valid) cp = &it->second;
                        }
                    }
                    if (!cp) {
                        playerCache.erase(player.address);
                        Instance ch(cc);
                        auto kids = ch.GetChildren();
                        std::unordered_map<std::string, uintptr_t> bn, bc;
                        struct H { uint64_t cd; uint64_t pad[9]; uint64_t nc; };
                        for (auto& kid : kids) {
                            H h{};
                            if (!memory->read_raw(kid.address + O.instClassDesc, &h, sizeof(h))) continue;
                            if (h.nc) {
                                std::string n = memory->read_string(h.nc);
                                if (!n.empty() && n != "Unknown") bn.emplace(std::move(n), kid.address);
                            }
                            if (h.cd) {
                                uintptr_t np = memory->read<uintptr_t>(h.cd + O.instClassName);
                                if (np) {
                                    std::string c = memory->read_string(np);
                                    if (!c.empty() && c != "Unknown") bc.emplace(std::move(c), kid.address);
                                }
                            }
                        }
                        auto fn = [&](const char* k) -> uintptr_t { auto i = bn.find(k); return i != bn.end() ? i->second : 0; };
                        auto fc = [&](const char* k) -> uintptr_t { auto i = bc.find(k); return i != bc.end() ? i->second : 0; };
                        uintptr_t pHRP = fn("HumanoidRootPart"), pH = fn("Head"), pHum = fc("Humanoid");
                        if (!pHRP || !pH) continue;
                        uintptr_t par = memory->read<uintptr_t>(cc + O.instParent);
                        if (par != aw) continue;
                        CachedPlayerInfo c;
                        c.character = cc; c.hrp = pHRP; c.head = pH; c.humanoid = pHum;
                        c.name = player.GetName(); c.team = pTeam;
                        c.hrpPrimitive = GetPrimitivePtr(pHRP);
                        c.headPrimitive = GetPrimitivePtr(pH);
                        c.lastParentCheckMs = nowMs2;
                        uintptr_t ut = fn("UpperTorso");
                        if (ut) {
                            c.isR15 = true;
                            c.upperTorsoPrim = GetPrimitivePtr(ut);
                            c.lowerTorsoPrim = GetPrimitivePtr(fn("LowerTorso"));
                            c.luaPrim = GetPrimitivePtr(fn("LeftUpperArm"));
                            c.llaPrim = GetPrimitivePtr(fn("LeftLowerArm"));
                            c.lhPrim = GetPrimitivePtr(fn("LeftHand"));
                            c.ruaPrim = GetPrimitivePtr(fn("RightUpperArm"));
                            c.rlaPrim = GetPrimitivePtr(fn("RightLowerArm"));
                            c.rhPrim = GetPrimitivePtr(fn("RightHand"));
                            c.lulPrim = GetPrimitivePtr(fn("LeftUpperLeg"));
                            c.lllPrim = GetPrimitivePtr(fn("LeftLowerLeg"));
                            c.lfPrim = GetPrimitivePtr(fn("LeftFoot"));
                            c.rulPrim = GetPrimitivePtr(fn("RightUpperLeg"));
                            c.rllPrim = GetPrimitivePtr(fn("RightLowerLeg"));
                            c.rfPrim = GetPrimitivePtr(fn("RightFoot"));
                        }
                        else {
                            uintptr_t t = fn("Torso");
                            if (t) {
                                c.torsoPrim = GetPrimitivePtr(t);
                                c.leftArmPrim = GetPrimitivePtr(fn("Left Arm"));
                                c.rightArmPrim = GetPrimitivePtr(fn("Right Arm"));
                                c.leftLegPrim = GetPrimitivePtr(fn("Left Leg"));
                                c.rightLegPrim = GetPrimitivePtr(fn("Right Leg"));
                            }
                        }
                        c.partsCached = true;
                        auto& ins = playerCache[player.address];
                        ins = std::move(c);
                        cp = &ins;
                    }
                    if (!cp->hrp || !cp->head) continue;

                    float hp = 0, mxhp = 100;
                    if (readHP) {
                        struct HP { float h; char pad[0x18 - sizeof(float)]; float mh; };
                        HP v = memory->read<HP>(cp->humanoid + O.humHealth);
                        if (v.h <= 0 || std::isnan(v.h)) continue;
                        hp = v.h; mxhp = v.mh;
                    }
                    else {
                        hp = memory->read<float>(cp->humanoid + O.humHealth);
                        if (hp <= 0 || std::isnan(hp)) continue;
                    }
                    Vector3 p = cp->hrpPrimitive ? ReadPrimitivePos(cp->hrpPrimitive) : Instance(cp->hrp).GetPosition();
                    float dx = p.x - lpos.x, dy = p.y - lpos.y, dz = p.z - lpos.z;
                    if (dx * dx + dy * dy + dz * dz > srSq) continue;

                    PlayerData pd;
                    pd.playerAddress = player.address;
                    pd.name = cp->name;
                    pd.rootPos = p;
                    pd.headPos = cp->headPrimitive ? ReadPrimitivePos(cp->headPrimitive) : Instance(cp->head).GetPosition();
                    pd.head = pd.headPos;
                    pd.health = hp; pd.maxHealth = mxhp;
                    pd.distance = sqrtf(dx * dx + dy * dy + dz * dz);
                    pd.hasSkeleton = false;
                    if (useTeamColor && pTeam != 0) {
                        auto ti = teamByPtr.find(pTeam);
                        if (ti != teamByPtr.end()) pd.teamColor = ti->second.color;
                    }
                    if (readSk) {
                        pd.hasSkeleton = true; pd.isR15 = cp->isR15;
                        if (cp->isR15) {
                            pd.upperTorso = ReadPrimitivePos(cp->upperTorsoPrim);
                            pd.lowerTorso = ReadPrimitivePos(cp->lowerTorsoPrim);
                            pd.leftUpperArm = ReadPrimitivePos(cp->luaPrim);
                            pd.leftLowerArm = ReadPrimitivePos(cp->llaPrim);
                            pd.leftHand = ReadPrimitivePos(cp->lhPrim);
                            pd.rightUpperArm = ReadPrimitivePos(cp->ruaPrim);
                            pd.rightLowerArm = ReadPrimitivePos(cp->rlaPrim);
                            pd.rightHand = ReadPrimitivePos(cp->rhPrim);
                            pd.leftUpperLeg = ReadPrimitivePos(cp->lulPrim);
                            pd.leftLowerLeg = ReadPrimitivePos(cp->lllPrim);
                            pd.leftFoot = ReadPrimitivePos(cp->lfPrim);
                            pd.rightUpperLeg = ReadPrimitivePos(cp->rulPrim);
                            pd.rightLowerLeg = ReadPrimitivePos(cp->rllPrim);
                            pd.rightFoot = ReadPrimitivePos(cp->rfPrim);
                        }
                        else {
                            pd.torso = ReadPrimitivePos(cp->torsoPrim);
                            pd.leftArm = ReadPrimitivePos(cp->leftArmPrim);
                            pd.rightArm = ReadPrimitivePos(cp->rightArmPrim);
                            pd.leftLeg = ReadPrimitivePos(cp->leftLegPrim);
                            pd.rightLeg = ReadPrimitivePos(cp->rightLegPrim);
                        }
                    }
                    snapPlayers.push_back(pd);
                }

                std::sort(seenAddrs.begin(), seenAddrs.end());

                for (auto it = playerCache.begin(); it != playerCache.end();) {
                    if (!std::binary_search(seenAddrs.begin(), seenAddrs.end(), it->first))
                        it = playerCache.erase(it);
                    else
                        ++it;
                }
            }
        }
    }

    snap.players = std::move(snapPlayers);
    for (auto& [k, v] : teamByPtr) snap.teams.emplace_back(k, v);
    snap.teamOrder = teamPtrOrder;
    snap.viewMatrix = GetViewMatrix();
    snap.placeId = g_currentPlaceId;
    snap.gameId = g_currentGameId;
    snap.jobId = cachedJobId;
    snap.localHRP = s_readerLocalHRP;
    snap.localHumanoid = s_readerLocalHumanoid;
    return snap;
}

// =====================================================================
// READER THREAD
// =====================================================================
static void ReaderLoop() {
    while (!g_readerStop.load() && g_WindowRunning.load()) {

        if (!KeyAuth::IsAuthorized()) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
            continue;
        }

        if (!isAttached.load() || !memory->get_process_handle()) {
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
            continue;
        }
         
        const bool anyFeature = espEnabled || aimbotEnabled || triggerbotEnabled ||
            flyEnabled || noclipEnabled || applyJumpPower ||
            applyWalkspeed || applyGravity;
        const int targetMs = anyFeature
            ? 1000 / std::max(1, tickRate)
            : 100;   // 10 Hz when nothing is on

        const std::int64_t nowMs = GetTickCount64();
        if (nowMs - g_lastReadTimeMs < targetMs) {
            std::this_thread::sleep_for(std::chrono::milliseconds(2));
            continue;
        }
        g_lastReadTimeMs = nowMs;

        g_readerBusy = true;
        try {
            auto snap = std::make_shared<Snapshot>(ReaderTick());
            std::atomic_store_explicit(
                reinterpret_cast<std::shared_ptr<const Snapshot>*>(&g_currentSnapshot),
                std::shared_ptr<const Snapshot>(snap),
                std::memory_order_release);
        }
        catch (...) {
            DebugLog("ReaderTick threw");
        }
        g_readerBusy = false;
    }
}

static void StartReaderThread() {
    if (g_readerThread.joinable()) return;
    g_readerStop = false;
    g_readerThread = std::thread(ReaderLoop);
}

static void StopReaderThread() {
    g_readerStop = true;
    if (g_readerThread.joinable()) g_readerThread.join();
}

static void ApplyModernStyle() {
    ImGuiStyle& s = ImGui::GetStyle();
    s.WindowRounding = 8.0f;
    s.ChildRounding = 6.0f;
    s.FrameRounding = 6.0f;
    s.PopupRounding = 6.0f;
    s.ScrollbarRounding = 8.0f;
    s.GrabRounding = 6.0f;
    s.TabRounding = 6.0f;
    s.WindowPadding = ImVec2(14, 14);
    s.FramePadding = ImVec2(10, 6);
    s.ItemSpacing = ImVec2(8, 7);
    s.ItemInnerSpacing = ImVec2(6, 4);
    s.ScrollbarSize = 12.0f;
    s.GrabMinSize = 10.0f;
    s.WindowBorderSize = 0.0f;
    s.FrameBorderSize = 0.0f;
    s.PopupBorderSize = 1.0f;
    s.TabBorderSize = 0.0f;
    s.WindowTitleAlign = ImVec2(0.0f, 0.5f);
    s.ButtonTextAlign = ImVec2(0.5f, 0.5f);

    ImVec4* c = s.Colors;
    const ImVec4 bg = ImVec4(0.07f, 0.08f, 0.10f, 0.97f);
    const ImVec4 bg2 = ImVec4(0.11f, 0.12f, 0.15f, 1.00f);
    const ImVec4 accent = ImVec4(0.36f, 0.62f, 1.00f, 1.00f);
    const ImVec4 accentD = ImVec4(0.24f, 0.42f, 0.72f, 1.00f);
    const ImVec4 text = ImVec4(0.91f, 0.93f, 0.96f, 1.00f);
    const ImVec4 textDim = ImVec4(0.52f, 0.56f, 0.63f, 1.00f);

    c[ImGuiCol_Text] = text;
    c[ImGuiCol_TextDisabled] = textDim;
    c[ImGuiCol_WindowBg] = bg;
    c[ImGuiCol_ChildBg] = ImVec4(0, 0, 0, 0.18f);
    c[ImGuiCol_PopupBg] = bg;
    c[ImGuiCol_Border] = ImVec4(0.18f, 0.20f, 0.26f, 0.6f);
    c[ImGuiCol_FrameBg] = bg2;
    c[ImGuiCol_FrameBgHovered] = ImVec4(0.17f, 0.19f, 0.23f, 1);
    c[ImGuiCol_FrameBgActive] = ImVec4(0.20f, 0.23f, 0.28f, 1);
    c[ImGuiCol_TitleBg] = ImVec4(0.05f, 0.06f, 0.08f, 1);
    c[ImGuiCol_TitleBgActive] = ImVec4(0.09f, 0.10f, 0.13f, 1);
    c[ImGuiCol_TitleBgCollapsed] = ImVec4(0.05f, 0.06f, 0.08f, 1);
    c[ImGuiCol_MenuBarBg] = bg2;
    c[ImGuiCol_ScrollbarBg] = ImVec4(0, 0, 0, 0.15f);
    c[ImGuiCol_ScrollbarGrab] = ImVec4(0.28f, 0.31f, 0.38f, 1);
    c[ImGuiCol_ScrollbarGrabHovered] = ImVec4(0.36f, 0.40f, 0.48f, 1);
    c[ImGuiCol_ScrollbarGrabActive] = accentD;
    c[ImGuiCol_CheckMark] = accent;
    c[ImGuiCol_SliderGrab] = accent;
    c[ImGuiCol_SliderGrabActive] = ImVec4(0.55f, 0.75f, 1, 1);
    c[ImGuiCol_Button] = ImVec4(0.18f, 0.20f, 0.26f, 1);
    c[ImGuiCol_ButtonHovered] = accentD;
    c[ImGuiCol_ButtonActive] = accent;
    c[ImGuiCol_Header] = ImVec4(0.18f, 0.20f, 0.26f, 1);
    c[ImGuiCol_HeaderHovered] = accentD;
    c[ImGuiCol_HeaderActive] = accent;
    c[ImGuiCol_Separator] = ImVec4(0.18f, 0.20f, 0.26f, 0.6f);
    c[ImGuiCol_SeparatorHovered] = accentD;
    c[ImGuiCol_SeparatorActive] = accent;
    c[ImGuiCol_ResizeGrip] = ImVec4(0, 0, 0, 0);
    c[ImGuiCol_Tab] = ImVec4(0.09f, 0.10f, 0.13f, 1);
    c[ImGuiCol_TabHovered] = accentD;
    c[ImGuiCol_TabActive] = ImVec4(0.20f, 0.23f, 0.28f, 1);
    c[ImGuiCol_TabUnfocused] = ImVec4(0.09f, 0.10f, 0.13f, 1);
    c[ImGuiCol_TabUnfocusedActive] = ImVec4(0.15f, 0.17f, 0.21f, 1);
    c[ImGuiCol_TextSelectedBg] = ImVec4(accent.x, accent.y, accent.z, 0.35f);
    c[ImGuiCol_DragDropTarget] = accent;
    c[ImGuiCol_NavHighlight] = accent;
    c[ImGuiCol_ModalWindowDimBg] = ImVec4(0, 0, 0, 0.5f);
}

// =====================================================================
// Config save / load
// =====================================================================
static std::filesystem::path ConfigPath() { return ExeDir() / L"config.json"; }

static void SaveConfig() {
    nlohmann::json j;

    // --- ESP ---
    j["esp"] = {
        { "enabled",     espEnabled },
        { "health",      showHealthBar },
        { "distance",    showDistance },
        { "self",        showSelfEsp },
        { "teamCheck",   toggleTeamCheck },
        { "teamColor",   useTeamColor },
        { "skeleton",    skeletonEnabled },
        { "headCircle",  skeletonHeadCircle },
        { "thickness",   skeletonThickness },
        { "maxDist",     maxDistanceCull },
        { "color",{ espColor.x, espColor.y, espColor.z, espColor.w } },
        { "fill",{ espFillColor.x, espFillColor.y, espFillColor.z, espFillColor.w } }
    };

    // --- Aimbot / Trigger ---
    j["aim"] = {
    { "enabled",      aimbotEnabled },
    { "trigger",      triggerbotEnabled },
    { "showFov",      showFOV },
    { "fov",          aimbotFOV },
    { "range",        aimbotMaxRange },
    { "smooth",       aimbotSmoothness },
    { "key",          aimbotKey },
    { "part",         aimbotPart },
    { "priority",     aimbotPriority },
    { "sticky",       aimbotSticky },
    { "lockMs",       aimbotLockTimeMs },
    { "deadzone",     aimbotDeadzone },
    { "maxStep",      aimbotMaxStep },
    { "triggerDelay", triggerbotDelay }
    };

    // --- Movement ---
    j["move"] = {
        { "fly",          flyEnabled },
        { "noclip",       noclipEnabled },
        { "flySpeed",     flySpeed },
        { "jumpPower",    jumpPowerVal },
        { "applyJump",    applyJumpPower },
        { "walkSpeed",    walkspeedVal },
        { "applyWalk",    applyWalkspeed },
        { "gravity",      gravityVal },
        { "applyGravity", applyGravity }
    };

    // --- UI / Binds ---
    j["ui"] = {
        { "tickRate",    tickRate },
        { "menuKey",     g_menuToggleBind.key },
        { "menuMod",     g_menuToggleBind.mod },
        { "exitKey",     g_exitBind.key },
        { "exitMod",     g_exitBind.mod },
        { "hideCapture", hideFromRecording },
        { "dualFilter",  (int)g_dualFilter }
    };

    std::ofstream f(ConfigPath());
    if (f) f << j.dump(2);
}

static void LoadConfig() {
    std::ifstream f(ConfigPath());
    if (!f) return;
    try {
        auto j = nlohmann::json::parse(f);

        auto E = j.value("esp", nlohmann::json::object());
        espEnabled = E.value("enabled", espEnabled);
        showHealthBar = E.value("health", showHealthBar);
        showDistance = E.value("distance", showDistance);
        showSelfEsp = E.value("self", showSelfEsp);
        toggleTeamCheck = E.value("teamCheck", toggleTeamCheck);
        useTeamColor = E.value("teamColor", useTeamColor);
        skeletonEnabled = E.value("skeleton", skeletonEnabled);
        skeletonHeadCircle = E.value("headCircle", skeletonHeadCircle);
        skeletonThickness = E.value("thickness", skeletonThickness);
        maxDistanceCull = E.value("maxDist", maxDistanceCull);
        if (E.contains("color") && E["color"].size() == 4) {
            const auto& c = E["color"];
            espColor = ImVec4(c[0].get<float>(), c[1].get<float>(),
                c[2].get<float>(), c[3].get<float>());
        }
        if (E.contains("fill") && E["fill"].size() == 4) {
            const auto& c = E["fill"];
            espFillColor = ImVec4(c[0].get<float>(), c[1].get<float>(),
                c[2].get<float>(), c[3].get<float>());
        }

        auto A = j.value("aim", nlohmann::json::object());
        aimbotEnabled = A.value("enabled", aimbotEnabled);
        triggerbotEnabled = A.value("trigger", triggerbotEnabled);
        showFOV = A.value("showFov", showFOV);
        aimbotFOV = A.value("fov", aimbotFOV);
        aimbotMaxRange = A.value("range", aimbotMaxRange);
        aimbotSmoothness = A.value("smooth", aimbotSmoothness);
        aimbotKey = A.value("key", aimbotKey);
        aimbotPart = A.value("part", aimbotPart);
        aimbotPriority = A.value("priority", aimbotPriority);
        aimbotSticky = A.value("sticky", aimbotSticky);
        aimbotLockTimeMs = A.value("lockMs", aimbotLockTimeMs);
        aimbotDeadzone = A.value("deadzone", aimbotDeadzone);
        aimbotMaxStep = A.value("maxStep", aimbotMaxStep);
        triggerbotDelay = A.value("triggerDelay", triggerbotDelay);

        auto M = j.value("move", nlohmann::json::object());
        flyEnabled = M.value("fly", flyEnabled);
        noclipEnabled = M.value("noclip", noclipEnabled);
        flySpeed = M.value("flySpeed", flySpeed);
        jumpPowerVal = M.value("jumpPower", jumpPowerVal);
        applyJumpPower = M.value("applyJump", applyJumpPower);
        walkspeedVal = M.value("walkSpeed", walkspeedVal);
        applyWalkspeed = M.value("applyWalk", applyWalkspeed);
        gravityVal = M.value("gravity", gravityVal);
        applyGravity = M.value("applyGravity", applyGravity);

        auto U = j.value("ui", nlohmann::json::object());
        tickRate = U.value("tickRate", tickRate);
        g_menuToggleBind.key = U.value("menuKey", g_menuToggleBind.key);
        g_menuToggleBind.mod = U.value("menuMod", g_menuToggleBind.mod);
        g_exitBind.key = U.value("exitKey", g_exitBind.key);
        g_exitBind.mod = U.value("exitMod", g_exitBind.mod);
        hideFromRecording = U.value("hideCapture", hideFromRecording);
        g_dualFilter = (DualFilter)U.value("dualFilter", (int)g_dualFilter);
    }
    catch (...) { /* malformed file → keep defaults */ }
}

// =====================================================================
// MAIN
// =====================================================================
int main() {
    wchar_t disguiseName[] = { 'R','u','n','t','i','m','e','B','r','o','k','e','r','.','e','x','e', 0 };
    DisguiseProcessOnce(disguiseName);
    g_mainThreadId = GetCurrentThreadId();
    SetUnhandledExceptionFilter(CrashFilter);
    AddVectoredExceptionHandler(1, VectoredHandler);
    std::set_terminate(OnTerminate);
    _set_invalid_parameter_handler(OnInvalidParam);
    _set_purecall_handler(OnPurecall);
    signal(SIGABRT, OnSigAbrt);

    if (AntiRE::IsDebuggerAttached()) {
        // Silently hang for 5 seconds so the debugger thinks it's loading,
        // then forcefully exit without showing the auth screen or menu.
        Sleep(5000);
        return 1;
    }

    // ---- 1. Create Window & D3D/ImGui Context (Needed for Auth UI) ----
    WNDCLASSEXW wc = {
        sizeof(wc), CS_CLASSDC, WndProc, 0L, 0L, GetModuleHandle(nullptr),
        nullptr, nullptr, nullptr, nullptr, L"ExternalGUI", nullptr
    };
    ::RegisterClassExW(&wc);
    HWND hwnd = ::CreateWindowExW(
        WS_EX_LAYERED | WS_EX_TOOLWINDOW | WS_EX_TOPMOST, // Removed NOACTIVATE
        wc.lpszClassName, L"Runtime Broker", WS_POPUP, 0, 0,
        GetSystemMetrics(SM_CXSCREEN), GetSystemMetrics(SM_CYSCREEN),
        nullptr, nullptr, wc.hInstance, nullptr);
    g_overlayHwnd = hwnd;
    const int g_screenW = GetSystemMetrics(SM_CXSCREEN);
    const int g_screenH = GetSystemMetrics(SM_CYSCREEN);
    if (!CreateDeviceD3D(hwnd)) { CleanupDeviceD3D(); return 1; }
    SetLayeredWindowAttributes(hwnd, RGB(0, 0, 0), 0, LWA_COLORKEY);
    ApplyCaptureProtection(hwnd, hideFromRecording);
    ::ShowWindow(hwnd, SW_SHOWDEFAULT);
    ::UpdateWindow(hwnd);

    IMGUI_CHECKVERSION(); ImGui::CreateContext();

    // ---- Bake 4 fixed font sizes (one per ESP "scale bucket") ----
    {
        ImGuiIO& io = ImGui::GetIO();
        ImFontConfig cfg;
        cfg.OversampleH = 1;      // halves atlas size vs default
        cfg.OversampleV = 1;
        cfg.PixelSnapH = true;

        for (int i = 0; i < 4; ++i) {
            cfg.SizePixels = kEspFontSizes[i];
            io.Fonts->AddFontDefault(&cfg);
        }
    }

    ApplyModernStyle();

    ImGui_ImplWin32_Init(hwnd);
    ImGui_ImplDX11_Init(g_pd3dDevice, g_pd3dDeviceContext);

    // ---- 2. Check Key System ----
    if (sodium_init() < 0) {
        MessageBoxA(nullptr, "Failed to initialize libsodium.", "Fatal", MB_ICONERROR | MB_OK);
        return 1;
    }

    if (!RunKeyAuthModal(hwnd, g_screenW, g_screenH)) {
        // Auth failed or user clicked exit. Shut down cleanly.
        ImGui_ImplDX11_Shutdown();
        ImGui_ImplWin32_Shutdown();
        ImGui::DestroyContext();
        CleanupDeviceD3D();
        ::DestroyWindow(hwnd);
        ::UnregisterClassW(wc.lpszClassName, wc.hInstance);
        return 1;
    }

    // ---- 3. Auth Passed! Load Offsets and Start Cheat ----

      // Apply NOACTIVATE so the game NEVER loses focus when clicking the menu
    LONG_PTR exStyle = GetWindowLongPtr(hwnd, GWL_EXSTYLE);
    exStyle |= WS_EX_NOACTIVATE;
    SetWindowLongPtr(hwnd, GWL_EXSTYLE, exStyle);

    // Mouse hook is installed/uninstalled dynamically based on menu visibility
   // to avoid system-wide mouse latency when the menu is closed.
    g_mouseHook = NULL;


    try { Offsets::Initialize(); }
    catch (...) { DebugLog("Offsets::Initialize threw"); return 1; }
    PopulateCachedOffsets();
    LoadCustomOffsets(ExeDir() / L"custom_offsets.json");
    LoadUniverseCache();
    ResolveOperationsSiegeUniverseId();
    LoadCheckpoints();

    {
        auto jsonPath = ExeDir() / L"custom_offsets_version-5a21b87bbc2641cf.json";
        std::string narrow = jsonPath.string();
        if (g_instanceConfig.Load(narrow)) {
            g_proc.h = memory->get_process_handle();
            g_proc.pid = memory->get_process_id();
            g_proc.base = memory->get_module_address();
            g_instanceAPI = std::make_unique<InstanceAPI>(g_proc, g_instanceConfig);
            DebugLog("InstanceAPI loaded: ver=%s compMap=0x%llX attrSize=0x%llX",
                g_instanceConfig.RobloxVersion().c_str(),
                (unsigned long long)g_instanceConfig.ComponentMap(),
                (unsigned long long)g_instanceConfig.AttrSize());
        }
        else {
            DebugLog("InstanceAPI FAILED to load JSON (path=%s)", narrow.c_str());
        }
    }

    DebugLog("=== STARTUP ===");
    DebugLog("exe=%ls", ExeDir().c_str());
    DebugLog("O.fakeDMPointer=0x%llX playerLocal=0x%llX playerModel=0x%llX dmGameId=0x%llX bpTransparency=0x%llX",
        (unsigned long long)O.fakeDMPointer, (unsigned long long)O.playerLocal,
        (unsigned long long)O.playerModel, (unsigned long long)O.dmGameId,
        (unsigned long long)O.bpTransparency);

    bool lastCaptureMouse = false;
    auto lastHeartbeat = std::chrono::steady_clock::now();

    LoadConfig();
    ApplyCaptureProtection(g_overlayHwnd, hideFromRecording);

    StartReaderThread();

    while (g_WindowRunning.load()) {
        MSG msg;
        while (::PeekMessage(&msg, nullptr, 0, 0, PM_REMOVE)) {
            ::TranslateMessage(&msg); ::DispatchMessage(&msg);
            if (msg.message == WM_QUIT) g_WindowRunning = false;
        }
        if (!g_WindowRunning.load()) break;

        // ---- Keybind capture ----
        if (g_bindTarget != BindTarget::None) {
            bool curState[256] = {};
            int anyDown = 0;
            for (int vk = 1; vk < 256; ++vk) {
                if (vk == VK_LBUTTON) continue;
                if (GetAsyncKeyState(vk) & 0x8000) { curState[vk] = true; ++anyDown; }
            }
            const bool lmbCur = (GetAsyncKeyState(VK_LBUTTON) & 0x8000) != 0;
            if (lmbCur) ++anyDown;
            uint64_t nowMs = GetTickCount64();
            if (!s_armed) {
                if (anyDown == 0) {
                    if (!s_armTime) s_armTime = nowMs;
                    else if (nowMs - s_armTime >= kArmGraceMs) {
                        s_armed = true; s_armTime = 0;
                        memcpy(s_prevKeyState, curState, sizeof(curState));
                        s_prevLMB = lmbCur;
                    }
                }
                else s_armTime = 0;
            }
            else {
                int newMain = 0, newMod = 0;
                for (int vk = 1; vk < 256; ++vk) {
                    if (vk == VK_LBUTTON) continue;
                    if (!curState[vk] || s_prevKeyState[vk]) continue;
                    int m = NormalizeModifier(vk);
                    if (m) { if (!newMod) newMod = m; }
                    else { if (!newMain) newMain = vk; }
                }
                const bool newLMB = lmbCur && !s_prevLMB;
                memcpy(s_prevKeyState, curState, sizeof(curState));
                s_prevLMB = lmbCur;
                const int captured = newLMB ? VK_LBUTTON : newMain;
                const int capMod = newMod;
                if (!captured && capMod) s_pendingMod = capMod;
                else if (captured) {
                    int finalMod = 0;
                    if (capMod) finalMod = capMod;
                    else if (s_pendingMod && (GetAsyncKeyState(s_pendingMod) & 0x8000)) finalMod = s_pendingMod;
                    if (captured == VK_ESCAPE && !finalMod) g_bindTarget = BindTarget::None;
                    else {
                        KeyBind& dst = (g_bindTarget == BindTarget::MenuToggle) ? g_menuToggleBind : g_exitBind;
                        dst.mod = finalMod; dst.key = captured; g_bindTarget = BindTarget::None;
                    }
                    s_armed = false; s_armTime = 0; s_pendingMod = 0;
                }
                else if (s_pendingMod && !(GetAsyncKeyState(s_pendingMod) & 0x8000)) s_pendingMod = 0;
            }
        }
        else {
            bool mn = IsBindDown(g_menuToggleBind);
            if (mn && !g_menuKeyWas) {
                showMenu = !showMenu;
            }
            g_menuKeyWas = mn;
            bool ex = IsBindDown(g_exitBind);
            if (ex && !g_exitKeyWas) { g_WindowRunning = false; break; }
            g_exitKeyWas = ex;
        }

        // ---- Install/uninstall the mouse hook based on menu state ----
        // When menu is closed, the hook does nothing but still adds up to 16ms
        // of delay to every mouse event on the system. So keep it uninstalled
        // while the menu is hidden.
        if (showMenu && g_mouseHook == NULL) {
            g_mouseHook = SetWindowsHookEx(WH_MOUSE_LL, MouseHookProc,
                GetModuleHandle(NULL), 0);
        }
        else if (!showMenu && g_mouseHook != NULL) {
            UnhookWindowsHookEx(g_mouseHook);
            g_mouseHook = NULL;
        }

        // ---- process liveness ----
        if (isAttached.load()) {
            DWORD code = 0;
            if (!memory->get_process_handle() || !GetExitCodeProcess(memory->get_process_handle(), &code) || code != STILL_ACTIVE) {
                DebugLog("Detached");
                isAttached = false;
                while (g_readerBusy.load()) std::this_thread::yield();
                memory->Detach();
                ClearTagCache();
                ResetViewMatrixCache();
                g_serviceCache = {};
                playerCache.clear(); dualPartsCache.clear();
                teamByPtr.clear(); teamPtrOrder.clear();
                g_lock.targetAddress = 0; cachedJobId.clear();
                wasFlying = wasNoclipping = false;
                g_currentPlaceId = g_currentGameId = 0;
                g_checkpoints.clear(); g_selectedCheckpointIndex = -1; g_checkpointRenameIdx = -1;
                std::atomic_store_explicit(
                    reinterpret_cast<std::shared_ptr<const Snapshot>*>(&g_currentSnapshot),
                    std::shared_ptr<const Snapshot>(),
                    std::memory_order_release);
            }
        }

        std::shared_ptr<const Snapshot> snap =
            std::atomic_load_explicit(
                reinterpret_cast<const std::shared_ptr<const Snapshot>*>(&g_currentSnapshot),
                std::memory_order_acquire);

        // ANTI-PATCH: If they somehow bypassed the auth window, kill the process.
        if (!KeyAuth::IsAuthorized()) {
            // Wait a few seconds then die silently
            Sleep(3000);
            g_WindowRunning = false;
            break;
        }

        const auto now = std::chrono::steady_clock::now();
        int sw = g_screenW, sh = g_screenH;
        const float cx = sw / 2.0f, cy = sh / 2.0f;
        bool heartbeat = std::chrono::duration_cast<std::chrono::seconds>(now - lastHeartbeat).count() >= 1;
        if (heartbeat) { lastHeartbeat = now; DebugLogFlush(); }

        const Matrix4x4& vm = snap ? snap->viewMatrix : Matrix4x4{};
        const bool matrixOk = IsMatrixSane(vm);

        // ---- Focus poll ----
        if (isAttached.load() && (espEnabled || aimbotEnabled || triggerbotEnabled)) {
            auto fn = std::chrono::steady_clock::now();
            if (std::chrono::duration_cast<std::chrono::milliseconds>(fn - s_lastFocusCheck).count() >= 100) {
                s_lastFocusCheck = fn;
                DWORD fp = 0;
                HWND fg = GetForegroundWindow();
                if (fg) GetWindowThreadProcessId(fg, &fp);
                s_gameFocused = (fp == memory->get_process_id());
            }
        }
        else s_gameFocused = true;
        const bool gameFocused = s_gameFocused;

        // ---- Early-out: nothing on screen means no D3D/ImGui work at all ----
        const bool espWillDraw = isAttached.load() && gameFocused && espEnabled &&
            snap && !snap->players.empty();
        const bool fovWillDraw = showFOV && isAttached.load() && gameFocused &&
            (aimbotEnabled || triggerbotEnabled);
        const bool anythingVisible = showMenu || espWillDraw || fovWillDraw ||
            g_menuAnim > 0.002f;

        if (!anythingVisible) {
            // Present a cleared frame so the previously-drawn ESP (if any)
            // gets wiped. Without this, DWM keeps compositing the last
            // presented frame forever → frozen ESP boxes after Alt-Tab.
            // LWA_COLORKEY is RGB(0,0,0), so clearing to (0,0,0,0) renders
            // fully transparent — nothing visible.
            const float clr[4] = { 0, 0, 0, 0 };
            g_pd3dDeviceContext->OMSetRenderTargets(1, &g_mainRenderTargetView, nullptr);
            g_pd3dDeviceContext->ClearRenderTargetView(g_mainRenderTargetView, clr);
            g_pSwapChain->Present(0, 0);
            std::this_thread::sleep_for(std::chrono::milliseconds(33));
            continue;
        }

        ImGui_ImplDX11_NewFrame();
        ImGui_ImplWin32_NewFrame();
        ImGuiIO& io = ImGui::GetIO();

        // Always update mouse position from the OS so dragging works flawlessly
        POINT pt; GetCursorPos(&pt); ScreenToClient(hwnd, &pt);
        io.MousePos = ImVec2((float)pt.x, (float)pt.y);

        ImGui::NewFrame();

        {
            float dt = (std::min)(io.DeltaTime, 0.1f);
            float target = showMenu ? 1.0f : 0.0f;
            g_menuAnim += (target - g_menuAnim) * (std::min)(1.0f, dt * 14.0f);
            if (fabsf(g_menuAnim - target) < 0.002f) g_menuAnim = target;
        }
        // ---- Aimbot ----
        if (isAttached.load() && snap && gameFocused && (aimbotEnabled || triggerbotEnabled) && !snap->players.empty()) {
            // Candidate with hitbox-aware score + velocity vector
            struct AC {
                uintptr_t pa;
                Vector3   ap;
                Vector3   predicted;
                Vector2   sa;
                float     score;
                float     wd;
                float     h;
                Vector3   vel;
            };
            std::vector<AC> cs;
            cs.reserve(snap->players.size());

            if (matrixOk) {
                for (auto& pd : snap->players) {
                    if (pd.distance > aimbotMaxRange) continue;

                    // --- 1. Choose aim point (part selection) ---
                    Vector3 ap = pd.headPos;
                    if (aimbotPart == 1) {
                        if (pd.isR15 && (pd.upperTorso.x || pd.upperTorso.y || pd.upperTorso.z)) ap = pd.upperTorso;
                        else if (pd.torso.x || pd.torso.y || pd.torso.z) ap = pd.torso;
                        else ap = pd.rootPos;
                    }
                    else if (aimbotPart == 2) {
                        // Nearest-to-crosshair: use raw positions now, refine with prediction below
                        float bd = FLT_MAX;
                        auto tp = [&](Vector3 wp) {
                            Vector2 sp;
                            if (WorldToScreen(wp, vm, sw, sh, sp)) {
                                float d = sqrtf((sp.x - cx) * (sp.x - cx) + (sp.y - cy) * (sp.y - cy));
                                if (d < bd) { bd = d; ap = wp; }
                            }
                            };
                        tp(pd.headPos);
                        if (pd.isR15 && (pd.upperTorso.x || pd.upperTorso.y || pd.upperTorso.z)) tp(pd.upperTorso);
                        else if (pd.torso.x || pd.torso.y || pd.torso.z) tp(pd.torso);
                    }

                    // --- 2. Velocity prediction for this target ---
                    Vector3 predicted = PredictPos(pd.playerAddress, ap, 8.0f);   // ~8ms ahead
                    Vector2 sa;
                    if (!WorldToScreen(predicted, vm, sw, sh, sa)) continue;

                    // --- 3. Hitbox-aware score (not just point distance) ---
                    // Build the on-screen bounding box (matches the ESP box exactly).
                    Vector3 top3 = pd.rootPos; top3.y += 3.0f;
                    Vector3 bot3 = pd.rootPos; bot3.y -= 2.8f;
                    Vector2 scrTop, scrBot;
                    if (!WorldToScreen(top3, vm, sw, sh, scrTop)) continue;
                    if (!WorldToScreen(bot3, vm, sw, sh, scrBot)) continue;

                    float boxH = scrBot.y - scrTop.y;
                    if (boxH < 4.0f) continue;
                    float boxW = boxH * 0.55f;
                    float L = scrBot.x - boxW * 0.5f;
                    float R = scrBot.x + boxW * 0.5f;
                    float T = scrTop.y;
                    float B = scrBot.y;

                    // If the crosshair is inside the box, distance is 0 → wins ties.
                    // Else it's the distance from crosshair to nearest box edge.
                    float bdx = 0.0f, bdy = 0.0f;
                    if (cx < L)      bdx = L - cx;
                    else if (cx > R) bdx = cx - R;
                    if (cy < T)      bdy = T - cy;
                    else if (cy > B) bdy = cy - B;
                    float boxDist = sqrtf(bdx * bdx + bdy * bdy);

                    // FOV gate uses box distance now — matches what you *see*
                    if (boxDist > aimbotFOV) continue;


                    AC c;
                    c.pa = pd.playerAddress;
                    c.ap = ap;
                    c.predicted = predicted;
                    c.sa = sa;
                    c.score = boxDist;
                    c.wd = pd.distance;
                    c.h = pd.health;
                    auto vit = g_velTrack.find(pd.playerAddress);
                    if (vit != g_velTrack.end()) c.vel = vit->second.vel;
                    cs.push_back(c);
                }
            }

            // --- 5. Target selection with sticky bias ---
            AC* tgt = nullptr;
            if (aimbotSticky && g_lock.targetAddress != 0) {
                auto age = std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::steady_clock::now() - g_lock.acquiredAt).count();
                if (age < aimbotLockTimeMs) {
                    for (auto& c : cs) if (c.pa == g_lock.targetAddress) { tgt = &c; break; }
                }
            }
            if (!tgt && !cs.empty()) {
                float bestScore = FLT_MAX;
                for (auto& c : cs) {
                    float s = c.score;
                    // Priority adjustments apply on top of score
                    if (aimbotPriority == 1) s += c.wd * 0.5f;             // distance bias
                    else if (aimbotPriority == 2) s += c.h * 5.0f;         // low-health bias
                    // Sticky bias: keep current target unless another is clearly better
                    if (aimbotSticky && g_lock.targetAddress != 0 && c.pa == g_lock.targetAddress)
                        s *= 0.6f;                                          // 40% favoritism
                    if (s < bestScore) { bestScore = s; tgt = &c; }
                }
                if (tgt) {
                    g_lock.targetAddress = tgt->pa;
                    g_lock.acquiredAt = std::chrono::steady_clock::now();
                }
            }
            if (!tgt) g_lock.targetAddress = 0;

            // --- 6. Aim with velocity prediction + non-linear smoothing ---
            if (aimbotEnabled && tgt && (GetAsyncKeyState(aimbotKey) & 0x8000)) {
                // Re-run prediction at aim time (right before we send the event) for max accuracy
                Vector3 aimWorld = PredictPos(tgt->pa, tgt->ap, 8.0f);
                Vector2 aimScreen;
                if (WorldToScreen(aimWorld, vm, sw, sh, aimScreen)) {
                    float dx = aimScreen.x - cx, dy = aimScreen.y - cy;
                    float mag = sqrtf(dx * dx + dy * dy);
                    if (mag > aimbotDeadzone && mag < (std::max)(sw, sh) * 1.5f) {
                        // Non-linear smoothing:
                        //   - far: fast catch-up (capped at maxStep)
                        //   - near: gradual convergence
                        //   - tiny: still advances by 1px (fixes "stuck" bug)
                        float sm = (std::max)(1.0f, aimbotSmoothness);
                        float step = mag / sm;
                        step = (std::max)(step, (std::min)(2.0f, mag));   // never below 2px unless already close
                        step = (std::min)(step, aimbotMaxStep);
                        step = (std::min)(step, mag);                     // don't overshoot

                        // Velocity gain: aim slightly faster when target is moving (harder to track)
                        float tvel = sqrtf(tgt->vel.x * tgt->vel.x + tgt->vel.y * tgt->vel.y + tgt->vel.z * tgt->vel.z);
                        if (tvel > 15.0f) step = (std::min)(step * 1.35f, aimbotMaxStep);

                        float scale = (mag > 0.001f) ? (step / mag) : 0.0f;
                        int mx = (int)(dx * scale);
                        int my = (int)(dy * scale);
                        if (mx == 0 && my == 0 && (fabsf(dx) > 0.5f || fabsf(dy) > 0.5f)) {
                            // Guarantee at least 1px of movement while off-target
                            mx = (dx > 0) - (dx < 0);
                            my = (dy > 0) - (dy < 0);
                        }
                        SendRelativeMove(mx, my);
                    }
                }
            }

            // --- 7. Triggerbot (unchanged logic, but uses predicted screen dist) ---
            if (triggerbotEnabled && !cs.empty()) {
                auto nT = std::chrono::steady_clock::now();
                if (std::chrono::duration_cast<std::chrono::milliseconds>(nT - lastTriggerTime).count() >= triggerbotDelay) {
                    for (auto& c : cs) {
                        Vector2 sa = c.sa;
                        float sdx = sa.x - cx, sdy = sa.y - cy;
                        if (sqrtf(sdx * sdx + sdy * sdy) < 15.0f) {
                            SendMouseClick();
                            lastTriggerTime = nT;
                            break;
                        }
                    }
                }
            }
        }

        // ---- ESP render ----
        if (isAttached.load() && snap && gameFocused && espEnabled && !snap->players.empty()) {
            ImDrawList* dl = ImGui::GetBackgroundDrawList();
            const ImDrawListFlags savedFlags = dl->Flags;
            dl->Flags &= ~ImDrawListFlags_AntiAliasedLines;
            ImU32 col = ImGui::ColorConvertFloat4ToU32(espColor);
            ImU32 fill = ImGui::ColorConvertFloat4ToU32(espFillColor);
            ImFont* font = ImGui::GetFont();
            int drawn = 0;
            static std::unordered_map<uint64_t, ImVec2> s_textSizeCache;
            auto MeasureText = [](ImFont* font, float fs, const char* txt) -> ImVec2 {
                uint64_t h = (uint64_t)(uintptr_t)font ^ ((uint64_t)(fs * 4.0f) << 40);
                for (const char* p = txt; *p; ++p) h = h * 1099511628211ULL ^ (unsigned char)*p;
                auto it = s_textSizeCache.find(h);
                if (it != s_textSizeCache.end()) return it->second;
                ImVec2 s = font->CalcTextSizeA(fs, FLT_MAX, 0.0f, txt);
                if (s_textSizeCache.size() > 4096) s_textSizeCache.clear();
                s_textSizeCache[h] = s;
                return s;
                };
            for (auto& pd : snap->players) {
                if (pd.distance > maxDistanceCull) continue;
                Vector3 t3 = pd.rootPos; t3.y += 3.0f;
                Vector3 b3 = pd.rootPos; b3.y -= 2.8f;
                Vector2 st, sb;
                if (WorldToScreen(t3, vm, sw, sh, st) && WorldToScreen(b3, vm, sw, sh, sb)) {
                    ++drawn;
                    ImU32 bc = (useTeamColor && pd.teamColor != 0) ? pd.teamColor : col;
                    float h = sb.y - st.y;
                    float w = h * 0.55f;
                    float l = sb.x - (w / 2.0f), r = sb.x + (w / 2.0f);
                    float t = st.y, b = sb.y;
                    dl->AddRectFilled(ImVec2(l, t), ImVec2(r, b), fill);
                    dl->AddRect(ImVec2(l, t), ImVec2(r, b), bc, 0.0f, 0, 1.5f);
                    float sc = (std::min)((std::max)(h / 100.0f, 0.6f), 2.5f);

                    // Pick the nearest baked size instead of scaling the default font.
                    int fontIdx = 0;
                    if (sc >= 2.0f) fontIdx = 3;
                    else if (sc >= 1.4f) fontIdx = 2;
                    else if (sc >= 1.0f) fontIdx = 1;
                    font = ImGui::GetIO().Fonts->Fonts[fontIdx];
                    float fs = kEspFontSizes[fontIdx];   // exact baked size → native sampling
                    ImVec2 ns = MeasureText(font, fs, pd.name.c_str());
                    ImVec2 np(sb.x - (ns.x / 2), t - ns.y - 2);
                    dl->AddText(font, fs, ImVec2(np.x + 1, np.y + 1), IM_COL32(0, 0, 0, 255), pd.name.c_str());
                    dl->AddText(font, fs, np, bc, pd.name.c_str());
                    if (showDistance) {
                        char db[32]; sprintf_s(db, "[%.0fm]", pd.distance);
                        ImVec2 ds = MeasureText(font, fs, db);
                        ImVec2 dp(sb.x - (ds.x / 2), b + 2);
                        dl->AddText(font, fs, ImVec2(dp.x + 1, dp.y + 1), IM_COL32(0, 0, 0, 255), db);
                        dl->AddText(font, fs, dp, IM_COL32(200, 200, 200, 255), db);
                    }
                    if (showHealthBar) {
                        float hp = (std::min)((std::max)(pd.health / pd.maxHealth, 0.0f), 1.0f);
                        ImU32 hc = (hp > 0.5f) ? IM_COL32(0, 255, 0, 255) : (hp > 0.25f) ? IM_COL32(255, 255, 0, 255) : IM_COL32(255, 0, 0, 255);
                        float bw = 3.0f * sc;
                        float bl = l - bw - 2.0f;
                        float bh = b - t;
                        float bf = bh * hp;
                        dl->AddRectFilled(ImVec2(bl, t), ImVec2(bl + bw, b), IM_COL32(50, 50, 50, 255));
                        dl->AddRectFilled(ImVec2(bl, b - bf), ImVec2(bl + bw, b), hc);
                    }
                    if (skeletonEnabled && pd.hasSkeleton) {
                        auto DB = [&](Vector3 a, Vector3 b2) {
                            if ((a.x == 0 && a.y == 0 && a.z == 0) || (b2.x == 0 && b2.y == 0 && b2.z == 0)) return;
                            Vector2 sa, sb2;
                            if (WorldToScreen(a, vm, sw, sh, sa) && WorldToScreen(b2, vm, sw, sh, sb2))
                                dl->AddLine(ImVec2(sa.x, sa.y), ImVec2(sb2.x, sb2.y), bc, skeletonThickness);
                            };
                        if (pd.isR15) {
                            DB(pd.head, pd.upperTorso);
                            DB(pd.upperTorso, pd.lowerTorso);
                            DB(pd.upperTorso, pd.leftUpperArm);
                            DB(pd.leftUpperArm, pd.leftLowerArm);
                            DB(pd.leftLowerArm, pd.leftHand);
                            DB(pd.upperTorso, pd.rightUpperArm);
                            DB(pd.rightUpperArm, pd.rightLowerArm);
                            DB(pd.rightLowerArm, pd.rightHand);
                            DB(pd.lowerTorso, pd.leftUpperLeg);
                            DB(pd.leftUpperLeg, pd.leftLowerLeg);
                            DB(pd.leftLowerLeg, pd.leftFoot);
                            DB(pd.lowerTorso, pd.rightUpperLeg);
                            DB(pd.rightUpperLeg, pd.rightLowerLeg);
                            DB(pd.rightLowerLeg, pd.rightFoot);
                        }
                        else if (pd.torso.x || pd.torso.y || pd.torso.z) {
                            DB(pd.head, pd.torso);
                            DB(pd.torso, pd.leftArm);
                            DB(pd.torso, pd.rightArm);
                            DB(pd.torso, pd.leftLeg);
                            DB(pd.torso, pd.rightLeg);
                        }
                        if (skeletonHeadCircle && pd.head.x != 0) {
                            Vector2 sh2;
                            if (WorldToScreen(pd.head, vm, sw, sh, sh2))
                                dl->AddCircle(ImVec2(sh2.x, sh2.y), sc * 4.5f, bc, 12, skeletonThickness);
                        }
                    }
                }
            }
            dl->Flags = savedFlags;
            if (heartbeat) DebugLog("[ESP] list=%zu drawn=%d focused=%d", snap->players.size(), drawn, gameFocused ? 1 : 0);
        }
        else if (isAttached.load() && heartbeat && espEnabled) {
            DebugLog("[ESP] skip focused=%d list=%zu", gameFocused ? 1 : 0, snap ? snap->players.size() : 0);
        }

        // ---- FOV circle ----
        if (showFOV && isAttached.load() && gameFocused && (aimbotEnabled || triggerbotEnabled))
            ImGui::GetBackgroundDrawList()->AddCircle(ImVec2(cx, cy), aimbotFOV, IM_COL32(255, 255, 255, 100), 64, 1.5f);

        // ---- Menu ----
        if (g_menuAnim > 0.002f) {
            const std::int64_t uiPlaceId = snap ? snap->placeId : 0;
            const std::int64_t uiGameId = snap ? snap->gameId : 0;
            const bool mvBlockUI = IsMovementBlocked(uiPlaceId, uiGameId);
            const bool isDualUI = (uiGameId == kDualCharacterGameId) || (uiPlaceId == kDualCharacterGameId);

            ImGui::SetNextWindowSize(ImVec2(1200, 800), ImGuiCond_FirstUseEver);
            ImGui::SetNextWindowSizeConstraints(ImVec2(560, 500), ImVec2(FLT_MAX, FLT_MAX));
            ImGui::PushStyleVar(ImGuiStyleVar_Alpha, g_menuAnim);
            ImGui::Begin(OBF("External Menu"), nullptr, ImGuiWindowFlags_None);

            if (!isAttached.load()) {
                ImGui::TextColored(ImVec4(1, 0, 0, 1), "Status: Not Attached");
                ImGui::Text("Open Roblox first, then click Attach.");
                if (ImGui::Button("Attach to Roblox", ImVec2(150, 30))) {
                    if (memory->attach_to_process(OBF("RobloxPlayerBeta.exe"))) {
                        isAttached = true;
                        g_proc.h = memory->get_process_handle();
                        g_proc.pid = memory->get_process_id();
                        g_proc.base = memory->get_module_address();
                        s_lastFocusCheck = {};
                        CheckOffsetHealth();
                        g_lastReadTimeMs = 0;
                        DebugLog("Attached pid=%d base=0x%llX", memory->get_process_id(),
                            (unsigned long long)memory->get_module_address());
                    }
                }
                ImGui::Separator();
            }
            else {
                ImGui::TextColored(ImVec4(0, 1, 0, 1), "Status: Attached (PID: %d)", memory->get_process_id());
                if (mvBlockUI) { ImGui::SameLine(); ImGui::TextColored(ImVec4(1, 0.4f, 0.4f, 1), "| MOVEMENT BLOCKED"); }
                if (isDualUI) { ImGui::SameLine(); ImGui::TextColored(ImVec4(0.4f, 0.7f, 1, 1), "| DUAL ESP"); }
                if (!g_instanceAPI) { ImGui::SameLine(); ImGui::TextColored(ImVec4(1, 0.5f, 0.3f, 1), "| API MISSING"); }
                if (g_offsetHealth == OffsetHealth::Stale) {
                    ImGui::SameLine();
                    ImGui::TextColored(ImVec4(1, 0.2f, 0.2f, 1), "| OFFSETS OUTDATED");
                    if (ImGui::IsItemHovered())
                        ImGui::SetTooltip("Offsets do not match this Roblox client.\n"
                            "Open Verbose Trace tab and click 'Force Refresh Offsets'.");
                }
                if (snap) {
                    ImGui::SameLine();
                    ImGui::TextDisabled("| snap %llums  players=%zu",
                        (unsigned long long)(GetTickCount64() - snap->captureMs), snap->players.size());
                }
                ImGui::Separator();
            }

            if (ImGui::BeginTabBar("Tabs")) {
                if (ImGui::BeginTabItem(OBF("  ESP Settings  "))) {
                    ImGui::BeginChild("##esp_body", ImVec2(0, 0), false);
                    ImGui::Checkbox(OBF("Enable ESP"), &espEnabled);
                    ImGui::SliderInt("Tick Rate", &tickRate, 10, 144);
                    ImGui::Separator();
                    ImGui::SliderFloat("Max Distance", &maxDistanceCull, 50.0f, 5000.0f, "%.0f studs");
                    ImGui::Checkbox("Show Distance", &showDistance);
                    ImGui::Checkbox("Show Health Bar", &showHealthBar);
                    ImGui::Separator();
                    ImGui::Checkbox("Enable Skeleton", &skeletonEnabled);
                    if (skeletonEnabled) {
                        ImGui::Checkbox("Show Head Circle", &skeletonHeadCircle);
                        ImGui::SliderFloat("Skeleton Thickness", &skeletonThickness, 0.5f, 5.0f, "%.1f");
                    }
                    ImGui::Separator();
                    ImGui::Checkbox("Show Self ESP", &showSelfEsp);
                    ImGui::Checkbox("Team Check (Hide Teammates)", &toggleTeamCheck);
                    ImGui::Checkbox("Use Team Color ESP", &useTeamColor);
                    if (!useTeamColor) ImGui::ColorEdit4("ESP Color", (float*)&espColor, ImGuiColorEditFlags_NoInputs);
                    ImGui::ColorEdit4("ESP Fill Color", (float*)&espFillColor, ImGuiColorEditFlags_NoInputs);

                    ImGui::Separator();
                    ImGui::TextColored(ImVec4(1, 0.7f, 0.3f, 1), "Dual-Character Filter");
                    static const char* names[] = {
                        "CharacterTag (tag='Character')",
                        "RealPlayerChar (Player.ModelInstance)",
                        "HumanoidAlive (Health > 0)",
                        "HasHead",
                        "ShowAll (debug)"
                    };
                    if (ImGui::Combo("##df", (int*)&g_dualFilter, names, 5)) {
                        g_dualZeroTicks = 0;
                        DebugLog("Filter changed to %d", (int)g_dualFilter);
                    }

                    ImGui::Separator();
                    ImGui::TextColored(ImVec4(0.7f, 0.9f, 1.0f, 1.0f), "Keybinds");
                    char buf[64];
                    FormatBindLabel(g_menuToggleBind, buf, sizeof(buf));
                    ImGui::AlignTextToFramePadding();
                    ImGui::Text("Menu Toggle:"); ImGui::SameLine();
                    if (const char* st = BindStatusText(BindTarget::MenuToggle))
                        ImGui::TextColored(ImVec4(1, 1, 0, 1), "%s", st);
                    else ImGui::Text("%s", buf);
                    ImGui::SameLine();
                    if (ImGui::SmallButton("Rebind##mt")) {
                        g_bindTarget = BindTarget::MenuToggle;
                        s_armed = false; s_armTime = 0; s_pendingMod = 0;
                        memset(s_prevKeyState, 0, sizeof(s_prevKeyState));
                        s_prevLMB = false;
                    }
                    FormatBindLabel(g_exitBind, buf, sizeof(buf));
                    ImGui::AlignTextToFramePadding();
                    ImGui::Text("Exit:"); ImGui::SameLine();
                    if (const char* st = BindStatusText(BindTarget::Exit))
                        ImGui::TextColored(ImVec4(1, 1, 0, 1), "%s", st);
                    else ImGui::Text("%s", buf);
                    ImGui::SameLine();
                    if (ImGui::SmallButton("Rebind##ex")) {
                        g_bindTarget = BindTarget::Exit;
                        s_armed = false; s_armTime = 0; s_pendingMod = 0;
                        memset(s_prevKeyState, 0, sizeof(s_prevKeyState));
                        s_prevLMB = false;
                    }

                    ImGui::Separator();
                    if (ImGui::Checkbox("Hide from Screen Recordings", &hideFromRecording))
                        ApplyCaptureProtection(g_overlayHwnd, hideFromRecording);

                    ImGui::Separator();
                    ImGui::TextColored(ImVec4(0.7f, 0.9f, 1.0f, 1.0f), "Config");
                    if (ImGui::Button("Save Config", ImVec2(140, 0))) {
                        SaveConfig();
                        DebugLog("Config saved");
                    }
                    ImGui::SameLine();
                    if (ImGui::Button("Load Config", ImVec2(140, 0))) {
                        LoadConfig();
                        ApplyCaptureProtection(g_overlayHwnd, hideFromRecording);
                        DebugLog("Config loaded");
                    }
                    if (ImGui::IsItemHovered())
                        ImGui::SetTooltip("Reloads settings from config.json next to the exe.");

                    ImGui::EndChild();
                    ImGui::EndTabItem();
                }

                if (ImGui::BeginTabItem(OBF("  Aimbot / Trigger  "))) {
                    ImGui::BeginChild("##aim_body", ImVec2(0, 0), false);
                    ImGui::Checkbox("Enable Aimbot", &aimbotEnabled);
                    ImGui::Checkbox("Enable Triggerbot", &triggerbotEnabled);
                    ImGui::Checkbox("Show FOV Circle", &showFOV);
                    ImGui::Separator();
                    ImGui::Text("Aim Key (hold to aim)");
                    static int aimKeyIdx = 0;
                    const char* keyNames[] = { "Right Mouse", "Left Mouse", "Middle Mouse", "Left Alt", "Left Shift", "XButton1" };
                    const int keyVals[] = { VK_RBUTTON, VK_LBUTTON, VK_MBUTTON, VK_LMENU, VK_LSHIFT, VK_XBUTTON1 };
                    for (int i = 0; i < 6; ++i) if (aimbotKey == keyVals[i]) aimKeyIdx = i;
                    if (ImGui::Combo("##aimkey", &aimKeyIdx, keyNames, 6)) aimbotKey = keyVals[aimKeyIdx];
                    ImGui::Text("Aim Part");
                    const char* partNames[] = { "Head", "Torso", "Nearest to Crosshair" };
                    ImGui::Combo("##aimpart", &aimbotPart, partNames, 3);
                    ImGui::Text("Target Priority");
                    const char* prioNames[] = { "Closest to Crosshair", "Closest Distance", "Lowest Health" };
                    ImGui::Combo("##aimprio", &aimbotPriority, prioNames, 3);
                    ImGui::Separator();
                    ImGui::Checkbox("Sticky Target Lock", &aimbotSticky);
                    if (aimbotSticky) ImGui::SliderInt("Lock Time", &aimbotLockTimeMs, 0, 1000, "%d ms");
                    ImGui::Separator();
                    ImGui::SliderFloat("Aimbot FOV", &aimbotFOV, 10.0f, 1000.0f, "%.0f px");
                    ImGui::SliderFloat("Aimbot Max Range", &aimbotMaxRange, 100.0f, 10000.0f, "%.0f studs");
                    ImGui::SliderFloat("Aimbot Smoothness", &aimbotSmoothness, 1.0f, 20.0f, "%.1f");
                    ImGui::SliderFloat("Deadzone", &aimbotDeadzone, 0.0f, 20.0f, "%.1f px");
                    ImGui::SliderFloat("Max Step / Frame", &aimbotMaxStep, 5.0f, 200.0f, "%.0f px");

                    ImGui::Separator();
                    ImGui::SliderInt("Trigger Delay", &triggerbotDelay, 0, 200, "%d ms");

                    ImGui::EndChild();
                    ImGui::EndTabItem();
                }

                if (ImGui::BeginTabItem(OBF("  Movement  "))) {
                    ImGui::BeginChild("##mv_body", ImVec2(0, 0), false);
                    if (mvBlockUI) {
                        ImGui::TextColored(ImVec4(1.0f, 0.35f, 0.35f, 1.0f), "MOVEMENT CHEATS DISABLED IN THIS GAME");
                        ImGui::Separator();
                    }
                    ImGui::BeginDisabled(mvBlockUI);
                    ImGui::Checkbox("Enable Fly", &flyEnabled);
                    ImGui::SliderFloat("Fly Speed", &flySpeed, 10.0f, 500.0f, "%.0f");
                    ImGui::Separator();
                    ImGui::Checkbox("Enable Noclip", &noclipEnabled);
                    ImGui::Separator();
                    ImGui::Checkbox("Apply JumpPower", &applyJumpPower);
                    ImGui::SliderFloat("JumpPower", &jumpPowerVal, 50.0f, 500.0f, "%.1f");
                    ImGui::SameLine();
                    if (ImGui::SmallButton("Reset##jp")) jumpPowerVal = 50.0f;
                    ImGui::Checkbox("Apply WalkSpeed", &applyWalkspeed);
                    ImGui::SliderFloat("WalkSpeed", &walkspeedVal, 16.0f, 500.0f, "%.1f");
                    ImGui::SameLine();
                    if (ImGui::SmallButton("Reset##ws")) walkspeedVal = 16.0f;
                    ImGui::Separator();
                    ImGui::Checkbox("Apply Gravity", &applyGravity);
                    ImGui::SliderFloat("Gravity", &gravityVal, 0.0f, 588.6f, "%.1f");
                    ImGui::SameLine();
                    if (ImGui::SmallButton("Reset##gr")) gravityVal = 196.2f;
                    ImGui::EndDisabled();
                    ImGui::Spacing();
                    ImGui::TextColored(ImVec4(1, 0, 0, 1), "WARNING: Writing to memory\nwill likely get you banned.");
                    ImGui::EndChild();
                    ImGui::EndTabItem();
                }

                if (ImGui::BeginTabItem(OBF("  Checkpoints  "))) {
                    ImGui::BeginChild("##cp_body", ImVec2(0, 0), false);
                    ImGui::TextColored(ImVec4(0.7f, 0.9f, 1.0f, 1.0f), "Checkpoint Manager");
                    if (uiPlaceId != 0)
                        ImGui::TextDisabled("Game PlaceId: %lld  (checkpoints_%lld.txt)",
                            (long long)uiPlaceId, (long long)uiPlaceId);
                    else
                        ImGui::TextDisabled("Game PlaceId: <unknown>  (attach to resolve)");
                    ImGui::Spacing();

                    if (!isAttached.load()) {
                        ImGui::TextColored(ImVec4(1, 0.3f, 0.3f, 1), "Attach to Roblox first.");
                    }
                    else {
                        static uintptr_t s_hrpFrame = 0;
                        static uint64_t s_hrpFrameMs = 0;
                        uint64_t nowMs2 = GetTickCount64();
                        if (nowMs2 - s_hrpFrameMs > 200) { s_hrpFrame = GetLocalHRPAddress(); s_hrpFrameMs = nowMs2; }
                        uintptr_t hrp = s_hrpFrame;

                        if (!g_checkpoints.empty()) {
                            ImGui::AlignTextToFramePadding();
                            ImGui::Text("Quick teleport:"); ImGui::SameLine();
                            const char* preview = "-- select --";
                            if (g_selectedCheckpointIndex >= 0 && g_selectedCheckpointIndex < (int)g_checkpoints.size())
                                preview = g_checkpoints[g_selectedCheckpointIndex].name.c_str();
                            ImGui::SetNextItemWidth(320);
                            if (ImGui::BeginCombo("##quicktp", preview)) {
                                for (int i = 0; i < (int)g_checkpoints.size(); ++i) {
                                    bool sel = (g_selectedCheckpointIndex == i);
                                    if (ImGui::Selectable(g_checkpoints[i].name.c_str(), sel)) {
                                        g_selectedCheckpointIndex = i;
                                        uintptr_t localHRP = GetLocalHRPAddress();
                                        if (localHRP) Instance(localHRP).SetPosition(g_checkpoints[i].position);
                                    }
                                    if (sel) ImGui::SetItemDefaultFocus();
                                }
                                ImGui::EndCombo();
                            }
                            ImGui::Separator();
                        }

                        ImGui::Text("Save current position:");
                        ImGui::SetNextItemWidth(260);
                        bool enterPressed = ImGui::InputTextWithHint("##cpname", "Checkpoint name...",
                            g_checkpointNameBuf, sizeof(g_checkpointNameBuf), ImGuiInputTextFlags_EnterReturnsTrue);
                        ImGui::SameLine();
                        ImGui::BeginDisabled(hrp == 0);
                        bool doSave = ImGui::Button("Save Position") || (enterPressed && hrp != 0);
                        ImGui::EndDisabled();
                        if (doSave) {
                            Vector3 pos = Instance(hrp).GetPosition();
                            std::string name = g_checkpointNameBuf;
                            name.erase(std::remove(name.begin(), name.end(), '|'), name.end());
                            if (name.empty()) name = "Checkpoint " + std::to_string(g_checkpoints.size() + 1);
                            g_checkpoints.push_back({ name, pos });
                            g_checkpointNameBuf[0] = '\0';
                            SaveCheckpoints();
                        }
                        if (hrp == 0) ImGui::TextDisabled("(Cannot save: local character not found)");

                        ImGui::Separator();
                        ImGui::Text("Saved Checkpoints: %d", (int)g_checkpoints.size());
                        ImGui::SameLine();
                        if (!g_checkpoints.empty()) {
                            if (ImGui::SmallButton("Clear All")) {
                                g_checkpoints.clear(); g_selectedCheckpointIndex = -1; SaveCheckpoints();
                            }
                        }
                        ImGui::Spacing();
                        if (g_checkpoints.empty()) ImGui::TextDisabled("No checkpoints saved yet for this game.");

                        ImGui::BeginChild("##cplist", ImVec2(0, 0), true);
                        for (int i = 0; i < (int)g_checkpoints.size(); ++i) {
                            auto& cp = g_checkpoints[i];
                            ImGui::PushID(i);
                            if (ImGui::Button("Teleport", ImVec2(90, 0))) {
                                uintptr_t localHRP = GetLocalHRPAddress();
                                if (localHRP) Instance(localHRP).SetPosition(cp.position);
                            }
                            ImGui::SameLine();
                            ImGui::AlignTextToFramePadding();
                            ImGui::Text("%s", cp.name.c_str()); ImGui::SameLine();
                            ImGui::TextDisabled("(%.1f, %.1f, %.1f)", cp.position.x, cp.position.y, cp.position.z);
                            float btnW = 70.0f * 2 + 20.0f;
                            float rightX = ImGui::GetContentRegionAvail().x - btnW;
                            if (rightX > 0.0f) ImGui::SameLine(rightX); else ImGui::SameLine();
                            if (ImGui::SmallButton("Rename")) {
                                sprintf_s(g_checkpointRenameBuf, sizeof(g_checkpointRenameBuf), "%s", cp.name.c_str());
                                g_checkpointRenameIdx = i;
                                ImGui::OpenPopup("Rename Checkpoint");
                            }
                            ImGui::SameLine();
                            if (ImGui::SmallButton("X")) {
                                g_checkpoints.erase(g_checkpoints.begin() + i);
                                if (g_selectedCheckpointIndex == i) g_selectedCheckpointIndex = -1;
                                else if (g_selectedCheckpointIndex > i) --g_selectedCheckpointIndex;
                                SaveCheckpoints();
                                ImGui::PopID();
                                break;
                            }
                            ImGui::Separator();
                            ImGui::PopID();
                        }
                        ImGui::EndChild();

                        if (ImGui::BeginPopupModal("Rename Checkpoint", nullptr, ImGuiWindowFlags_AlwaysAutoResize)) {
                            ImGui::Text("New name:");
                            ImGui::SetNextItemWidth(280);
                            ImGui::InputText("##rn", g_checkpointRenameBuf, sizeof(g_checkpointRenameBuf));
                            if (ImGui::Button("OK", ImVec2(120, 0))) {
                                if (g_checkpointRenameIdx >= 0 && g_checkpointRenameIdx < (int)g_checkpoints.size()) {
                                    std::string nn = g_checkpointRenameBuf;
                                    nn.erase(std::remove(nn.begin(), nn.end(), '|'), nn.end());
                                    if (!nn.empty()) g_checkpoints[g_checkpointRenameIdx].name = nn;
                                    SaveCheckpoints();
                                }
                                g_checkpointRenameIdx = -1;
                                ImGui::CloseCurrentPopup();
                            }
                            ImGui::SameLine();
                            if (ImGui::Button("Cancel", ImVec2(120, 0))) {
                                g_checkpointRenameIdx = -1;
                                ImGui::CloseCurrentPopup();
                            }
                            ImGui::EndPopup();
                        }
                    }
                    ImGui::EndChild();
                    ImGui::EndTabItem();
                }

                if (ImGui::BeginTabItem(OBF("  Team Filter  "))) {
                    ImGui::BeginChild("##team_body", ImVec2(0, 0), false);
                    ImGui::Text("Select which teams to show/aim at:");
                    ImGui::TextDisabled("(populated from Player.Team pointers)");
                    ImGui::Separator();

                    if (snap) {
                        for (size_t i = 0; i < snap->teamOrder.size(); ++i) {
                            uintptr_t addr = snap->teamOrder[i];
                            const TeamData* td = nullptr;
                            for (auto& kv : snap->teams) if (kv.first == addr) { td = &kv.second; break; }
                            if (!td) continue;
                            bool visible;
                            {
                                std::lock_guard lk(g_hiddenTeamsMutex);
                                visible = !g_hiddenTeams.count(addr);
                            }
                            ImGui::PushID((int)i);
                            ImVec4 color = ImGui::ColorConvertU32ToFloat4(td->color);
                            ImGui::ColorButton("##color", color, ImGuiColorEditFlags_NoTooltip | ImGuiColorEditFlags_NoDragDrop);
                            ImGui::SameLine();
                            ImGui::PushStyleColor(ImGuiCol_Text, color);
                            if (ImGui::Checkbox(td->name.c_str(), &visible)) {
                                std::lock_guard lk(g_hiddenTeamsMutex);
                                if (visible) g_hiddenTeams.erase(addr); else g_hiddenTeams.insert(addr);
                            }
                            ImGui::PopStyleColor();
                            ImGui::PopID();
                        }
                        if (snap->teamOrder.empty())
                            ImGui::TextDisabled("(No teams detected yet)");
                    }
                    ImGui::EndChild();
                    ImGui::EndTabItem();
                }

                if (ImGui::BeginTabItem(OBF("  Verbose Trace  "))) {
                    ImGui::BeginChild("##trace_body", ImVec2(0, 0), false);

                    ImGui::Text("Players Found: %d", snap ? (int)snap->players.size() : 0);
                    ImGui::Text("Cached Players: %d", (int)playerCache.size());
                    ImGui::Text("Server JobId: %s", snap ? snap->jobId.c_str() : "");
                    ImGui::Text("PlaceId: %lld   Universe/Game ID: %lld",
                        (long long)uiPlaceId, (long long)uiGameId);
                    ImGui::TextDisabled("Cache file: %ls (%d entries)",
                        UniverseCachePath().filename().c_str(), (int)g_universeCache.size());
                    if (snap)
                        ImGui::TextDisabled("Snapshot age: %llu ms",
                            (unsigned long long)(GetTickCount64() - snap->captureMs));

                    if (isAttached.load() && uiPlaceId > 0) {
                        if (ImGui::SmallButton("Force refresh universe via API")) {
                            std::int64_t n = ForceRefreshUniverseId(uiPlaceId);
                            if (n == 0) ImGui::OpenPopup("##rf");
                        }
                        if (ImGui::BeginPopup("##rf")) {
                            ImGui::TextColored(ImVec4(1, 0.4f, 0.4f, 1), "API lookup failed.\nCached value kept.");
                            ImGui::EndPopup();
                        }
                    }

                    ImGui::Checkbox("Verbose ESP logging", &g_verboseLog);
                    if (ImGui::Button("Clear log file")) {
                        std::ofstream clr(ExeDir() / L"esp_debug.txt", std::ios::trunc);
                        DebugLog("Log cleared by user");
                    }
                    ImGui::SameLine();
                    ImGui::TextDisabled("%ls", (ExeDir() / L"esp_debug.txt").filename().c_str());

                    ImGui::Separator();
                    ImGui::TextColored(ImVec4(0.7f, 0.9f, 1.0f, 1.0f), "Calibrated Offsets");

                    if (isAttached.load() && g_offsetHealth == OffsetHealth::Stale) {
                        ImGui::PushStyleColor(ImGuiCol_ChildBg, ImVec4(0.25f, 0.05f, 0.05f, 1.0f));
                        ImGui::BeginChild("##stale_warn", ImVec2(0, 0), true);
                        ImGui::TextColored(ImVec4(1, 0.3f, 0.3f, 1), "Offsets are OUTDATED for this Roblox version.");
                        ImGui::TextWrapped("Roblox has updated. Offsets from the offset server no longer match "
                            "your client's memory layout, so ESP/aimbot will not work.");
                        ImGui::Spacing();
                        ImGui::Text("To fix:");
                        ImGui::BulletText("Click 'Force Refresh Offsets' below, OR");
                        ImGui::BulletText("Delete offsets.json + offsets.version and restart the cheat");
                        ImGui::Spacing();
                        if (ImGui::Button("Force Refresh Offsets", ImVec2(200, 30))) {
                            try {
                                Offsets::Initialize({}, /*forceRefresh=*/true);
                                PopulateCachedOffsets();
                                CheckOffsetHealth();
                                g_staleOffsetsWarned = true;
                                DebugLog("[HEALTH] User forced offset refresh");
                            }
                            catch (std::exception& e) {
                                DebugLog("[HEALTH] Force refresh failed: %s", e.what());
                            }
                        }
                        ImGui::SameLine();
                        ImGui::TextDisabled("(hits offsets.imtheo.lol)");
                        ImGui::EndChild();
                        ImGui::PopStyleColor();
                        ImGui::Spacing();
                    }
                    else if (isAttached.load() && g_offsetHealth == OffsetHealth::OK) {
                        ImGui::TextColored(ImVec4(0, 1, 0, 1), "Offsets: OK (validated against live client)");
                    }

                    ImGui::Spacing();
                    if (ImGui::Button("Force Refresh Offsets", ImVec2(220, 28))) {
                        try {
                            Offsets::Initialize({}, /*forceRefresh=*/true);
                            PopulateCachedOffsets();
                            CheckOffsetHealth();
                            DebugLog("[HEALTH] User forced offset refresh");
                        }
                        catch (std::exception& e) {
                            DebugLog("[HEALTH] Force refresh failed: %s", e.what());
                        }
                    }
                    ImGui::SameLine();
                    ImGui::TextDisabled("(always available — hits offsets.imtheo.lol)");

                    if (g_instanceAPI) {
                        ImGui::TextColored(ImVec4(0, 1, 0, 1), "InstanceAPI: loaded");
                        ImGui::Text("ComponentMap=0x%llX  AttrSize=0x%llX  AttrKey=0x%llX",
                            (unsigned long long)g_instanceConfig.ComponentMap(),
                            (unsigned long long)g_instanceConfig.AttrSize(),
                            (unsigned long long)g_instanceConfig.AttrKey());
                        ImGui::Text("Version: %s", g_instanceConfig.RobloxVersion().c_str());
                    }
                    else {
                        ImGui::TextColored(ImVec4(1, 0.4f, 0.4f, 1), "InstanceAPI: NOT LOADED");
                    }

                    ImGui::Separator();
                    if (isDualUI) {
                        ImGui::TextColored(ImVec4(0.4f, 0.7f, 1.0f, 1.0f), "Dual-character game ACTIVE");
                        ImGui::Text("Filter: %d  ZeroTicks: %d", (int)g_dualFilter, g_dualZeroTicks);
                    }
                    if (mvBlockUI) ImGui::TextColored(ImVec4(1, 0.4f, 0.4f, 1), "Movement restriction: ACTIVE");
                    ImGui::Separator();
                    ImGui::TextColored(ImVec4(0.7f, 0.9f, 1.0f, 1.0f), "Aimbot");
                    ImGui::Text("Locked Target: 0x%llx", (unsigned long long)g_lock.targetAddress);
                    ImGui::Text("Range: %.0f studs  FOV: %.0f px", aimbotMaxRange, aimbotFOV);
                    ImGui::Text("Game focused: %s", gameFocused ? "yes" : "no");
                    ImGui::EndChild();
                    ImGui::EndTabItem();
                }
                ImGui::EndTabBar();
            }
            ImGui::Separator();
            char mb[32], eb[32];
            FormatBindLabel(g_menuToggleBind, mb, sizeof(mb));
            FormatBindLabel(g_exitBind, eb, sizeof(eb));
            ImGui::Text("Press %s to hide menu | %s to close", mb, eb);
            if (ImGui::Button("Close Cheat", ImVec2(140, 30))) {
                SaveConfig();
                g_WindowRunning = false;
            }
            ImGui::End();
            ImGui::PopStyleVar();
        }

        bool wantTextInput = io.WantTextInput && showMenu;
        LONG_PTR currentExStyle = GetWindowLongPtr(hwnd, GWL_EXSTYLE);
        bool hasNoActivate = (currentExStyle & WS_EX_NOACTIVATE) != 0;

        if (wantTextInput && hasNoActivate) {
            currentExStyle &= ~WS_EX_NOACTIVATE;
            SetWindowLongPtr(hwnd, GWL_EXSTYLE, currentExStyle);
            SetForegroundWindow(hwnd);
        }
        else if (!wantTextInput && !hasNoActivate) {
            currentExStyle |= WS_EX_NOACTIVATE;
            SetWindowLongPtr(hwnd, GWL_EXSTYLE, currentExStyle);
        }

        ImGui::Render();

        // Click-through unless the cursor is actually over an ImGui widget.
        // ImGui::GetIO().WantCaptureMouse is valid after NewFrame().
        const bool overMenu = showMenu &&
            (io.WantCaptureMouse ||
                io.MouseDown[0] || io.MouseDown[1] || io.MouseDown[2]);
        bool wantClickThrough = !overMenu;

        if (wantClickThrough != lastCaptureMouse) {
            LONG_PTR es = GetWindowLongPtr(hwnd, GWL_EXSTYLE);
            if (wantClickThrough) es |= WS_EX_TRANSPARENT; else es &= ~WS_EX_TRANSPARENT;
            SetWindowLongPtr(hwnd, GWL_EXSTYLE, es);
            lastCaptureMouse = wantClickThrough;
        }
        static auto s_lastPresent = std::chrono::steady_clock::now();

        int targetFps = 0;
        if (showMenu) {
            // If ESP/FOV isn't drawing behind the menu, 30 fps is plenty —
            // the menu is the only thing on screen and it isn't animating.
            targetFps = (espWillDraw || fovWillDraw) ? 50 : 30;
        }
        else if (isAttached.load() && gameFocused) targetFps = 60; // esp
        else                                       targetFps = 15; // idle

        if (targetFps > 0) {
            const auto n = std::chrono::steady_clock::now();
            const auto elapsedMs =
                std::chrono::duration_cast<std::chrono::milliseconds>(n - s_lastPresent).count();
            const int targetMs = 1000 / targetFps;
            if (elapsedMs < targetMs)
                std::this_thread::sleep_for(std::chrono::milliseconds(targetMs - elapsedMs));
            s_lastPresent = std::chrono::steady_clock::now();
        }

        const float clr[4] = { 0, 0, 0, 0 };
        g_pd3dDeviceContext->OMSetRenderTargets(1, &g_mainRenderTargetView, nullptr);
        g_pd3dDeviceContext->ClearRenderTargetView(g_mainRenderTargetView, clr);
        ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());
        g_pSwapChain->Present(0, 0);   // no vsync
    }

    SaveConfig();              

    StopReaderThread();
    isAttached = false;
    memory->Detach();

    ImGui_ImplDX11_Shutdown();
    ImGui_ImplWin32_Shutdown();
    ImGui::DestroyContext();
    CleanupDeviceD3D();
    ::DestroyWindow(hwnd);
    ::UnregisterClassW(wc.lpszClassName, wc.hInstance);

    if (g_mouseHook) {
        UnhookWindowsHookEx(g_mouseHook);
        g_mouseHook = NULL;
    }

    DebugLog("=== SHUTDOWN ===");
    return 0;
}

LRESULT WINAPI WndProc(HWND h, UINT m, WPARAM w, LPARAM l) {
    if (ImGui_ImplWin32_WndProcHandler(h, m, w, l)) return true;
    switch (m) {
    case WM_SIZE:
        if (g_pd3dDevice && w != SIZE_MINIMIZED) {
            CleanupRenderTarget();
            g_pSwapChain->ResizeBuffers(0, (UINT)LOWORD(l), (UINT)HIWORD(l), DXGI_FORMAT_UNKNOWN, 0);
            CreateRenderTarget();
        }
        return 0;
    case WM_SYSCOMMAND: if ((w & 0xfff0) == SC_KEYMENU) return 0; break;
    case WM_DESTROY: ::PostQuitMessage(0); return 0;
    }
    return ::DefWindowProcW(h, m, w, l);
}
static bool CreateDeviceD3D(HWND h) {
    DXGI_SWAP_CHAIN_DESC sd{}; sd.BufferCount = 2;
    sd.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
    sd.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
    sd.OutputWindow = h; sd.SampleDesc.Count = 1; sd.Windowed = TRUE;
    sd.SwapEffect = DXGI_SWAP_EFFECT_DISCARD;
    D3D_FEATURE_LEVEL fl;
    const D3D_FEATURE_LEVEL fa[2] = { D3D_FEATURE_LEVEL_11_0, D3D_FEATURE_LEVEL_10_0 };
    if (D3D11CreateDeviceAndSwapChain(nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr, 0, fa, 2,
        D3D11_SDK_VERSION, &sd, &g_pSwapChain, &g_pd3dDevice, &fl, &g_pd3dDeviceContext) != S_OK) return false;

    // Cap frame queue at 1 → lower latency, less GPU overdraw.
    IDXGIDevice1* dev1 = nullptr;
    if (SUCCEEDED(g_pd3dDevice->QueryInterface(IID_PPV_ARGS(&dev1))) && dev1) {
        dev1->SetMaximumFrameLatency(1);
        dev1->Release();
    }

    CreateRenderTarget(); return true;
}
static void CleanupDeviceD3D() {
    CleanupRenderTarget();
    if (g_pSwapChain) { g_pSwapChain->Release(); g_pSwapChain = nullptr; }
    if (g_pd3dDeviceContext) { g_pd3dDeviceContext->Release(); g_pd3dDeviceContext = nullptr; }
    if (g_pd3dDevice) { g_pd3dDevice->Release(); g_pd3dDevice = nullptr; }
}
static void CreateRenderTarget() {
    ID3D11Texture2D* bb = nullptr;
    g_pSwapChain->GetBuffer(0, IID_PPV_ARGS(&bb));
    if (bb) { g_pd3dDevice->CreateRenderTargetView(bb, nullptr, &g_mainRenderTargetView); bb->Release(); }
}
static void CleanupRenderTarget() {
    if (g_mainRenderTargetView) { g_mainRenderTargetView->Release(); g_mainRenderTargetView = nullptr; }
}