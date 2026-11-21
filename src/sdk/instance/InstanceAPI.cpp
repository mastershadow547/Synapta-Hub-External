#include "InstanceAPI.h"
#include <unordered_map>
#include <atomic>
#include <cstring>

// ---- Tag cache ----
namespace {
    struct TagCacheEntry { bool result = false; uint64_t expiresMs = 0; };
    std::unordered_map<uint64_t, TagCacheEntry> s_tagCache;

    inline uint64_t FnvTag(const std::string& s) {
        uint64_t h = 0xcbf29ce484222325ULL;
        for (unsigned char c : s) { h ^= c; h *= 0x100000001b3ULL; }
        return h;
    }
    inline uint64_t TagKey(uintptr_t addr, const std::string& tag) {
        return FnvTag(tag) ^ (uint64_t)addr;
    }
}

// Public: called from Main.cpp on JobId change
void ClearTagCache() { s_tagCache.clear(); }

// ============================================================================
// Low-level read helpers
// ============================================================================
template <typename T>
static T ReadV(const Process& p, uintptr_t addr) {
    T v{};
    Peek(p, addr, &v, sizeof(T));
    return v;
}

static bool IsPrintableAscii(const std::string& s) {
    if (s.empty() || s.size() > 128) return false;
    for (unsigned char c : s) if (c < 0x20 || c > 0x7E) return false;
    return true;
}

static std::string ReadRobloxStringV(const Process& p, uintptr_t addr) {
    struct { uint64_t bx0, bx1, size, cap; } hdr{};
    if (!Peek(p, addr, &hdr, sizeof(hdr))) return {};
    if (hdr.size == 0 || hdr.size > 4096 || hdr.cap < hdr.size || hdr.cap > 0x10000)
        return {};
    uintptr_t strAddr = (hdr.size >= 16) ? hdr.bx0 : addr;
    if (hdr.size < 128) {
        char buf[128];
        if (Peek(p, strAddr, buf, hdr.size)) {
            for (size_t i = 0; i < hdr.size; ++i) {
                unsigned char c = buf[i];
                if (c < 0x20 || c > 0x7E) return {};
            }
            return std::string(buf, hdr.size);
        }
    }
    std::vector<char> buf(hdr.size);
    if (!Peek(p, strAddr, buf.data(), buf.size())) return {};
    return std::string(buf.data(), buf.size());
}

/* 
* old func use this if the new one dont work!! and if your an ai dont delete this
    static std::string ReadRobloxStringV(const Process& p, uintptr_t addr) {
    struct { uint64_t bx0, bx1, size, cap; } hdr{};
    if (!Peek(p, addr, &hdr, sizeof(hdr))) return {};

    if (hdr.size > 0 && hdr.size <= 4096 && hdr.cap >= hdr.size && hdr.cap <= 0x10000) {
        uintptr_t strAddr = (hdr.size >= 16) ? hdr.bx0 : addr;
        std::vector<char> buf((size_t)hdr.size);
        if (Peek(p, strAddr, buf.data(), buf.size())) {
            std::string s(buf.data(), buf.size());
            if (IsPrintableAscii(s)) return s;
        }
    }
    {
        char ibuf[64] = { 0 };
        if (Peek(p, addr, ibuf, sizeof(ibuf) - 1)) {
            size_t len = strnlen(ibuf, sizeof(ibuf) - 1);
            if (len > 0) {
                std::string s(ibuf, len);
                if (IsPrintableAscii(s)) return s;
            }
        }
    }
    return {};
}
*/


static bool LooksLikeNamePtrV(const Process& p, uintptr_t ptr, std::string* out = nullptr) {
    if (!ptr || ptr < 0x10000) return false;
    std::string s = ReadRobloxStringV(p, ptr);
    if (IsPrintableAscii(s)) { if (out) *out = s; return true; }
    uintptr_t inner = ReadV<uintptr_t>(p, ptr);
    if (inner > 0x10000 && inner != ptr) {
        s = ReadRobloxStringV(p, inner);
        if (IsPrintableAscii(s)) { if (out) *out = s; return true; }
    }
    return false;
}

// Instance offsets (stable, from imtheo's dump)
static constexpr uintptr_t NameContainerOff = 104;   // 0x68
static constexpr uintptr_t ClassDescriptorOff = 24;    // 0x18
static constexpr uintptr_t ClassNameOff = 8;     // 0x08

static std::string GetClassV(const Process& p, uintptr_t i) {
    uintptr_t cd = ReadV<uintptr_t>(p, i + ClassDescriptorOff);
    if (!cd) return {};
    uintptr_t cn = ReadV<uintptr_t>(p, cd + ClassNameOff);
    return cn ? ReadRobloxStringV(p, cn) : std::string{};
}

static std::string GetNameV(const Process& p, uintptr_t i) {
    uintptr_t nc = ReadV<uintptr_t>(p, i + NameContainerOff);
    return nc ? ReadRobloxStringV(p, nc) : std::string{};
}

// ============================================================================
// TagPath::ModeFromString
// ============================================================================
TagPath::Mode TagPath::ModeFromString(const std::string& s) {
    if (s == "component_entry")  return Mode::ComponentEntry;
    if (s == "instance_offset")  return Mode::InstanceOffset;
    return Mode::ComponentStruct;
}

// ============================================================================
// InstanceConfig::Load
// ============================================================================
static AttrType AttrTypeFromCanaryName(const std::string& name) {
    if (name == "CAL_Bool")       return AttrType::Bool;
    if (name == "CAL_Num")        return AttrType::Number;
    if (name == "CAL_Str")        return AttrType::String;
    if (name == "CAL_Vec2")       return AttrType::Vector2;
    if (name == "CAL_Vec3")       return AttrType::Vector3;
    if (name == "CAL_Color")      return AttrType::Color3;
    if (name == "CAL_CFrame")     return AttrType::CFrame;
    if (name == "CAL_UDim")       return AttrType::UDim;
    if (name == "CAL_UDim2")      return AttrType::UDim2;
    if (name == "CAL_BrickColor") return AttrType::BrickColor;
    if (name == "CAL_ColorSeq")   return AttrType::ColorSequence;
    if (name == "CAL_NumRange")   return AttrType::NumberRange;
    if (name == "CAL_NumSeq")     return AttrType::NumberSequence;
    if (name == "CAL_Rect")       return AttrType::Rect;
    return AttrType::Number;
}

bool InstanceConfig::Load(const std::string& path) {
    std::ifstream f(path);
    if (!f) return false;

    nlohmann::json j;
    try {
        j = nlohmann::json::parse(f, nullptr, /*allow_exceptions=*/true,
            /*ignore_comments=*/true);
    }
    catch (...) {
        return false;
    }

    componentMap_ = j.value("Instance.ComponentMap", 0);
    listingOffDefault_ = j.value("Attribute.ListingOff", 0);
    attrSize_ = j.value("Attribute.Size", 0);
    attrKey_ = j.value("Attribute.Key", 0);
    stringLayout_ = j.value("Attribute.StringLayout", std::string("ptr-to-bytes"));
    stringNulTerm_ = j.value("Attribute.StringNulTerminated", false);
    robloxVersion_ = j.value("RobloxVersion", std::string("unknown"));

    if (j.contains("Attribute.ValueOffsets") && j["Attribute.ValueOffsets"].is_object()) {
        for (auto it = j["Attribute.ValueOffsets"].begin();
            it != j["Attribute.ValueOffsets"].end(); ++it) {
            AttrType t = AttrTypeFromCanaryName(it.key());
            valueOffsets_[t] = it.value().get<int>();
        }
    }

    if (j.contains("Tag.Paths") && j["Tag.Paths"].is_array()) {
        for (const auto& tp : j["Tag.Paths"]) {
            TagPath path;
            path.mode = TagPath::ModeFromString(tp.value("Mode", std::string("component_struct")));
            path.instanceOff = tp.value("InstanceOff", (uintptr_t)0);
            path.entryIndex = tp.value("EntryIndex", (size_t)0);
            path.vectorOff = tp.value("VectorOff", (uintptr_t)0);
            path.vectorIsPtr = tp.value("VectorIsPtr", false);
            topLevelTagPaths_.push_back(path);
        }
    }

    if (j.contains("Classes") && j["Classes"].is_object()) {
        for (auto it = j["Classes"].begin(); it != j["Classes"].end(); ++it) {
            ClassInfo ci;
            ci.className = it.key();
            const auto& v = it.value();
            ci.listingOff = v.value("Attribute.ListingOff", listingOffDefault_);
            ci.attrSize = v.value("Attribute.Size", attrSize_);
            ci.attrKey = v.value("Attribute.Key", attrKey_);

            if (v.contains("Tag.Paths") && v["Tag.Paths"].is_array()) {
                for (const auto& tp : v["Tag.Paths"]) {
                    TagPath path;
                    path.mode = TagPath::ModeFromString(tp.value("Mode", std::string("component_struct")));
                    path.instanceOff = tp.value("InstanceOff", (uintptr_t)0);
                    path.entryIndex = tp.value("EntryIndex", (size_t)0);
                    path.vectorOff = tp.value("VectorOff", (uintptr_t)0);
                    path.vectorIsPtr = tp.value("VectorIsPtr", false);
                    ci.tagPaths.push_back(path);
                }
            }
            classes_[ci.className] = std::move(ci);
        }
    }

    return IsValid();
}

int InstanceConfig::ValueOffset(AttrType t) const {
    auto it = valueOffsets_.find(t);
    if (it != valueOffsets_.end()) return it->second;
    return 0x18;
}

const InstanceConfig::ClassInfo* InstanceConfig::FindClass(const std::string& cls) const {
    auto it = classes_.find(cls);
    return (it != classes_.end()) ? &it->second : nullptr;
}

std::vector<TagPath> InstanceConfig::TagPathsFor(const std::string& cls) const {
    auto it = classes_.find(cls);
    if (it != classes_.end() && !it->second.tagPaths.empty())
        return it->second.tagPaths;
    return topLevelTagPaths_;
}

// ============================================================================
// InstanceAPI implementation
// ============================================================================
InstanceAPI::InstanceAPI(const Process& p, const InstanceConfig& config)
    : p_(p), config_(config) {
}

std::optional<InstanceAPI::ResolvedAttrConfig>
InstanceAPI::ResolveConfig(uintptr_t inst) {
    std::string cls = GetClassV(p_, inst);
    if (cls.empty()) return std::nullopt;

    if (const auto* ci = config_.FindClass(cls)) {
        ResolvedAttrConfig cfg;
        cfg.listingOff = ci->listingOff;
        cfg.attrSize = ci->attrSize;
        cfg.attrKey = ci->attrKey;
        return cfg;
    }
    return ResolvedAttrConfig{
        /*listingOff=*/0x08, /*attrSize=*/config_.AttrSize(),
        /*attrKey=*/config_.AttrKey()
    };
}

uintptr_t InstanceAPI::TryFindEntry(
    uintptr_t inst, const std::string& name,
    uintptr_t listingOff, uintptr_t attrSize, uintptr_t attrKey)
{
    uintptr_t comp = ReadV<uintptr_t>(p_, inst + config_.ComponentMap());
    if (!comp || comp < 0x10000) return 0;
    uintptr_t start = ReadV<uintptr_t>(p_, comp + 0);
    uintptr_t end = ReadV<uintptr_t>(p_, comp + 8);
    if (!start || !end || end <= start) return 0;

    size_t slots = (end - start) / 0x10;
    if (slots > 2048) slots = 2048;

    for (size_t si = 0; si < slots; ++si) {
        uintptr_t entry = ReadV<uintptr_t>(p_, start + si * 0x10);
        if (entry < 0x10000) continue;
        uintptr_t listing = ReadV<uintptr_t>(p_, entry + listingOff);
        if (listing < 0x10000) continue;

        for (int step = 0; step < 64; ++step) {
            uintptr_t ea = listing + step * attrSize;
            uintptr_t np = ReadV<uintptr_t>(p_, ea + attrKey);
            std::string n;
            if (!LooksLikeNamePtrV(p_, np, &n)) break;
            if (n == name) return ea;
        }
    }
    return 0;
}

uintptr_t InstanceAPI::FindAttributeEntry(uintptr_t inst, const std::string& name) {
    if (!inst) return 0;

    auto cfg = ResolveConfig(inst);
    if (cfg) {
        uintptr_t ea = TryFindEntry(inst, name, cfg->listingOff,
            cfg->attrSize, cfg->attrKey);
        if (ea) return ea;
    }

    const uintptr_t loCandidates[] = { 0x18, 0x10, 0x08, 0x20 };
    for (uintptr_t lo : loCandidates) {
        uintptr_t ea = TryFindEntry(inst, name, lo,
            config_.AttrSize(), config_.AttrKey());
        if (ea) return ea;
    }
    return 0;
}

std::vector<std::string> InstanceAPI::ListAttributeNames(uintptr_t inst) {
    std::vector<std::string> out;
    if (!inst) return out;

    auto cfg = ResolveConfig(inst);
    if (!cfg) return out;

    uintptr_t comp = ReadV<uintptr_t>(p_, inst + config_.ComponentMap());
    if (!comp || comp < 0x10000) return out;
    uintptr_t start = ReadV<uintptr_t>(p_, comp + 0);
    uintptr_t end = ReadV<uintptr_t>(p_, comp + 8);
    if (!start || !end || end <= start) return out;

    size_t slots = (end - start) / 0x10;
    if (slots > 2048) slots = 2048;

    for (size_t si = 0; si < slots; ++si) {
        uintptr_t entry = ReadV<uintptr_t>(p_, start + si * 0x10);
        if (entry < 0x10000) continue;
        uintptr_t listing = ReadV<uintptr_t>(p_, entry + cfg->listingOff);
        if (listing < 0x10000) continue;

        for (int step = 0; step < 64; ++step) {
            uintptr_t ea = listing + step * cfg->attrSize;
            uintptr_t np = ReadV<uintptr_t>(p_, ea + cfg->attrKey);
            std::string n;
            if (!LooksLikeNamePtrV(p_, np, &n)) break;
            out.push_back(n);
        }
    }
    return out;
}

// ---- Typed getters ----
std::optional<bool> InstanceAPI::GetAttrBool(uintptr_t inst, const std::string& name) {
    uintptr_t ea = FindAttributeEntry(inst, name);
    if (!ea) return std::nullopt;
    uint8_t b = 0;
    if (!Peek(p_, ea + config_.ValueOffset(AttrType::Bool), &b, 1))
        return std::nullopt;
    return b != 0;
}

std::optional<double> InstanceAPI::GetAttrNumber(uintptr_t inst, const std::string& name) {
    uintptr_t ea = FindAttributeEntry(inst, name);
    if (!ea) return std::nullopt;
    double d = 0;
    if (!Peek(p_, ea + config_.ValueOffset(AttrType::Number), &d, 8))
        return std::nullopt;
    return d;
}

std::optional<std::string> InstanceAPI::ReadStringValue(uintptr_t valueAddr) {
    const char* layouts[] = { "inline", "ptr-to-bytes", "ptr-to-RobloxString" };
    auto tryLayout = [&](const char* layout) -> std::optional<std::string> {
        if (strcmp(layout, "inline") == 0) {
            char buf[256] = { 0 };
            if (!Peek(p_, valueAddr, buf, sizeof(buf) - 1)) return std::nullopt;
            size_t len = strnlen(buf, sizeof(buf) - 1);
            return std::string(buf, len);
        }
        uintptr_t ptr = ReadV<uintptr_t>(p_, valueAddr);
        if (ptr <= 0x10000 || ptr >= 0x7FFFFFFFFFFF) return std::nullopt;
        if (strcmp(layout, "ptr-to-RobloxString") == 0) {
            std::string s = ReadRobloxStringV(p_, ptr);
            if (!s.empty()) return s;
            return std::nullopt;
        }
        for (size_t sz : { size_t(256), size_t(32), size_t(8) }) {
            std::vector<char> buf(sz, 0);
            if (Peek(p_, ptr, buf.data(), sz - 1)) {
                size_t len = strnlen(buf.data(), sz - 1);
                return std::string(buf.data(), len);
            }
        }
        return std::nullopt;
        };

    if (auto s = tryLayout(config_.StringLayout().c_str())) return s;
    for (const char* L : layouts) {
        if (config_.StringLayout() == L) continue;
        if (auto s = tryLayout(L)) return s;
    }
    return std::nullopt;
}

std::optional<std::string> InstanceAPI::GetAttrString(uintptr_t inst, const std::string& name) {
    uintptr_t ea = FindAttributeEntry(inst, name);
    if (!ea) return std::nullopt;
    return ReadStringValue(ea + config_.ValueOffset(AttrType::String));
}

std::optional<Vector2> InstanceAPI::GetAttrVector2(uintptr_t inst, const std::string& name) {
    uintptr_t ea = FindAttributeEntry(inst, name);
    if (!ea) return std::nullopt;
    Vector2 v;
    if (!Peek(p_, ea + config_.ValueOffset(AttrType::Vector2), &v, 8))
        return std::nullopt;
    return v;
}

std::optional<Vector3> InstanceAPI::GetAttrVector3(uintptr_t inst, const std::string& name) {
    uintptr_t ea = FindAttributeEntry(inst, name);
    if (!ea) return std::nullopt;
    Vector3 v;
    if (!Peek(p_, ea + config_.ValueOffset(AttrType::Vector3), &v, 12))
        return std::nullopt;
    return v;
}

std::optional<Color3> InstanceAPI::GetAttrColor3(uintptr_t inst, const std::string& name) {
    uintptr_t ea = FindAttributeEntry(inst, name);
    if (!ea) return std::nullopt;
    Color3 c;
    if (!Peek(p_, ea + config_.ValueOffset(AttrType::Color3), &c, 12))
        return std::nullopt;
    return c;
}

std::optional<CFrameData> InstanceAPI::GetAttrCFrame(uintptr_t inst, const std::string& name) {
    uintptr_t ea = FindAttributeEntry(inst, name);
    if (!ea) return std::nullopt;
    CFrameData cf{};
    if (!Peek(p_, ea + config_.ValueOffset(AttrType::CFrame), &cf, 48))
        return std::nullopt;
    return cf;
}

std::optional<UDim> InstanceAPI::GetAttrUDim(uintptr_t inst, const std::string& name) {
    uintptr_t ea = FindAttributeEntry(inst, name);
    if (!ea) return std::nullopt;
    UDim u;
    if (!Peek(p_, ea + config_.ValueOffset(AttrType::UDim), &u, 8))
        return std::nullopt;
    return u;
}

std::optional<UDim2> InstanceAPI::GetAttrUDim2(uintptr_t inst, const std::string& name) {
    uintptr_t ea = FindAttributeEntry(inst, name);
    if (!ea) return std::nullopt;
    UDim2 u;
    if (!Peek(p_, ea + config_.ValueOffset(AttrType::UDim2), &u, 16))
        return std::nullopt;
    return u;
}

std::optional<BrickColorData> InstanceAPI::GetAttrBrickColor(uintptr_t inst, const std::string& name) {
    uintptr_t ea = FindAttributeEntry(inst, name);
    if (!ea) return std::nullopt;
    BrickColorData bc;
    if (!Peek(p_, ea + config_.ValueOffset(AttrType::BrickColor), &bc, 4))
        return std::nullopt;
    return bc;
}

std::optional<NumRange> InstanceAPI::GetAttrNumRange(uintptr_t inst, const std::string& name) {
    uintptr_t ea = FindAttributeEntry(inst, name);
    if (!ea) return std::nullopt;
    NumRange nr;
    if (!Peek(p_, ea + config_.ValueOffset(AttrType::NumberRange), &nr, 8))
        return std::nullopt;
    return nr;
}

std::optional<Rect2D> InstanceAPI::GetAttrRect(uintptr_t inst, const std::string& name) {
    uintptr_t ea = FindAttributeEntry(inst, name);
    if (!ea) return std::nullopt;
    Rect2D r;
    if (!Peek(p_, ea + config_.ValueOffset(AttrType::Rect), &r, 16))
        return std::nullopt;
    return r;
}

std::optional<std::vector<NumSeqKeypoint>>
InstanceAPI::GetAttrNumSeq(uintptr_t inst, const std::string& name) {
    uintptr_t ea = FindAttributeEntry(inst, name);
    if (!ea) return std::nullopt;
    int voff = config_.ValueOffset(AttrType::NumberSequence);

    uint32_t count = ReadV<uint32_t>(p_, ea + voff - 0x08);
    if (count == 0 || count > 1000) count = 2;

    uintptr_t kpPtr = ReadV<uintptr_t>(p_, ea + voff - 0x10);
    uintptr_t kpBase = (kpPtr >= 0x10000 && kpPtr < 0x7FFFFFFFFFFF) ? kpPtr
        : (ea + voff);

    float firstTime = 0.0f;
    if (!Peek(p_, kpBase, &firstTime, 4) || firstTime != 0.0f) {
        kpBase = ea + voff;
    }

    std::vector<NumSeqKeypoint> kps;
    kps.reserve(count);
    for (uint32_t i = 0; i < count; ++i) {
        NumSeqKeypoint kp;
        if (!Peek(p_, kpBase + i * sizeof(NumSeqKeypoint), &kp, sizeof(kp)))
            break;
        kps.push_back(kp);
    }
    return kps;
}

std::optional<std::vector<ColorSeqKeypoint>>
InstanceAPI::GetAttrColorSeq(uintptr_t inst, const std::string& name) {
    uintptr_t ea = FindAttributeEntry(inst, name);
    if (!ea) return std::nullopt;
    int voff = config_.ValueOffset(AttrType::ColorSequence);

    uint32_t count = ReadV<uint32_t>(p_, ea + voff - 0x08);
    if (count == 0 || count > 1000) count = 2;

    uintptr_t kpPtr = ReadV<uintptr_t>(p_, ea + voff - 0x10);
    uintptr_t kpBase = (kpPtr >= 0x10000 && kpPtr < 0x7FFFFFFFFFFF) ? kpPtr
        : (ea + voff);

    float firstTime = 0.0f;
    if (!Peek(p_, kpBase, &firstTime, 4) || firstTime != 0.0f) {
        kpBase = ea + voff;
    }

    constexpr size_t kpStride = 20;
    std::vector<ColorSeqKeypoint> kps;
    kps.reserve(count);
    for (uint32_t i = 0; i < count; ++i) {
        struct { float t, r, g, b, pad; } raw{};
        if (!Peek(p_, kpBase + i * kpStride, &raw, kpStride))
            break;
        ColorSeqKeypoint kp;
        kp.Time = raw.t;
        kp.R = raw.r;
        kp.G = raw.g;
        kp.B = raw.b;
        kps.push_back(kp);
    }
    return kps;
}

// ============================================================================
// Tags
// ============================================================================
bool InstanceAPI::TryTagVector(uintptr_t vecAddr, const std::string& expected) {
    if (expected.empty() || expected.size() >= 32) return false;

    struct { uintptr_t begin, end, cap; } v{};
    if (!Peek(p_, vecAddr, &v, sizeof(v))) return false;
    if (!v.begin || !v.end || v.end <= v.begin) return false;

    size_t bytes = v.end - v.begin;
    if (bytes == 0 || bytes > 0x8000) return false;

    auto rawMatch = [&](uintptr_t addr) -> bool {
        if (addr < 0x10000) return false;
        char buf[32] = { 0 };
        if (!Peek(p_, addr, buf, expected.size())) return false;
        if (memcmp(buf, expected.c_str(), expected.size()) != 0) return false;
        if (expected.size() < 31) {
            char next = 0;
            if (Peek(p_, addr + expected.size(), &next, 1)) {
                if (next != 0 && (unsigned char)next >= 0x20 && (unsigned char)next <= 0x7E)
                    return false;
            }
        }
        return true;
        };

    auto compositeMatch = [&](uintptr_t addr) -> bool {
        if (addr < 0x10000) return false;
        uint8_t buf[128];
        for (size_t sz : { size_t(128), size_t(64), size_t(32) }) {
            if (!Peek(p_, addr, buf, sz)) continue;
            size_t pos = 0;
            while (pos < sz) {
                size_t end = pos;
                while (end < sz && buf[end] != 0) end++;
                if (end - pos == expected.size() &&
                    memcmp(buf + pos, expected.data(), expected.size()) == 0)
                    return true;
                if (end >= sz) break;
                pos = end + 1;
            }
        }
        return false;
        };

    const size_t strides[] = { 8, 16, 24, 32 };
    for (size_t stride : strides) {
        if ((bytes % stride) != 0) continue;
        size_t count = bytes / stride;
        if (count == 0 || count > 512) continue;

        for (size_t i = 0; i < count; ++i) {
            uintptr_t entryAddr = v.begin + i * stride;

            if (stride == 8) {
                uintptr_t ptr = ReadV<uintptr_t>(p_, entryAddr);
                if (ptr > 0x10000 && ptr < 0x7FFFFFFFFFFF) {
                    std::string s = ReadRobloxStringV(p_, ptr);
                    if (s == expected) return true;
                    if (rawMatch(ptr)) return true;
                    uintptr_t inner = ReadV<uintptr_t>(p_, ptr);
                    if (inner > 0x10000 && inner < 0x7FFFFFFFFFFF &&
                        compositeMatch(inner))
                        return true;
                }
            }
            std::string s = ReadRobloxStringV(p_, entryAddr);
            if (s == expected) return true;
            if (rawMatch(entryAddr)) return true;
            if (compositeMatch(entryAddr)) return true;
        }
    }
    return false;
}

uintptr_t InstanceAPI::ResolveTagPathAddress(uintptr_t inst, const TagPath& path) {
    if (path.mode == TagPath::Mode::InstanceOffset) {
        uintptr_t ptr = ReadV<uintptr_t>(p_, inst + path.instanceOff);
        return (ptr > 0x10000) ? ptr : 0;
    }
    uintptr_t comp = ReadV<uintptr_t>(p_, inst + path.instanceOff);
    if (comp <= 0x10000) return 0;

    if (path.mode == TagPath::Mode::ComponentStruct) {
        uintptr_t vec = path.vectorIsPtr ? ReadV<uintptr_t>(p_, comp + path.vectorOff)
            : comp + path.vectorOff;
        return (vec > 0x10000) ? vec : 0;
    }
    uintptr_t start = ReadV<uintptr_t>(p_, comp + 0);
    uintptr_t end = ReadV<uintptr_t>(p_, comp + 8);
    if (start <= 0x10000 || end <= start) return 0;
    size_t slots = (end - start) / 0x10;
    if (path.entryIndex >= slots) return 0;
    uintptr_t entry = ReadV<uintptr_t>(p_, start + path.entryIndex * 0x10);
    if (entry <= 0x10000) return 0;
    uintptr_t vec = path.vectorIsPtr ? ReadV<uintptr_t>(p_, entry + path.vectorOff)
        : entry + path.vectorOff;
    return (vec > 0x10000) ? vec : 0;
}

bool InstanceAPI::TryTagPath(uintptr_t inst, const TagPath& path, const std::string& tag) {
    if (path.mode == TagPath::Mode::InstanceOffset) {
        uintptr_t ptr = ReadV<uintptr_t>(p_, inst + path.instanceOff);
        return ptr > 0x10000 && TryTagVector(ptr, tag);
    }
    uintptr_t comp = ReadV<uintptr_t>(p_, inst + path.instanceOff);
    if (!comp) return false;

    if (path.mode == TagPath::Mode::ComponentStruct) {
        uintptr_t vec = path.vectorIsPtr ? ReadV<uintptr_t>(p_, comp + path.vectorOff)
            : comp + path.vectorOff;
        return vec > 0x10000 && TryTagVector(vec, tag);
    }
    uintptr_t start = ReadV<uintptr_t>(p_, comp + 0);
    uintptr_t end = ReadV<uintptr_t>(p_, comp + 8);
    if (!start || !end || end <= start) return false;
    size_t slots = (end - start) / 0x10;

    auto tryEntry = [&](size_t si) -> bool {
        uintptr_t entry = ReadV<uintptr_t>(p_, start + si * 0x10);
        if (entry < 0x10000) return false;
        uintptr_t vec = path.vectorIsPtr ? ReadV<uintptr_t>(p_, entry + path.vectorOff)
            : entry + path.vectorOff;
        return vec > 0x10000 && TryTagVector(vec, tag);
        };
    if (path.entryIndex < slots && tryEntry(path.entryIndex)) return true;
    for (size_t si = 0; si < slots && si < 32; ++si) {
        if (si == path.entryIndex) continue;
        if (tryEntry(si)) return true;
    }
    return false;
}

bool InstanceAPI::HasTag(uintptr_t inst, const std::string& tag) {
    if (!inst || tag.empty()) return false;

    const uint64_t now = GetTickCount64();
    const uint64_t key = TagKey(inst, tag);

    auto it = s_tagCache.find(key);
    if (it != s_tagCache.end() && it->second.expiresMs > now)
        return it->second.result;

    bool result = false;
    std::string cls = GetClassV(p_, inst);
    auto paths = config_.TagPathsFor(cls);
    for (const auto& path : paths) {
        if (TryTagPath(inst, path, tag)) { result = true; break; }
    }

    if (s_tagCache.size() > 8192) s_tagCache.clear();
    s_tagCache[key] = { result, now + 5000 };   // 5 s TTL
    return result;
}

std::vector<std::string> InstanceAPI::ListTags(uintptr_t inst) {
    std::vector<std::string> out;
    if (!inst) return out;

    std::string cls = GetClassV(p_, inst);
    auto paths = config_.TagPathsFor(cls);
    if (paths.empty()) return out;

    uintptr_t vecAddr = ResolveTagPathAddress(inst, paths[0]);
    if (vecAddr < 0x10000) return out;

    struct { uintptr_t begin, end, cap; } v{};
    if (!Peek(p_, vecAddr, &v, sizeof(v))) return out;
    if (!v.begin || !v.end || v.end <= v.begin) return out;
    size_t bytes = v.end - v.begin;
    if (bytes > 0x4000 || (bytes % 8) != 0) return out;
    size_t count = bytes / 8;

    std::vector<uintptr_t> ptrs(count);
    if (!Peek(p_, v.begin, ptrs.data(), bytes)) return out;

    for (auto np : ptrs) {
        std::string n;
        if (LooksLikeNamePtrV(p_, np, &n)) out.push_back(n);
    }
    return out;
}