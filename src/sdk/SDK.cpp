#include "SDK.h"
#include "../core/Memory.h"
#include "../offsets/Offsets.h"

#include <nlohmann/json.hpp>
#include <cstring>
#include <cmath>
#include <fstream>
#include <unordered_set>
#include <unordered_map>

CustomOffsets g_customOffsets;

// =====================================================================
// Custom offset loader
// =====================================================================
void LoadCustomOffsets(const std::filesystem::path& jsonPath) {
    g_customOffsets = CustomOffsets{};

    std::ifstream f(jsonPath);
    if (!f.is_open()) return;

    try {
        auto j = nlohmann::json::parse(f);
        g_customOffsets.instanceComponentMap = j.value("Instance.ComponentMap", 0ull);
        g_customOffsets.attributeListingOff = j.value("Attribute.ListingOff", 0ull);
        g_customOffsets.attributeSize = j.value("Attribute.Size", 0ull);
        g_customOffsets.attributeKey = j.value("Attribute.Key", 0ull);

        // Value offset: pick any from ValueOffsets map (they're all the same
        // on current builds, but we take the first available).
        if (j.contains("Attribute.ValueOffsets") &&
            j["Attribute.ValueOffsets"].is_object() &&
            !j["Attribute.ValueOffsets"].empty()) {
            g_customOffsets.attributeValueOff =
                j["Attribute.ValueOffsets"].begin().value().get<uintptr_t>();
        }

        // Tag paths
        if (j.contains("Tag.Paths") && j["Tag.Paths"].is_array()) {
            for (const auto& e : j["Tag.Paths"]) {
                CustomOffsets::TagPath tp{};
                std::string mode = e.value("Mode", "");
                if (mode == "component_struct") tp.mode = CustomOffsets::TagPath::Mode::ComponentStruct;
                else if (mode == "component_entry") tp.mode = CustomOffsets::TagPath::Mode::ComponentEntry;
                else if (mode == "instance_offset") tp.mode = CustomOffsets::TagPath::Mode::InstanceOffset;
                else continue;
                tp.instanceOff = e.value("InstanceOff", 0ull);
                tp.entryIndex = e.value("EntryIndex", 0ull);
                tp.vectorOff = e.value("VectorOff", 0ull);
                tp.vectorIsPtr = e.value("VectorIsPtr", false);
                g_customOffsets.tagPaths.push_back(tp);
            }
        }

        g_customOffsets.loaded =
            g_customOffsets.instanceComponentMap != 0 &&
            g_customOffsets.attributeListingOff != 0 &&
            g_customOffsets.attributeSize != 0;
    }
    catch (...) {
        g_customOffsets = CustomOffsets{};
    }
}

// =====================================================================
// Instance accessors
// =====================================================================
std::string Instance::GetName() const {
    if (!address) return "None";
    uintptr_t nameContainer =
        memory->read<uintptr_t>(address + Offsets::Get("Instance", "NameContainer"));
    if (nameContainer) {
        std::string name = memory->read_string(nameContainer);
        if (name != "Unknown" && !name.empty()) return name;
    }
    return "Unknown";
}

std::string Instance::GetClass() const {
    if (!address) return "None";
    uintptr_t classDescriptor =
        memory->read<uintptr_t>(address + Offsets::Get("Instance", "ClassDescriptor"));
    if (!classDescriptor) return "Unknown";

    // ---- Class name cache keyed by ClassDescriptor pointer ----
    static std::unordered_map<uintptr_t, std::string> s_classCache;
    auto it = s_classCache.find(classDescriptor);
    if (it != s_classCache.end()) return it->second;

    uintptr_t classNamePtr =
        memory->read<uintptr_t>(classDescriptor + Offsets::Get("Instance", "ClassName"));
    std::string className = classNamePtr ? memory->read_string(classNamePtr) : std::string{};
    if (className.empty()) className = "Unknown";

    if (s_classCache.size() < 4096) s_classCache[classDescriptor] = className;
    return className;
}

std::vector<Instance> Instance::GetChildren() const {
    std::vector<Instance> children;
    if (!address) return children;
    uintptr_t vector_ptr =
        memory->read<uintptr_t>(address + Offsets::Get("Instance", "ChildrenStart"));
    if (!vector_ptr) return children;

    struct VecBounds { uintptr_t begin; uintptr_t end; } bounds{};
    if (!memory->read_raw(vector_ptr, &bounds, sizeof(bounds))) return children;
    if (!bounds.begin || !bounds.end || bounds.end < bounds.begin) return children;
    const size_t byteSpan = bounds.end - bounds.begin;
    if (byteSpan > 0x100000) return children;
    const size_t count = byteSpan / 0x10;
    if (count == 0) return children;

    thread_local std::vector<uint8_t> raw;
    raw.reserve(byteSpan);  // reserve once
    raw.resize(byteSpan);
    if (!memory->read_raw(bounds.begin, raw.data(), byteSpan)) return children;

    children.reserve(count);
    for (size_t i = 0; i < count; ++i) {
        uintptr_t child = 0;
        std::memcpy(&child, raw.data() + i * 0x10, sizeof(child));
        if (child) children.emplace_back(child);
    }
    return children;
}

uintptr_t Instance::FindFirstChild(const std::string& name) const {
    for (const auto& child : GetChildren())
        if (child.GetName() == name) return child.address;
    return 0;
}

uintptr_t Instance::FindFirstChildByClass(const std::string& className) const {
    for (const auto& child : GetChildren())
        if (child.GetClass() == className) return child.address;
    return 0;
}

// =====================================================================
// Tag vector helpers
// =====================================================================
static bool TryTagVec(uintptr_t vecAddr, const std::string& tag) {
    struct { uintptr_t begin, end, cap; } v{};
    if (!memory->read_raw(vecAddr, &v, sizeof(v))) return false;
    if (!v.begin || !v.end || v.end <= v.begin) return false;
    if ((v.end - v.begin) % 8 || (v.end - v.begin) > 0x4000) return false;

    for (uintptr_t p = v.begin; p < v.end; p += 8) {
        uintptr_t np = memory->read<uintptr_t>(p);
        if (np < 0x10000) continue;
        if (memory->read_string(np) == tag) return true;
    }
    return false;
}

static bool TryOneTagPath(uintptr_t instance, const CustomOffsets::TagPath& c,
    const std::string& tag) {
    if (c.mode == CustomOffsets::TagPath::Mode::InstanceOffset) {
        uintptr_t ptr = memory->read<uintptr_t>(instance + c.instanceOff);
        return ptr > 0x10000 && TryTagVec(ptr, tag);
    }
    uintptr_t comp = memory->read<uintptr_t>(instance + c.instanceOff);
    if (!comp) return false;

    if (c.mode == CustomOffsets::TagPath::Mode::ComponentStruct) {
        uintptr_t vec = c.vectorIsPtr ? memory->read<uintptr_t>(comp + c.vectorOff)
            : comp + c.vectorOff;
        return vec > 0x10000 && TryTagVec(vec, tag);
    }
    // ComponentEntry
    uintptr_t start = memory->read<uintptr_t>(comp + 0);
    uintptr_t end = memory->read<uintptr_t>(comp + 8);
    if (!start || !end || end <= start) return false;
    size_t slots = (end - start) / 0x10;
    auto tryEntry = [&](size_t si) {
        uintptr_t entry = memory->read<uintptr_t>(start + si * 0x10);
        if (!entry) return false;
        uintptr_t vec = c.vectorIsPtr ? memory->read<uintptr_t>(entry + c.vectorOff)
            : entry + c.vectorOff;
        return vec > 0x10000 && TryTagVec(vec, tag);
        };
    if (c.entryIndex < slots && tryEntry(c.entryIndex)) return true;
    for (size_t si = 0; si < slots && si < 32; ++si) {
        if (si == c.entryIndex) continue;
        if (tryEntry(si)) return true;
    }
    return false;
}

std::vector<std::string> Instance::GetTags() const {
    std::vector<std::string> tags;
    if (!address || !g_customOffsets.loaded) return tags;

    // Walk the first tag path that yields a vector; dedupe + collect names.
    for (const auto& c : g_customOffsets.tagPaths) {
        uintptr_t vecAddr = 0;
        if (c.mode == CustomOffsets::TagPath::Mode::InstanceOffset) {
            vecAddr = memory->read<uintptr_t>(address + c.instanceOff);
        }
        else {
            uintptr_t comp = memory->read<uintptr_t>(address + c.instanceOff);
            if (!comp) continue;
            if (c.mode == CustomOffsets::TagPath::Mode::ComponentStruct) {
                vecAddr = c.vectorIsPtr ? memory->read<uintptr_t>(comp + c.vectorOff)
                    : comp + c.vectorOff;
            }
            else {
                uintptr_t start = memory->read<uintptr_t>(comp + 0);
                uintptr_t end = memory->read<uintptr_t>(comp + 8);
                if (!start || !end || end <= start) continue;
                size_t slots = (end - start) / 0x10;
                for (size_t si = 0; si < slots && si < 32; ++si) {
                    uintptr_t entry = memory->read<uintptr_t>(start + si * 0x10);
                    if (!entry) continue;
                    vecAddr = c.vectorIsPtr ? memory->read<uintptr_t>(entry + c.vectorOff)
                        : entry + c.vectorOff;
                    if (vecAddr > 0x10000) break;
                }
            }
        }
        if (vecAddr < 0x10000) continue;

        struct { uintptr_t begin, end, cap; } v{};
        if (!memory->read_raw(vecAddr, &v, sizeof(v))) continue;
        if (!v.begin || !v.end || v.end <= v.begin) continue;
        if ((v.end - v.begin) % 8 || (v.end - v.begin) > 0x4000) continue;

        for (uintptr_t p = v.begin; p < v.end; p += 8) {
            uintptr_t np = memory->read<uintptr_t>(p);
            if (np < 0x10000) continue;
            std::string n = memory->read_string(np);
            if (!n.empty()) tags.push_back(std::move(n));
        }
        if (!tags.empty()) break;   // first working path wins
    }
    return tags;
}

bool Instance::HasTag(const std::string& tag) const {
    if (!address || !g_customOffsets.loaded) return false;
    for (const auto& c : g_customOffsets.tagPaths)
        if (TryOneTagPath(address, c, tag)) return true;
    return false;
}

// =====================================================================
// Attribute walk — presence + heuristic value decode
// =====================================================================
static bool LooksLikeNamePtr(uintptr_t ptr, std::string* out = nullptr) {
    if (ptr < 0x10000) return false;
    std::string s = memory->read_string(ptr);
    if (s.empty() || s.size() > 128) return false;
    for (unsigned char c : s) if (c < 0x20 || c > 0x7E) return false;
    if (out) *out = s;
    return true;
}

// Returns entry address (base of the 0x58-byte record) for the named
// attribute, or 0 if not found.
static uintptr_t FindAttributeEntry(uintptr_t instance, const std::string& target) {
    if (!g_customOffsets.loaded || !instance) return 0;

    uintptr_t comp = memory->read<uintptr_t>(instance + g_customOffsets.instanceComponentMap);
    if (!comp) return 0;
    uintptr_t start = memory->read<uintptr_t>(comp + 0);
    uintptr_t end = memory->read<uintptr_t>(comp + 8);
    if (!start || !end || end <= start) return 0;

    size_t slots = (end - start) / 0x10;
    if (slots > 2048) slots = 2048;

    for (size_t si = 0; si < slots; ++si) {
        uintptr_t entry = memory->read<uintptr_t>(start + si * 0x10);
        if (!entry) continue;
        uintptr_t listing = memory->read<uintptr_t>(entry + g_customOffsets.attributeListingOff);
        if (!listing) continue;

        for (int step = 0; step < 64; ++step) {
            uintptr_t entryAddr = listing + step * g_customOffsets.attributeSize;
            uintptr_t namePtr = memory->read<uintptr_t>(entryAddr + g_customOffsets.attributeKey);
            if (namePtr < 0x10000) break;
            std::string name;
            if (!LooksLikeNamePtr(namePtr, &name)) break;
            if (name == target) return entryAddr;
        }
    }
    return 0;
}

bool Instance::HasAttribute(const std::string& name) const {
    return FindAttributeEntry(address, name) != 0;
}

// Best-effort value decode. All calibrated types have their value at the
// same offset (+0x18), so we read at that offset and figure out what it is.
AttributeValue Instance::GetAttribute(const std::string& name) const {
    AttributeValue av;
    uintptr_t entryAddr = FindAttributeEntry(address, name);
    if (!entryAddr) return av;

    uintptr_t valAddr = entryAddr + g_customOffsets.attributeValueOff;

    // Try String first — MSVC std::string header at valAddr
    {
        struct { uint64_t bx0, bx1, size, cap; } hdr{};
        if (memory->read_raw(valAddr, &hdr, sizeof(hdr)) &&
            hdr.size > 0 && hdr.size < 512 && hdr.cap >= hdr.size && hdr.cap < 0x10000) {
            uintptr_t strAddr = (hdr.size >= 16) ? hdr.bx0 : valAddr;
            std::vector<char> buf((size_t)hdr.size);
            if (memory->read_raw(strAddr, buf.data(), buf.size())) {
                bool printable = true;
                for (char c : buf) {
                    if ((unsigned char)c < 0x20 || (unsigned char)c > 0x7E) { printable = false; break; }
                }
                if (printable) {
                    av.kind = AttributeValue::Kind::String;
                    av.str.assign(buf.data(), buf.size());
                    return av;
                }
            }
        }
    }

    // Try Bool — single byte at valAddr, remaining 7 bytes zero
    {
        uint8_t byte0 = memory->read<uint8_t>(valAddr);
        uint64_t tail = memory->read<uint64_t>(valAddr + 1);
        if ((byte0 == 0 || byte0 == 1) && tail == 0) {
            av.kind = AttributeValue::Kind::Bool;
            av.b = (byte0 != 0);
            return av;
        }
    }

    // Try Number — double
    {
        double d = memory->read<double>(valAddr);
        if (std::isfinite(d) && std::fabs(d) < 1e15) {
            av.kind = AttributeValue::Kind::Number;
            av.num = d;
            return av;
        }
    }

    av.kind = AttributeValue::Kind::Unknown;
    return av;
}

bool Instance::DebugListAttributes(std::vector<std::string>& out) const {
    out.clear();
    if (!address || !g_customOffsets.loaded) return false;

    uintptr_t comp = memory->read<uintptr_t>(address + g_customOffsets.instanceComponentMap);
    if (!comp) return false;
    uintptr_t start = memory->read<uintptr_t>(comp + 0);
    uintptr_t end = memory->read<uintptr_t>(comp + 8);
    if (!start || !end || end <= start) return false;

    size_t slots = (end - start) / 0x10;
    if (slots > 2048) slots = 2048;

    for (size_t si = 0; si < slots; ++si) {
        uintptr_t entry = memory->read<uintptr_t>(start + si * 0x10);
        if (!entry) continue;
        uintptr_t listing = memory->read<uintptr_t>(entry + g_customOffsets.attributeListingOff);
        if (!listing) continue;
        for (int step = 0; step < 64; ++step) {
            uintptr_t entryAddr = listing + step * g_customOffsets.attributeSize;
            uintptr_t namePtr = memory->read<uintptr_t>(entryAddr + g_customOffsets.attributeKey);
            if (namePtr < 0x10000) break;
            std::string name;
            if (!LooksLikeNamePtr(namePtr, &name)) break;
            char buf[160];
            snprintf(buf, sizeof(buf), "  %s  @0x%llX", name.c_str(),
                (unsigned long long)entryAddr);
            out.emplace_back(buf);
        }
    }
    return true;
}

// =====================================================================
// BasePart / Primitive
// =====================================================================
Vector3 Instance::GetPosition() const {
    if (!address) return { 0, 0, 0 };
    uintptr_t primitive =
        memory->read<uintptr_t>(address + Offsets::Get("BasePart", "Primitive"));
    if (!primitive) return { 0, 0, 0 };
    return memory->read<Vector3>(primitive + Offsets::Get("Primitive", "Position"));
}

Vector3 Instance::GetVelocity() const {
    if (!address) return { 0, 0, 0 };
    uintptr_t primitive =
        memory->read<uintptr_t>(address + Offsets::Get("BasePart", "Primitive"));
    if (!primitive) return { 0, 0, 0 };
    return memory->read<Vector3>(primitive + Offsets::Get("Primitive", "AssemblyLinearVelocity"));
}

void Instance::SetVelocity(Vector3 velocity) {
    if (!address) return;
    uintptr_t primitive =
        memory->read<uintptr_t>(address + Offsets::Get("BasePart", "Primitive"));
    if (primitive)
        memory->write<Vector3>(
            primitive + Offsets::Get("Primitive", "AssemblyLinearVelocity"), velocity);
}

void Instance::SetPosition(Vector3 position) {
    if (!address) return;
    uintptr_t primitive =
        memory->read<uintptr_t>(address + Offsets::Get("BasePart", "Primitive"));
    if (!primitive) return;
    memory->write<Vector3>(primitive + Offsets::Get("Primitive", "Position"), position);
    memory->write<Vector3>(primitive + Offsets::Get("Primitive", "AssemblyLinearVelocity"),
        { 0.0f, 0.0f, 0.0f });
}

void Instance::SetCanCollide(bool collide) {
    if (!address) return;
    uintptr_t primitive =
        memory->read<uintptr_t>(address + Offsets::Get("BasePart", "Primitive"));
    if (!primitive) return;
    uintptr_t flagsAddr = primitive + Offsets::Get("Primitive", "Flags");
    uint8_t   currentFlags = memory->read<uint8_t>(flagsAddr);
    if (collide) currentFlags |= 0x8;
    else         currentFlags &= ~0x8;
    memory->write<uint8_t>(flagsAddr, currentFlags);
}

// =====================================================================
// View matrix + projection
// =====================================================================
// ---- Cached VisualEngine pointer (invalidated on detach) ----
static uintptr_t g_veCached = 0;

void ResetViewMatrixCache() {
    g_veCached = 0;
}

Matrix4x4 GetViewMatrix() {
    Matrix4x4 matrix{};
    if (!g_veCached) {
        g_veCached = memory->read<uintptr_t>(
            memory->get_module_address() + Offsets::Get("VisualEngine", "Pointer"));
    }
    if (!g_veCached) return matrix;
    uintptr_t matrixAddr = g_veCached + Offsets::Get("VisualEngine", "ViewMatrix");
    if (!memory->read_raw(matrixAddr, &matrix, sizeof(matrix))) {
        // Read failed → pointer is dead (process re-attached, page unmapped).
        // Clear the cache so next frame re-resolves.
        g_veCached = 0;
        return Matrix4x4{};
    }
    return matrix;
}

bool WorldToScreen(Vector3 pos, Matrix4x4 matrix,
    int screenWidth, int screenHeight, Vector2& out) {
    float clipX = (matrix.m[0][0] * pos.x) + (matrix.m[0][1] * pos.y) +
        (matrix.m[0][2] * pos.z) + matrix.m[0][3];
    float clipY = (matrix.m[1][0] * pos.x) + (matrix.m[1][1] * pos.y) +
        (matrix.m[1][2] * pos.z) + matrix.m[1][3];
    float clipW = (matrix.m[3][0] * pos.x) + (matrix.m[3][1] * pos.y) +
        (matrix.m[3][2] * pos.z) + matrix.m[3][3];
    if (clipW < 0.1f) return false;
    float ndcX = clipX / clipW;
    float ndcY = clipY / clipW;
    out.x = (screenWidth / 2.0f) + (ndcX * screenWidth / 2.0f);
    out.y = (screenHeight / 2.0f) - (ndcY * screenHeight / 2.0f);
    if (out.x < 0 || out.x > screenWidth || out.y < 0 || out.y > screenHeight) return false;
    return true;
}