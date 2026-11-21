#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include <filesystem>

struct Vector3 { float x, y, z; };
struct Vector2 { float x, y; };
struct Matrix4x4 { float m[4][4]; };

// =====================================================================
// Calibrated offsets (loaded from custom_offsets.json)
// =====================================================================
struct CustomOffsets {
    uintptr_t instanceComponentMap = 0;
    uintptr_t attributeListingOff = 0;
    uintptr_t attributeSize = 0;
    uintptr_t attributeKey = 0;
    uintptr_t attributeValueOff = 0;

    struct TagPath {
        enum class Mode { ComponentStruct, ComponentEntry, InstanceOffset } mode;
        uintptr_t instanceOff = 0;
        size_t    entryIndex = 0;
        uintptr_t vectorOff = 0;
        bool      vectorIsPtr = false;
    };
    std::vector<TagPath> tagPaths;

    bool loaded = false;
};
extern CustomOffsets g_customOffsets;

void LoadCustomOffsets(const std::filesystem::path& jsonPath);

// =====================================================================
// Attribute value (decoded heuristic)
// =====================================================================
struct AttributeValue {
    enum class Kind : uint8_t { None, Bool, Number, String, Unknown };
    Kind        kind = Kind::None;
    bool        b = false;
    double      num = 0.0;
    std::string str;

    bool IsValid() const { return kind != Kind::None; }
    bool IsUnknown() const { return kind == Kind::Unknown; }
    bool ToBool() const {
        switch (kind) {
        case Kind::Bool:   return b;
        case Kind::Number: return num != 0.0;
        case Kind::String: return !str.empty();
        default:           return IsValid();
        }
    }
    operator bool() const { return IsValid(); }
};

// =====================================================================
// Instance
// =====================================================================
class Instance {
public:
    uintptr_t address = 0;

    Instance() = default;
    explicit Instance(uintptr_t addr) : address(addr) {}

    bool IsValid() const { return address != 0; }

    std::string           GetName() const;
    std::string           GetClass() const;
    std::vector<Instance> GetChildren() const;

    uintptr_t FindFirstChild(const std::string& name) const;
    uintptr_t FindFirstChildByClass(const std::string& className) const;

    // ---- Tags / attributes (uses g_customOffsets) ----
    std::vector<std::string> GetTags() const;
    bool                     HasTag(const std::string& tag) const;

    bool           HasAttribute(const std::string& name) const;
    AttributeValue GetAttribute(const std::string& name) const;

    // Debug helper — dumps raw attribute entries into `out`
    bool DebugListAttributes(std::vector<std::string>& out) const;

    // ---- BasePart / Primitive ----
    Vector3 GetPosition() const;
    Vector3 GetVelocity() const;
    void    SetVelocity(Vector3 velocity);
    void    SetPosition(Vector3 position);
    void    SetCanCollide(bool collide);
};

bool      WorldToScreen(Vector3 pos, Matrix4x4 matrix,
    int screenWidth, int screenHeight, Vector2& out);
Matrix4x4 GetViewMatrix();
void      ResetViewMatrixCache();