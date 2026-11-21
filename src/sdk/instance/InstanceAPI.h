#pragma once
// ============================================================================
// InstanceAPI — live attribute and tag reader for Roblox instances
// ============================================================================
// Provides HasTag() and typed GetAttr*() functions that read attribute/tag
// data from live Roblox memory, using the offsets discovered by the external
// calibration dumper (custom_offsets_*.json).
//
// PREREQUISITES — the loader must provide:
//   * struct Process { HANDLE h; DWORD pid; uintptr_t base; };
//   * bool Peek(const Process&, uintptr_t addr, void* out, SIZE_T sz);
// ============================================================================
#include <windows.h>
#include <cstdint>
#include <string>
#include <vector>
#include <map>
#include <optional>
#include <fstream>
#include <nlohmann/json.hpp>
#include "../SDK.h"

void ClearTagCache();

struct Process {
    HANDLE    h = nullptr;
    DWORD     pid = 0;
    uintptr_t base = 0;
};

extern bool Peek(const Process& p, uintptr_t addr, void* out, SIZE_T sz);

// ============================================================================
// Value types (14 attribute types supported) // deleted two because sdk.h already has them
// ============================================================================
struct Color3 { float R = 0, G = 0, B = 0; };
struct UDim { float Scale = 0; int32_t Offset = 0; };
struct UDim2 { float ScaleX = 0, ScaleY = 0; int32_t OffsetX = 0, OffsetY = 0; };
struct Rect2D { float MinX = 0, MinY = 0, MaxX = 0, MaxY = 0; };
struct CFrameData {
    float R00, R01, R02, R10, R11, R12, R20, R21, R22;
    float X, Y, Z;
};
struct NumRange { float Min = 0, Max = 0; };
struct NumSeqKeypoint { float Time = 0, Value = 0, Envelope = 0; };
struct ColorSeqKeypoint { float Time = 0, R = 0, G = 0, B = 0; };
struct BrickColorData { int32_t Id = 0; };

// ============================================================================
// Attribute type identifiers
// ============================================================================
enum class AttrType {
    Bool, Number, String,
    Vector2, Vector3, Color3,
    CFrame, UDim, UDim2, BrickColor,
    ColorSequence, NumberRange, NumberSequence, Rect,
};

// ============================================================================
// TagPath — mirrors the JSON Tag.Paths[] structure
// ============================================================================
struct TagPath {
    enum class Mode { ComponentStruct, ComponentEntry, InstanceOffset } mode =
        Mode::ComponentStruct;
    uintptr_t instanceOff = 0;
    size_t    entryIndex = 0;
    uintptr_t vectorOff = 0;
    bool      vectorIsPtr = false;

    static Mode ModeFromString(const std::string& s);
};

// ============================================================================
// InstanceConfig — parsed custom_offsets JSON (JSONC-aware)
// ============================================================================
class InstanceConfig {
public:
    bool Load(const std::string& path);
    bool IsValid() const { return componentMap_ != 0 && attrSize_ != 0; }

    // Global offsets
    uintptr_t ComponentMap() const { return componentMap_; }
    uintptr_t AttrSize()     const { return attrSize_; }
    uintptr_t AttrKey()      const { return attrKey_; }
    int       ValueOffset(AttrType t) const;
    const std::string& StringLayout() const { return stringLayout_; }
    bool      StringNulTerm() const { return stringNulTerm_; }

    // Per-class data
    struct ClassInfo {
        std::string className;
        uintptr_t listingOff = 0;
        uintptr_t attrSize = 0;
        uintptr_t attrKey = 0;
        std::vector<TagPath> tagPaths;
    };
    const ClassInfo* FindClass(const std::string& cls) const;
    std::vector<TagPath> TagPathsFor(const std::string& cls) const;

    const std::string& RobloxVersion() const { return robloxVersion_; }

private:
    uintptr_t componentMap_ = 0;
    uintptr_t listingOffDefault_ = 0;
    uintptr_t attrSize_ = 0;
    uintptr_t attrKey_ = 0;
    std::map<AttrType, int> valueOffsets_;
    std::string stringLayout_ = "ptr-to-bytes";
    bool stringNulTerm_ = false;
    std::vector<TagPath> topLevelTagPaths_;
    std::map<std::string, ClassInfo> classes_;
    std::string robloxVersion_;
};

// ============================================================================
// InstanceAPI — public HasTag / GetAttribute API
// ============================================================================
class InstanceAPI {
public:
    InstanceAPI(const Process& p, const InstanceConfig& config);

    // ---- Attribute lookup ----
    uintptr_t FindAttributeEntry(uintptr_t inst, const std::string& name);
    std::vector<std::string> ListAttributeNames(uintptr_t inst);

    // ---- Typed getters ----
    std::optional<bool>           GetAttrBool(uintptr_t inst, const std::string& name);
    std::optional<double>         GetAttrNumber(uintptr_t inst, const std::string& name);
    std::optional<std::string>    GetAttrString(uintptr_t inst, const std::string& name);
    std::optional<Vector2>        GetAttrVector2(uintptr_t inst, const std::string& name);
    std::optional<Vector3>        GetAttrVector3(uintptr_t inst, const std::string& name);
    std::optional<Color3>         GetAttrColor3(uintptr_t inst, const std::string& name);
    std::optional<CFrameData>     GetAttrCFrame(uintptr_t inst, const std::string& name);
    std::optional<UDim>           GetAttrUDim(uintptr_t inst, const std::string& name);
    std::optional<UDim2>          GetAttrUDim2(uintptr_t inst, const std::string& name);
    std::optional<BrickColorData> GetAttrBrickColor(uintptr_t inst, const std::string& name);
    std::optional<NumRange>       GetAttrNumRange(uintptr_t inst, const std::string& name);
    std::optional<Rect2D>         GetAttrRect(uintptr_t inst, const std::string& name);
    std::optional<std::vector<NumSeqKeypoint>>   GetAttrNumSeq(uintptr_t inst, const std::string& name);
    std::optional<std::vector<ColorSeqKeypoint>> GetAttrColorSeq(uintptr_t inst, const std::string& name);

    // ---- Tags ----
    bool HasTag(uintptr_t inst, const std::string& tag);
    std::vector<std::string> ListTags(uintptr_t inst);

private:
    struct ResolvedAttrConfig {
        uintptr_t listingOff = 0;
        uintptr_t attrSize = 0;
        uintptr_t attrKey = 0;
    };
    std::optional<ResolvedAttrConfig> ResolveConfig(uintptr_t inst);
    uintptr_t TryFindEntry(uintptr_t inst, const std::string& name,
        uintptr_t listingOff, uintptr_t attrSize, uintptr_t attrKey);

    bool TryTagVector(uintptr_t vecAddr, const std::string& expected);
    bool TryTagPath(uintptr_t inst, const TagPath& path, const std::string& tag);
    uintptr_t ResolveTagPathAddress(uintptr_t inst, const TagPath& path);

    std::optional<std::string> ReadStringValue(uintptr_t valueAddr);

    const Process& p_;
    const InstanceConfig& config_;
};