#pragma once

#include <cstdint>
#include <filesystem>
#include <string>
#include <nlohmann/json.hpp>

namespace Offsets {

	// Downloads the latest offsets (if the Roblox version changed) and loads them into memory.
	// Call once at startup.
	void Initialize(const std::filesystem::path& cacheDir = {}, bool forceRefresh = false);

	bool IsInitialized();

	// Look up an offset by category and field name. Returns 0 if missing.
	uintptr_t Get(const char* category, const char* field);

	std::string RobloxVersion();
	int         Total();
	const nlohmann::json& Raw();

} // namespace Offsets