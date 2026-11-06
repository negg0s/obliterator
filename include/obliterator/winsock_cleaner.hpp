#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include "obliterator/target.hpp"

#include <string>
#include <vector>

namespace obliterator {

struct WinsockCleanReport {
    size_t catalog_entries_removed{0};
    std::vector<std::wstring> details;
};

class WinsockCleaner {
public:
    static WinsockCleanReport clean_winsock_providers(const Target& target, bool dry_run);

private:
    static bool is_protected_provider(const std::wstring& lib_path, const std::wstring& display_name);
    static bool matches_target(const std::wstring& name, const Target& target);
    static bool path_references_target(const std::wstring& path, const Target& target);
};

} // namespace obliterator
