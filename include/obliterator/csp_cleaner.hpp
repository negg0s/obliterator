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

struct CspCleanReport {
    size_t providers_removed{0};
    size_t provider_types_cleaned{0};
    std::vector<std::wstring> details;
};

class CspCleaner {
public:
    static CspCleanReport clean_csps(const Target& target, bool dry_run);

private:
    static bool is_protected_provider(const std::wstring& name);
    static bool matches_target(const std::wstring& name, const Target& target);
    static bool path_references_target(const std::wstring& path, const Target& target);
};

} // namespace obliterator
