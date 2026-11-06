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

struct IfeoCleanReport {
    size_t target_keys_removed{0};
    size_t debugger_hooks_removed{0};
    std::vector<std::wstring> details;
};

class IfeoCleaner {
public:
    static IfeoCleanReport clean_ifeo_entries(const Target& target, bool dry_run);

private:
    static bool path_references_target(const std::wstring& path, const Target& target);
    static bool matches_target_executable(const std::wstring& filename, const Target& target);
};

} // namespace obliterator
