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

struct WslCleanReport {
    size_t distros_removed{0};
    std::vector<std::wstring> details;
};

class WslCleaner {
public:
    static WslCleanReport clean_wsl_distros(const Target& target, bool dry_run);

private:
    static bool matches_target(const std::wstring& name, const Target& target);
    static bool path_references_target(const std::wstring& path, const Target& target);
};

} // namespace obliterator
