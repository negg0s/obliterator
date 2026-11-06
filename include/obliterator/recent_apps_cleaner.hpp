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

struct RecentAppsCleanReport {
    size_t recent_apps_removed{0};
    std::vector<std::wstring> details;
};

class RecentAppsCleaner {
public:
    static RecentAppsCleanReport clean_recent_apps(const Target& target, bool dry_run);

private:
    static bool path_references_target(const std::wstring& path, const Target& target);
};

} // namespace obliterator
