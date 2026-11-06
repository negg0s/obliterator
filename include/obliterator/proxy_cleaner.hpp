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

struct ProxyCleanReport {
    size_t proxy_settings_reset{0};
    std::vector<std::wstring> details;
};

class ProxyCleaner {
public:
    static ProxyCleanReport clean_proxy_settings(const Target& target, bool dry_run);

private:
    static bool path_references_target(const std::wstring& path, const Target& target);
    static bool matches_proxy_target(const Target& target);
    static void notify_wininet();
};

} // namespace obliterator
