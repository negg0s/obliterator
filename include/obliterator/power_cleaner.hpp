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

struct PowerCleanReport {
    size_t power_overrides_removed{0};
    std::vector<std::wstring> details;
};

class PowerCleaner {
public:
    static PowerCleanReport clean_power_overrides(const Target& target, bool dry_run);

private:
    static bool matches_target(const std::wstring& name, const Target& target);
};

} // namespace obliterator
