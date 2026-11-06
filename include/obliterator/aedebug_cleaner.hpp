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

struct AeDebugCleanReport {
    size_t aedebug_hooks_reset{0};
    std::vector<std::wstring> details;
};

class AeDebugCleaner {
public:
    static AeDebugCleanReport clean_aedebug(const Target& target, bool dry_run);

private:
    static bool path_references_target(const std::wstring& path, const Target& target);
};

} // namespace obliterator
