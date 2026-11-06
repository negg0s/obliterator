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

struct AutoPlayCleanReport {
    size_t autoplay_handlers_removed{0};
    size_t event_bindings_removed{0};
    std::vector<std::wstring> details;
};

class AutoPlayCleaner {
public:
    static AutoPlayCleanReport clean_autoplay_handlers(const Target& target, bool dry_run);

private:
    static bool is_protected_handler(const std::wstring& handler_name);
    static bool matches_target(const std::wstring& name, const Target& target);
    static bool path_references_target(const std::wstring& path, const Target& target);
};

} // namespace obliterator
