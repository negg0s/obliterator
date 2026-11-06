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

struct UserAssistCleanReport {
    size_t entries_removed{0};
    std::vector<std::wstring> details;
};

class UserAssistCleaner {
public:
    static UserAssistCleanReport clean_user_assist(const Target& target, bool dry_run);
    static std::wstring rot13(const std::wstring& input);

private:
    static bool path_references_target(const std::wstring& decoded_path, const Target& target);
};

} // namespace obliterator
