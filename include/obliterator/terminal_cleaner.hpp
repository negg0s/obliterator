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

struct TerminalCleanReport {
    size_t fragment_folders_removed{0};
    std::vector<std::wstring> details;
};

class TerminalCleaner {
public:
    static TerminalCleanReport clean_terminal_fragments(const Target& target, bool dry_run);

private:
    static bool matches_target(const std::wstring& name, const Target& target);
    static bool path_references_target(const std::wstring& path, const Target& target);
    static bool file_references_target(const std::wstring& file_path, const Target& target);
};

} // namespace obliterator
