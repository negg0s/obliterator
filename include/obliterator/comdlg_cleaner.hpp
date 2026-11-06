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

struct ComDlgCleanReport {
    size_t last_visited_removed{0};
    size_t cid_size_removed{0};
    std::vector<std::wstring> details;
};

class ComDlgCleaner {
public:
    static ComDlgCleanReport clean_comdlg_mru(const Target& target, bool dry_run);

private:
    static bool matches_target_executable(const std::wstring& filename, const Target& target);
    static bool path_references_target(const std::wstring& path, const Target& target);
};

} // namespace obliterator
