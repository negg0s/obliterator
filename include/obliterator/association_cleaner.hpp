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

struct AssociationCleanReport {
    size_t protocols_removed{0};
    size_t app_paths_removed{0};
    size_t file_exts_cleaned{0};
    std::vector<std::wstring> details;
};

class AssociationCleaner {
public:
    static AssociationCleanReport clean_associations(const Target& target, bool dry_run);

private:
    static void clean_url_protocols(const Target& target, bool dry_run, AssociationCleanReport& report);
    static void clean_app_paths(const Target& target, bool dry_run, AssociationCleanReport& report);
    static void clean_explorer_file_exts(const Target& target, bool dry_run, AssociationCleanReport& report);
    static bool path_references_target(const std::wstring& text, const Target& target);
    static bool is_protected_protocol(const std::wstring& protocol);
};

} // namespace obliterator
