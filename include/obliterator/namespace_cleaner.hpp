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

struct NamespaceCleanReport {
    size_t mycomputer_entries_removed{0};
    size_t desktop_entries_removed{0};
    std::vector<std::wstring> details;
};

class NamespaceCleaner {
public:
    static NamespaceCleanReport clean_namespace_extensions(const Target& target, bool dry_run);

private:
    static bool matches_target(const std::wstring& name, const Target& target);
    static bool path_references_target(const std::wstring& path, const Target& target);
    static bool inspect_clsid_server(HKEY root, const std::wstring& clsid_str, const Target& target);
    static void notify_shell();
};

} // namespace obliterator
