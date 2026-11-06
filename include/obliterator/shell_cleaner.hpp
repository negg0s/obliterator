#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include "obliterator/result.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace obliterator {

struct ShellExtensionInfo {
    std::wstring clsid;
    std::wstring name;
    std::wstring handler_key_path;
    std::wstring module_path;
    HKEY root_key{HKEY_CLASSES_ROOT};
    DWORD sam_view{0};
};

struct ShellCleanReport {
    size_t clsids_deleted{0};
    size_t context_menu_handlers_deleted{0};
    size_t icon_overlays_deleted{0};
    size_t approved_entries_deleted{0};
    std::vector<std::wstring> warnings;
};

class ShellCleaner {
public:
    // Finds all registered COM shell extensions, context menus, and icon overlays referencing target
    static std::vector<ShellExtensionInfo> find_target_shell_extensions(
        const std::wstring& target_root_path,
        std::wstring_view target_name = {}
    );

    // Removes identified shell extension registrations and refreshes Explorer shell cache
    static ShellCleanReport clean_shell_extensions(
        const std::wstring& target_root_path,
        std::wstring_view target_name = {}
    );

    // Signals Windows Explorer shell cache to drop orphaned icon and namespace caches
    static void notify_shell_cache_refresh();
};

} // namespace obliterator
