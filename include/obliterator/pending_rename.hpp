#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include <string>
#include <utility>
#include <vector>

namespace obliterator {

struct PendingRenameEntry {
    std::wstring source_nt_path;
    std::wstring destination_nt_path; // Empty for deletion
};

class PendingRenameManager {
public:
    // Reads existing PendingFileRenameOperations from HKLM\SYSTEM\CurrentControlSet\Control\Session Manager
    static std::vector<PendingRenameEntry> read_entries();

    // Appends reboot deletion entries without overwriting existing entries
    // Each entry is converted to NT path format (\??\C:\path) with an empty destination
    static bool schedule_deletions(const std::vector<std::wstring>& file_or_dir_paths);
    static bool schedule_deletion(const std::wstring& file_or_dir_path);

    // Formats a Win32 or extended path into NT object namespace format (\??\...)
    static std::wstring to_nt_path(const std::wstring& path);

    // Parses a REG_MULTI_SZ buffer into pairs of source/dest
    static std::vector<PendingRenameEntry> parse_multi_sz(const wchar_t* buffer, size_t wchar_count);

    // Serializes pairs of source/dest into a REG_MULTI_SZ buffer ending with double null
    static std::vector<wchar_t> serialize_multi_sz(const std::vector<PendingRenameEntry>& entries);
};

} // namespace obliterator
