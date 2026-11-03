#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include <string>
#include <vector>

namespace obliterator {

struct LockedFileInfo {
    std::wstring path;
    DWORD pid{0};
    std::wstring process_name;
};

struct UnlockReport {
    size_t restart_manager_processes{0};
    size_t handles_closed{0};
    std::vector<LockedFileInfo> locked_files;
};

class FileUnlocker {
public:
    static std::vector<LockedFileInfo> inspect_locks(const std::wstring& target_root_path);

    static UnlockReport release_locks(const std::wstring& target_root_path,
                                      bool enable_handle_kill = true);

    static bool is_critical_process(DWORD pid);
};

} // namespace obliterator
