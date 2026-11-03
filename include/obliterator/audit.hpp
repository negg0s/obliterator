#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include <string>
#include <string_view>

namespace obliterator {

class AuditJournal {
public:
    static std::wstring get_logs_directory();
    static std::wstring get_journal_file_path();

    // Logs an intent before executing a destructive action
    static void log_before(std::wstring_view action,
                           std::wstring_view target,
                           std::wstring_view details = {});

    // Logs the outcome after executing a destructive action
    static void log_after(std::wstring_view action,
                          std::wstring_view target,
                          bool success,
                          DWORD error_code = 0,
                          std::wstring_view details = {});

    // Performs size check and rotates log files if size exceeds max_bytes
    static void check_and_rotate(size_t max_bytes = 10 * 1024 * 1024, size_t max_backups = 5);
};

} // namespace obliterator
