#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include "obliterator/result.hpp"

#include <string>
#include <vector>

namespace obliterator {

struct ProcessInfo {
    DWORD pid{0};
    DWORD parent_pid{0};
    FILETIME creation_time{};
    std::wstring name;
    std::wstring image_path;
    bool matched_by_module{false};
    bool matched_as_descendant{false};
};

struct ProcessFailure {
    DWORD pid{0};
    std::wstring name;
    std::wstring image_path;
    std::wstring reason;
};

struct ProcessReport {
    size_t found{0};
    size_t killed{0};
    size_t failed{0};
    std::vector<ProcessFailure> failures;
};

class ProcessManager {
public:
    static std::vector<ProcessInfo> find_target_processes(const std::wstring& target_root_path);

    static ProcessReport terminate_target_processes(const std::wstring& target_root_path,
                                                   uint32_t timeout_seconds = 5);

    static DWORD get_parent_process_id(DWORD pid);
    static bool is_system_process(const std::wstring& image_path);
    static bool query_process_times(HANDLE process, FILETIME* creation_time);
};

} // namespace obliterator
