#include "obliterator/process.hpp"
#include "obliterator/handles.hpp"
#include "obliterator/log.hpp"
#include "obliterator/path.hpp"
#include "obliterator/safety.hpp"
#include "obliterator/wiper.hpp"

#include <tlhelp32.h>

#include <algorithm>
#include <chrono>
#include <cwctype>
#include <queue>
#include <thread>
#include <unordered_map>
#include <unordered_set>

extern "C" {
__declspec(dllimport) LONG __stdcall NtSuspendProcess(HANDLE ProcessHandle);
}

namespace obliterator {

static std::wstring to_lower_string(std::wstring_view input) {
    std::wstring result(input);
    std::transform(result.begin(), result.end(), result.begin(), [](wchar_t c) {
        return static_cast<wchar_t>(std::towlower(c));
    });
    return result;
}

static bool times_equal(const FILETIME& a, const FILETIME& b) noexcept {
    return a.dwLowDateTime == b.dwLowDateTime && a.dwHighDateTime == b.dwHighDateTime;
}

bool ProcessManager::query_process_times(HANDLE process, FILETIME* creation_time) {
    if (process == nullptr || creation_time == nullptr) {
        return false;
    }
    FILETIME exit_time{}, kernel_time{}, user_time{};
    return GetProcessTimes(process, creation_time, &exit_time, &kernel_time, &user_time) != 0;
}

static std::wstring query_image_path(HANDLE process) {
    std::wstring buffer(MAX_PATH, L'\0');
    DWORD size = static_cast<DWORD>(buffer.size());
    if (QueryFullProcessImageNameW(process, 0, buffer.data(), &size)) {
        buffer.resize(size);
        return buffer;
    }

    buffer.resize(32768);
    size = static_cast<DWORD>(buffer.size());
    if (QueryFullProcessImageNameW(process, 0, buffer.data(), &size)) {
        buffer.resize(size);
        return buffer;
    }

    return {};
}

DWORD ProcessManager::get_parent_process_id(DWORD pid) {
    UniqueHandle snap(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
    if (!snap) {
        return 0;
    }

    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(pe);
    if (!Process32FirstW(snap.get(), &pe)) {
        return 0;
    }

    do {
        if (pe.th32ProcessID == pid) {
            return pe.th32ParentProcessID;
        }
    } while (Process32NextW(snap.get(), &pe));

    return 0;
}

bool ProcessManager::is_system_process(const std::wstring& image_path) {
    if (image_path.empty()) {
        return false;
    }

    static const std::wstring lower_win = []() {
        wchar_t win_dir[MAX_PATH]{};
        if (GetWindowsDirectoryW(win_dir, MAX_PATH) > 0) {
            return to_lower_string(SafetyValidator::normalize_path(win_dir));
        }
        return std::wstring(L"c:\\windows");
    }();

    static const std::wstring lower_sys = []() {
        wchar_t sys_dir[MAX_PATH]{};
        if (GetSystemDirectoryW(sys_dir, MAX_PATH) > 0) {
            return to_lower_string(SafetyValidator::normalize_path(sys_dir));
        }
        return std::wstring(L"c:\\windows\\system32");
    }();

    const std::wstring lower = to_lower_string(image_path);
    if (lower == lower_win || lower.starts_with(lower_win + L"\\")) {
        return true;
    }
    if (lower == lower_sys || lower.starts_with(lower_sys + L"\\")) {
        return true;
    }

    return false;
}

static bool folder_has_modules(const std::wstring& target_root_path) {
    WIN32_FIND_DATAW fd{};
    std::wstring ext_path = FileWiper::ensure_extended_path(target_root_path);
    UniqueFindHandle h(FindFirstFileW((ext_path + L"\\*.dll").c_str(), &fd));
    if (h) {
        return true;
    }
    UniqueFindHandle hExe(FindFirstFileW((ext_path + L"\\*.exe").c_str(), &fd));
    if (hExe) {
        return true;
    }

    UniqueFindHandle hDir(FindFirstFileW((ext_path + L"\\*").c_str(), &fd));
    if (hDir) {
        do {
            if ((fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) &&
                wcscmp(fd.cFileName, L".") != 0 && wcscmp(fd.cFileName, L"..") != 0) {
                std::wstring sub = ext_path + L"\\" + fd.cFileName;
                UniqueFindHandle hSub(FindFirstFileW((sub + L"\\*.dll").c_str(), &fd));
                if (hSub) {
                    return true;
                }
            }
        } while (FindNextFileW(hDir.get(), &fd));
    }
    return false;
}

static bool process_has_module_in_path(DWORD pid, const std::wstring& target_root_path) {
    UniqueHandle snapshot(CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid));
    if (!snapshot) {
        return false;
    }

    MODULEENTRY32W me{};
    me.dwSize = sizeof(me);
    if (!Module32FirstW(snapshot.get(), &me)) {
        return false;
    }

    do {
        if (PathHelper::is_same_or_subpath(target_root_path, me.szExePath)) {
            return true;
        }
    } while (Module32NextW(snapshot.get(), &me));

    return false;
}

std::vector<ProcessInfo> ProcessManager::find_target_processes(const std::wstring& target_root_path) {
    std::vector<ProcessInfo> results;
    if (target_root_path.empty()) {
        return results;
    }

    UniqueHandle snap(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
    if (!snap) {
        return results;
    }

    const DWORD self_pid = GetCurrentProcessId();
    DWORD parent_pid = 0;

    struct RawEntry {
        DWORD pid;
        DWORD parent_pid;
        std::wstring name;
    };
    std::vector<RawEntry> all_processes;

    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(pe);
    if (!Process32FirstW(snap.get(), &pe)) {
        return results;
    }

    do {
        if (pe.th32ProcessID == self_pid) {
            parent_pid = pe.th32ParentProcessID;
        }
        all_processes.push_back({pe.th32ProcessID, pe.th32ParentProcessID, pe.szExeFile});
    } while (Process32NextW(snap.get(), &pe));

    std::unordered_set<DWORD> excluded_pids = {0, 4, self_pid};
    if (parent_pid != 0) {
        excluded_pids.insert(parent_pid);
    }

    const bool may_have_modules = folder_has_modules(target_root_path);

    std::unordered_map<DWORD, std::vector<DWORD>> parent_to_children;
    for (const auto& item : all_processes) {
        parent_to_children[item.parent_pid].push_back(item.pid);
    }

    std::unordered_map<DWORD, ProcessInfo> matched_map;
    std::unordered_set<DWORD> system_pids;

    for (const auto& item : all_processes) {
        if (excluded_pids.contains(item.pid)) {
            continue;
        }

        UniqueHandle proc(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, item.pid));
        if (!proc) {
            continue;
        }

        FILETIME creation_time{};
        if (!query_process_times(proc.get(), &creation_time)) {
            continue;
        }

        const std::wstring image_path = query_image_path(proc.get());
        if (is_system_process(image_path)) {
            system_pids.insert(item.pid);
            continue;
        }

        bool is_match = false;
        bool by_module = false;

        if (PathHelper::is_same_or_subpath(target_root_path, image_path)) {
            is_match = true;
        } else if (may_have_modules && process_has_module_in_path(item.pid, target_root_path)) {
            is_match = true;
            by_module = true;
        }

        if (is_match) {
            matched_map[item.pid] = ProcessInfo{
                item.pid,
                item.parent_pid,
                creation_time,
                item.name,
                image_path,
                by_module,
                false
            };
        }
    }

    // Traverse descendants of all matched processes
    std::queue<DWORD> queue;
    for (const auto& [pid, _] : matched_map) {
        queue.push(pid);
    }

    while (!queue.empty()) {
        const DWORD current_pid = queue.front();
        queue.pop();

        auto it = parent_to_children.find(current_pid);
        if (it == parent_to_children.end()) {
            continue;
        }

        for (DWORD child_pid : it->second) {
            if (excluded_pids.contains(child_pid) || system_pids.contains(child_pid)) {
                continue;
            }
            if (matched_map.contains(child_pid)) {
                continue;
            }

            UniqueHandle child_proc(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, child_pid));
            if (!child_proc) {
                continue;
            }

            const std::wstring child_image = query_image_path(child_proc.get());
            if (is_system_process(child_image)) {
                system_pids.insert(child_pid);
                continue;
            }

            FILETIME child_creation{};
            if (!query_process_times(child_proc.get(), &child_creation)) {
                continue;
            }

            std::wstring child_name;
            for (const auto& item : all_processes) {
                if (item.pid == child_pid) {
                    child_name = item.name;
                    break;
                }
            }

            ProcessInfo child_info{
                child_pid,
                current_pid,
                child_creation,
                child_name,
                child_image,
                false,
                true
            };

            matched_map[child_pid] = child_info;
            queue.push(child_pid);
        }
    }

    for (auto& [_, info] : matched_map) {
        results.push_back(std::move(info));
    }

    return results;
}

size_t ProcessManager::suspend_target_processes(const std::wstring& target_root_path) {
    if (target_root_path.empty()) {
        return 0;
    }

    const auto targets = find_target_processes(target_root_path);
    size_t suspended_count = 0;

    for (const auto& proc : targets) {
        UniqueHandle h(OpenProcess(PROCESS_SUSPEND_RESUME | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, proc.pid));
        if (!h) {
            continue;
        }

        FILETIME current_creation{};
        if (!query_process_times(h.get(), &current_creation) ||
            !times_equal(current_creation, proc.creation_time)) {
            continue;
        }

        if (NtSuspendProcess(h.get()) >= 0) {
            suspended_count++;
            Logger::debug(L"Frozen process: " + proc.name + L" (PID: " + std::to_wstring(proc.pid) + L")");
        }
    }

    return suspended_count;
}

ProcessReport ProcessManager::terminate_target_processes(const std::wstring& target_root_path,
                                                       uint32_t timeout_seconds) {
    ProcessReport report;
    std::unordered_set<DWORD> counted_pids;

    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(timeout_seconds);

    while (true) {
        auto targets = find_target_processes(target_root_path);
        if (targets.empty()) {
            break;
        }

        for (const auto& t : targets) {
            if (counted_pids.insert(t.pid).second) {
                report.found++;
            }
        }

        struct ActiveTarget {
            ProcessInfo info;
            UniqueHandle handle;
        };
        std::vector<ActiveTarget> active;

        for (const auto& proc : targets) {
            const DWORD access = PROCESS_SUSPEND_RESUME | PROCESS_TERMINATE |
                                PROCESS_QUERY_LIMITED_INFORMATION;
            UniqueHandle h(OpenProcess(access, FALSE, proc.pid));
            if (!h) {
                const DWORD err = GetLastError();
                const bool is_prot = (err == ERROR_ACCESS_DENIED);
                report.failed++;
                report.failures.push_back({
                    proc.pid,
                    proc.name,
                    proc.image_path,
                    err,
                    Win32Error::from_code(err).message(),
                    is_prot
                });

                if (is_prot) {
                    Logger::warn(L"Protected process detected: " + proc.name + L" (PID: " +
                                 std::to_wstring(proc.pid) + L"), error " + std::to_wstring(err) +
                                 L": " + Win32Error::from_code(err).message() +
                                 L" (kernel callback or PPL protection active)");
                }
                continue;
            }

            FILETIME current_creation{};
            if (!query_process_times(h.get(), &current_creation) ||
                !times_equal(current_creation, proc.creation_time)) {
                // Process identity mismatch; PID was recycled
                continue;
            }

            active.push_back({proc, std::move(h)});
        }

        // Freeze all target processes simultaneously to prevent watchdog respawning
        for (auto& item : active) {
            NtSuspendProcess(item.handle.get());
        }

        // Terminate all target processes after the whole set is suspended
        for (auto& item : active) {
            if (TerminateProcess(item.handle.get(), 1)) {
                report.killed++;
            } else {
                const DWORD err = GetLastError();
                DWORD exit_code = 0;
                if (GetExitCodeProcess(item.handle.get(), &exit_code) &&
                    exit_code != STILL_ACTIVE) {
                    report.killed++;
                } else {
                    const bool is_prot = (err == ERROR_ACCESS_DENIED);
                    report.failed++;
                    report.failures.push_back({
                        item.info.pid,
                        item.info.name,
                        item.info.image_path,
                        err,
                        Win32Error::from_code(err).message(),
                        is_prot
                    });

                    if (is_prot) {
                        Logger::warn(L"Protected process could not be terminated: " + item.info.name +
                                     L" (PID: " + std::to_wstring(item.info.pid) + L"), error " +
                                     std::to_wstring(err) + L": " + Win32Error::from_code(err).message());
                    }
                }
            }
        }

        if (std::chrono::steady_clock::now() >= deadline) {
            Logger::warn("Process termination reached configured timeout");
            break;
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    return report;
}

} // namespace obliterator
