#include "obliterator/unlocker.hpp"
#include "obliterator/handles.hpp"
#include "obliterator/log.hpp"
#include "obliterator/process.hpp"
#include "obliterator/safety.hpp"

#include <restartmanager.h>

using NTSTATUS = LONG;
constexpr NTSTATUS kStatusInfoLengthMismatch = static_cast<NTSTATUS>(0xC0000004L);

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cwctype>
#include <filesystem>
#include <memory>
#include <thread>
#include <unordered_map>
#include <vector>

struct SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX {
    PVOID Object;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR HandleValue;
    ULONG GrantedAccess;
    USHORT CreatorBackTraceIndex;
    USHORT ObjectTypeIndex;
    ULONG HandleAttributes;
    ULONG Reserved;
};

struct SYSTEM_HANDLE_INFORMATION_EX {
    ULONG_PTR NumberOfHandles;
    ULONG_PTR Reserved;
    SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX Handles[1];
};

extern "C" {
__declspec(dllimport) LONG __stdcall NtQuerySystemInformation(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
);
}

namespace obliterator {

static std::wstring to_lower_string(std::wstring_view input) {
    std::wstring result(input);
    std::transform(result.begin(), result.end(), result.begin(), [](wchar_t c) {
        return static_cast<wchar_t>(std::towlower(c));
    });
    return result;
}

bool FileUnlocker::is_critical_process(DWORD pid) {
    if (pid == 0 || pid == 4) {
        return true;
    }

    const DWORD self_pid = GetCurrentProcessId();
    if (pid == self_pid) {
        return true;
    }

    const DWORD parent_pid = ProcessManager::get_parent_process_id(self_pid);
    if (pid == parent_pid) {
        return true;
    }

    static std::unordered_map<DWORD, bool> cache;
    auto it = cache.find(pid);
    if (it != cache.end()) {
        return it->second;
    }

    UniqueHandle h(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid));
    if (!h) {
        cache[pid] = true;
        return true;
    }

    wchar_t image_buf[MAX_PATH];
    DWORD size = MAX_PATH;
    if (QueryFullProcessImageNameW(h.get(), 0, image_buf, &size)) {
        std::filesystem::path p(image_buf);
        std::wstring name = to_lower_string(p.filename().wstring());
        if (name == L"smss.exe" || name == L"csrss.exe" || name == L"wininit.exe" ||
            name == L"services.exe" || name == L"lsass.exe" || name == L"system") {
            cache[pid] = true;
            return true;
        }
    }

    cache[pid] = false;
    return false;
}

static std::wstring query_handle_path_with_timeout(HANDLE handle, std::chrono::milliseconds timeout) {
    struct ResultHolder {
        std::wstring path;
        std::atomic<bool> done{false};
    };
    auto holder = std::make_shared<ResultHolder>();

    std::thread worker([handle, holder]() {
        wchar_t path_buf[MAX_PATH];
        DWORD len = GetFinalPathNameByHandleW(handle, path_buf, MAX_PATH, FILE_NAME_NORMALIZED);
        if (len > 0 && len < MAX_PATH) {
            holder->path.assign(path_buf, len);
        }
        holder->done.store(true, std::memory_order_release);
    });

    const auto start = std::chrono::steady_clock::now();
    while (!holder->done.load(std::memory_order_acquire)) {
        if (std::chrono::steady_clock::now() - start > timeout) {
            // Detach thread to avoid blocking if GetFinalPathNameByHandleW hangs on named pipes
            worker.detach();
            return {};
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(2));
    }

    if (worker.joinable()) {
        worker.join();
    }
    return holder->path;
}

std::vector<LockedFileInfo> FileUnlocker::inspect_locks(const std::wstring& target_root_path) {
    std::vector<LockedFileInfo> results;
    if (target_root_path.empty()) {
        return results;
    }

    std::vector<std::wstring> files_to_check;
    std::error_code ec;

    if (std::filesystem::is_directory(target_root_path, ec)) {
        size_t count = 0;
        for (const auto& entry : std::filesystem::recursive_directory_iterator(
                 target_root_path, std::filesystem::directory_options::skip_permission_denied, ec)) {
            if (entry.is_regular_file(ec)) {
                files_to_check.push_back(entry.path().wstring());
                if (++count >= 128) {
                    break;
                }
            }
        }
    } else if (std::filesystem::exists(target_root_path, ec)) {
        files_to_check.push_back(target_root_path);
    }

    if (files_to_check.empty()) {
        return results;
    }

    std::vector<const wchar_t*> c_paths;
    c_paths.reserve(files_to_check.size());
    for (const auto& f : files_to_check) {
        c_paths.push_back(f.c_str());
    }

    DWORD session_handle = 0;
    WCHAR session_key[CCH_RM_SESSION_KEY + 1] = {0};

    DWORD err = RmStartSession(&session_handle, 0, session_key);
    if (err != ERROR_SUCCESS) {
        return results;
    }

    err = RmRegisterResources(session_handle, static_cast<UINT>(c_paths.size()),
                              c_paths.data(), 0, nullptr, 0, nullptr);
    if (err == ERROR_SUCCESS) {
        UINT nProcInfoNeeded = 0;
        UINT nProcInfo = 0;
        DWORD dwRebootReasons = 0;

        err = RmGetList(session_handle, &nProcInfoNeeded, &nProcInfo, nullptr, &dwRebootReasons);
        if (err == ERROR_MORE_DATA && nProcInfoNeeded > 0) {
            std::vector<RM_PROCESS_INFO> apps(nProcInfoNeeded);
            nProcInfo = nProcInfoNeeded;
            err = RmGetList(session_handle, &nProcInfoNeeded, &nProcInfo, apps.data(), &dwRebootReasons);
            if (err == ERROR_SUCCESS) {
                for (UINT i = 0; i < nProcInfo; ++i) {
                    results.push_back({
                        target_root_path,
                        apps[i].Process.dwProcessId,
                        apps[i].strAppName
                    });
                }
            }
        }
    }

    RmEndSession(session_handle);
    return results;
}

UnlockReport FileUnlocker::release_locks(const std::wstring& target_root_path,
                                        bool enable_handle_kill) {
    UnlockReport report;
    report.locked_files = inspect_locks(target_root_path);
    report.restart_manager_processes = report.locked_files.size();

    if (!enable_handle_kill) {
        return report;
    }

    const std::wstring norm_target = SafetyValidator::normalize_path(target_root_path);
    const std::wstring lower_target = to_lower_string(norm_target);
    const std::wstring target_prefix = lower_target + L"\\";

    // Only scan system handles if files in target directory are still locked
    bool has_locked_files = false;
    std::error_code ec;
    if (std::filesystem::exists(norm_target, ec)) {
        if (std::filesystem::is_directory(norm_target, ec)) {
            for (const auto& entry : std::filesystem::recursive_directory_iterator(
                     norm_target, std::filesystem::directory_options::skip_permission_denied, ec)) {
                if (entry.is_regular_file(ec)) {
                    HANDLE h = CreateFileW(entry.path().c_str(), GENERIC_READ, 0, nullptr,
                                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
                    if (h == INVALID_HANDLE_VALUE) {
                        const DWORD err = GetLastError();
                        if (err == ERROR_SHARING_VIOLATION || err == ERROR_LOCK_VIOLATION) {
                            has_locked_files = true;
                            break;
                        }
                    } else {
                        CloseHandle(h);
                    }
                }
            }
        } else {
            HANDLE h = CreateFileW(norm_target.c_str(), GENERIC_READ, 0, nullptr,
                                   OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
            if (h == INVALID_HANDLE_VALUE) {
                const DWORD err = GetLastError();
                if (err == ERROR_SHARING_VIOLATION || err == ERROR_LOCK_VIOLATION) {
                    has_locked_files = true;
                }
            } else {
                CloseHandle(h);
            }
        }
    }

    if (!has_locked_files) {
        return report;
    }

    ULONG buffer_size = 1024 * 1024 * 4;
    std::vector<BYTE> buffer;
    NTSTATUS status = 0;
    ULONG return_length = 0;

    do {
        buffer.resize(buffer_size);
        status = NtQuerySystemInformation(64 /* SystemExtendedHandleInformation */,
                                          buffer.data(), buffer_size, &return_length);
        if (status == kStatusInfoLengthMismatch) {
            buffer_size = (return_length > buffer_size) ? (return_length + 1024 * 64) : (buffer_size * 2);
        }
    } while (status == kStatusInfoLengthMismatch && buffer_size <= 1024 * 1024 * 128);

    if (status < 0 || buffer.empty()) {
        return report;
    }

    const auto* handle_info = reinterpret_cast<const SYSTEM_HANDLE_INFORMATION_EX*>(buffer.data());
    const ULONG_PTR handle_count = handle_info->NumberOfHandles;

    std::unordered_map<DWORD, HANDLE> proc_cache;

    auto cleanup_proc_cache = [&proc_cache]() {
        for (auto& [_, h] : proc_cache) {
            if (h != nullptr && h != INVALID_HANDLE_VALUE) {
                CloseHandle(h);
            }
        }
        proc_cache.clear();
    };

    for (ULONG_PTR i = 0; i < handle_count; ++i) {
        const auto& entry = handle_info->Handles[i];
        const DWORD pid = static_cast<DWORD>(entry.UniqueProcessId);

        if (is_critical_process(pid)) {
            continue;
        }

        HANDLE hProc = nullptr;
        auto it = proc_cache.find(pid);
        if (it != proc_cache.end()) {
            hProc = it->second;
        } else {
            hProc = OpenProcess(PROCESS_DUP_HANDLE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
            proc_cache[pid] = hProc;
        }

        if (hProc == nullptr || hProc == INVALID_HANDLE_VALUE) {
            continue;
        }

        HANDLE local_handle = nullptr;
        if (!DuplicateHandle(hProc, reinterpret_cast<HANDLE>(entry.HandleValue),
                             GetCurrentProcess(), &local_handle, 0, FALSE, DUPLICATE_SAME_ACCESS)) {
            continue;
        }
        UniqueHandle scoped_local(local_handle);

        // Filter out pipes, character devices and sockets to prevent hangs
        if (GetFileType(local_handle) != FILE_TYPE_DISK) {
            continue;
        }

        const std::wstring raw_path =
            query_handle_path_with_timeout(local_handle, std::chrono::milliseconds(50));
        if (raw_path.empty()) {
            continue;
        }

        const std::wstring norm_path = SafetyValidator::normalize_path(raw_path);
        const std::wstring lower_path = to_lower_string(norm_path);

        if (lower_path == lower_target || lower_path.starts_with(target_prefix)) {
            // Close the handle inside the remote process
            if (DuplicateHandle(hProc, reinterpret_cast<HANDLE>(entry.HandleValue),
                                GetCurrentProcess(), nullptr, 0, FALSE, DUPLICATE_CLOSE_SOURCE)) {
                report.handles_closed++;
                Logger::debug(L"Closed file handle in PID " + std::to_wstring(pid) + L": " + norm_path);
            }
        }
    }

    cleanup_proc_cache();
    return report;
}

} // namespace obliterator
