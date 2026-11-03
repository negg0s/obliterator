#include "obliterator/service.hpp"
#include "obliterator/handles.hpp"
#include "obliterator/log.hpp"
#include "obliterator/path.hpp"
#include "obliterator/safety.hpp"

#include <comdef.h>
#include <taskschd.h>

#include <algorithm>
#include <chrono>
#include <cwctype>
#include <filesystem>
#include <thread>
#include <vector>

namespace obliterator {

class ScopedCom {
public:
    ScopedCom() noexcept : m_hr(CoInitializeEx(nullptr, COINIT_MULTITHREADED)) {}
    ~ScopedCom() noexcept {
        if (SUCCEEDED(m_hr)) {
            CoUninitialize();
        }
    }
    ScopedCom(const ScopedCom&) = delete;
    ScopedCom& operator=(const ScopedCom&) = delete;
    [[nodiscard]] bool ok() const noexcept { return SUCCEEDED(m_hr); }
private:
    HRESULT m_hr;
};

std::wstring ServiceManager::normalize_service_image_path(std::wstring_view raw_path) {
    while (!raw_path.empty() && (raw_path.front() == L' ' || raw_path.front() == L'\t')) {
        raw_path.remove_prefix(1);
    }
    while (!raw_path.empty() && (raw_path.back() == L' ' || raw_path.back() == L'\t')) {
        raw_path.remove_suffix(1);
    }
    if (raw_path.empty()) {
        return {};
    }

    std::wstring path(raw_path);

    // Strip NT kernel driver prefix
    if (path.starts_with(L"\\??\\") || path.starts_with(L"\\\\?\\")) {
        path.erase(0, 4);
    }
    if (path.empty()) {
        return {};
    }

    // Replace NT SystemRoot with environment variable prefix
    if (PathHelper::to_lower_unicode(path).starts_with(L"\\systemroot\\")) {
        path = L"%SystemRoot%\\" + path.substr(12);
    }

    // Handle quoted command lines
    if (!path.empty() && path.front() == L'\"') {
        const size_t end_quote = path.find(L'\"', 1);
        if (end_quote != std::wstring::npos) {
            path = path.substr(1, end_quote - 1);
        } else {
            path.erase(0, 1);
        }
    } else if (!path.empty()) {
        const std::wstring lower = PathHelper::to_lower_unicode(path);
        size_t cutoff = std::wstring::npos;
        auto find_ext_boundary = [&](std::wstring_view ext) -> size_t {
            size_t pos = 0;
            while ((pos = lower.find(ext, pos)) != std::wstring::npos) {
                const size_t end = pos + ext.size();
                if (end == lower.size() || lower[end] == L' ' || lower[end] == L'\t' || lower[end] == L'\"') {
                    return end;
                }
                pos = end;
            }
            return std::wstring::npos;
        };

        const size_t exe_pos = find_ext_boundary(L".exe");
        const size_t sys_pos = find_ext_boundary(L".sys");

        if (exe_pos != std::wstring::npos) {
            cutoff = exe_pos;
        } else if (sys_pos != std::wstring::npos) {
            cutoff = sys_pos;
        } else {
            const size_t space = path.find(L' ');
            if (space != std::wstring::npos) {
                cutoff = space;
            }
        }
        if (cutoff != std::wstring::npos) {
            path = path.substr(0, cutoff);
        }
    }

    if (path.empty()) {
        return {};
    }

    // Expand relative system driver paths like system32\drivers\foo.sys
    if (path.find(L':') == std::wstring::npos && !path.starts_with(L"\\\\") &&
        !path.starts_with(L"%")) {
        path = L"%SystemRoot%\\" + path;
    }

    return SafetyValidator::normalize_path(path);
}

static std::wstring get_service_binary_path(SC_HANDLE service) {
    DWORD bytes_needed = 0;
    QueryServiceConfigW(service, nullptr, 0, &bytes_needed);
    if (bytes_needed == 0) {
        return {};
    }

    std::vector<BYTE> buffer(bytes_needed);
    auto* config = reinterpret_cast<QUERY_SERVICE_CONFIGW*>(buffer.data());
    if (QueryServiceConfigW(service, config, bytes_needed, &bytes_needed)) {
        if (config->lpBinaryPathName != nullptr) {
            return config->lpBinaryPathName;
        }
    }
    return {};
}

struct RawServiceEntry {
    std::wstring service_name;
    std::wstring display_name;
    DWORD service_type{0};
    DWORD current_state{0};
};

static std::vector<RawServiceEntry> enumerate_services(SC_HANDLE scm, DWORD type) {
    std::vector<RawServiceEntry> result;
    DWORD bytes_needed = 0;
    DWORD services_returned = 0;
    DWORD resume_handle = 0;

    EnumServicesStatusExW(scm, SC_ENUM_PROCESS_INFO, type, SERVICE_STATE_ALL,
                          nullptr, 0, &bytes_needed, &services_returned, &resume_handle, nullptr);
    if (bytes_needed == 0) {
        return result;
    }

    std::vector<BYTE> buffer(bytes_needed);
    resume_handle = 0;
    if (EnumServicesStatusExW(scm, SC_ENUM_PROCESS_INFO, type, SERVICE_STATE_ALL,
                              buffer.data(), bytes_needed, &bytes_needed,
                              &services_returned, &resume_handle, nullptr) ||
        GetLastError() == ERROR_MORE_DATA) {
        auto* entries = reinterpret_cast<const ENUM_SERVICE_STATUS_PROCESSW*>(buffer.data());
        for (DWORD i = 0; i < services_returned; ++i) {
            std::wstring svc_name = entries[i].lpServiceName ? entries[i].lpServiceName : L"";
            std::wstring disp_name = entries[i].lpDisplayName ? entries[i].lpDisplayName : L"";
            result.push_back({
                std::move(svc_name),
                std::move(disp_name),
                entries[i].ServiceStatusProcess.dwServiceType,
                entries[i].ServiceStatusProcess.dwCurrentState
            });
        }
    }
    return result;
}

std::vector<ServiceInfo> ServiceManager::find_target_services(const std::wstring& target_root_path) {
    std::vector<ServiceInfo> results;
    if (target_root_path.empty()) {
        return results;
    }

    UniqueScHandle scm(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT | SC_MANAGER_ENUMERATE_SERVICE));
    if (!scm) {
        return results;
    }

    const auto win32_services = enumerate_services(scm.get(), SERVICE_WIN32);
    const auto driver_services = enumerate_services(scm.get(), SERVICE_DRIVER);

    std::vector<RawServiceEntry> all_services;
    all_services.reserve(win32_services.size() + driver_services.size());
    all_services.insert(all_services.end(), win32_services.begin(), win32_services.end());
    all_services.insert(all_services.end(), driver_services.begin(), driver_services.end());

    for (const auto& entry : all_services) {
        UniqueScHandle svc(OpenServiceW(scm.get(), entry.service_name.c_str(), SERVICE_QUERY_CONFIG));
        if (!svc) {
            continue;
        }

        const std::wstring raw_binary = get_service_binary_path(svc.get());
        if (raw_binary.empty()) {
            continue;
        }

        const std::wstring norm_binary = normalize_service_image_path(raw_binary);
        if (PathHelper::is_same_or_subpath(target_root_path, norm_binary)) {
            // Refuse to touch services located in protected Windows directories
            if (!SafetyValidator::validate_path(norm_binary)) {
                continue;
            }

            const bool is_driver = (entry.service_type & SERVICE_DRIVER) != 0;
            const bool is_running = entry.current_state != SERVICE_STOPPED;

            results.push_back({
                entry.service_name,
                entry.display_name.empty() ? entry.service_name : entry.display_name,
                norm_binary,
                is_driver,
                is_running
            });
        }
    }

    return results;
}

static void process_task_folder(ITaskFolder* folder, const std::wstring& target_root_path,
                                std::vector<ScheduledTaskInfo>& found_tasks,
                                bool delete_tasks, size_t& deleted_count) {
    if (folder == nullptr) {
        return;
    }

    ComPtr<IRegisteredTaskCollection> task_col;
    if (SUCCEEDED(folder->GetTasks(TASK_ENUM_HIDDEN, task_col.put())) && task_col) {
        LONG count = 0;
        task_col->get_Count(&count);

        for (LONG i = 1; i <= count; ++i) {
            ComPtr<IRegisteredTask> task;
            if (FAILED(task_col->get_Item(_variant_t(i), task.put())) || !task) {
                continue;
            }

            BSTR bstr_name = nullptr;
            task->get_Name(&bstr_name);
            std::wstring task_name = bstr_name ? bstr_name : L"";
            SysFreeString(bstr_name);

            ComPtr<ITaskDefinition> def;
            if (FAILED(task->get_Definition(def.put())) || !def) {
                continue;
            }

            ComPtr<IActionCollection> actions;
            if (FAILED(def->get_Actions(actions.put())) || !actions) {
                continue;
            }

            LONG action_count = 0;
            actions->get_Count(&action_count);
            bool matched = false;
            std::wstring matched_path;

            for (LONG a = 1; a <= action_count; ++a) {
                ComPtr<IAction> action;
                if (FAILED(actions->get_Item(a, action.put())) || !action) {
                    continue;
                }

                TASK_ACTION_TYPE type{};
                action->get_Type(&type);
                if (type == TASK_ACTION_EXEC) {
                    ComPtr<IExecAction> exec_action;
                    if (SUCCEEDED(action->QueryInterface(IID_IExecAction, exec_action.put_void())) &&
                        exec_action) {
                        BSTR bstr_path = nullptr;
                        exec_action->get_Path(&bstr_path);
                        std::wstring exec_path = bstr_path ? bstr_path : L"";
                        SysFreeString(bstr_path);

                        const std::wstring norm_exec = SafetyValidator::normalize_path(exec_path);
                        if (PathHelper::is_same_or_subpath(target_root_path, norm_exec)) {
                            matched = true;
                            matched_path = norm_exec;
                            break;
                        }
                    }
                }
            }

            if (matched) {
                BSTR bstr_folder = nullptr;
                folder->get_Path(&bstr_folder);
                std::wstring folder_path = bstr_folder ? bstr_folder : L"";
                SysFreeString(bstr_folder);

                found_tasks.push_back({task_name, folder_path, matched_path});

                if (delete_tasks) {
                    if (SUCCEEDED(folder->DeleteTask(_bstr_t(task_name.c_str()), 0))) {
                        deleted_count++;
                        Logger::debug(L"Deleted scheduled task: " + folder_path + L"\\" + task_name);
                    }
                }
            }
        }
    }

    ComPtr<ITaskFolderCollection> subfolders;
    if (SUCCEEDED(folder->GetFolders(0, subfolders.put())) && subfolders) {
        LONG folder_count = 0;
        subfolders->get_Count(&folder_count);
        for (LONG f = 1; f <= folder_count; ++f) {
            ComPtr<ITaskFolder> sub;
            if (SUCCEEDED(subfolders->get_Item(_variant_t(f), sub.put())) && sub) {
                process_task_folder(sub.get(), target_root_path,
                                    found_tasks, delete_tasks, deleted_count);
            }
        }
    }
}

std::vector<ScheduledTaskInfo> ServiceManager::find_target_tasks(const std::wstring& target_root_path) {
    std::vector<ScheduledTaskInfo> results;
    if (target_root_path.empty()) {
        return results;
    }

    ScopedCom com;
    if (!com.ok()) {
        return results;
    }

    ComPtr<ITaskService> task_service;
    if (FAILED(CoCreateInstance(CLSID_TaskScheduler, nullptr, CLSCTX_INPROC_SERVER,
                                IID_ITaskService, task_service.put_void())) || !task_service) {
        return results;
    }

    if (FAILED(task_service->Connect(_variant_t(), _variant_t(), _variant_t(), _variant_t()))) {
        return results;
    }

    ComPtr<ITaskFolder> root_folder;
    if (FAILED(task_service->GetFolder(_bstr_t(L"\\"), root_folder.put())) || !root_folder) {
        return results;
    }

    size_t ignored = 0;
    process_task_folder(root_folder.get(), target_root_path, results, false, ignored);
    return results;
}

static bool stop_service_tree(SC_HANDLE scm, SC_HANDLE svc, const std::wstring& name,
                              DWORD wait_seconds = 5) {
    SERVICE_STATUS_PROCESS ssp{};
    DWORD bytes_needed = 0;
    if (!QueryServiceStatusEx(svc, SC_STATUS_PROCESS_INFO, reinterpret_cast<LPBYTE>(&ssp),
                              sizeof(ssp), &bytes_needed)) {
        return false;
    }

    if (ssp.dwCurrentState == SERVICE_STOPPED) {
        return true;
    }

    // Stop dependent services first
    DWORD count = 0;
    EnumDependentServicesW(svc, SERVICE_ACTIVE, nullptr, 0, &bytes_needed, &count);
    if (bytes_needed > 0) {
        std::vector<BYTE> dep_buf(bytes_needed);
        if (EnumDependentServicesW(svc, SERVICE_ACTIVE,
                                   reinterpret_cast<LPENUM_SERVICE_STATUSW>(dep_buf.data()),
                                   bytes_needed, &bytes_needed, &count)) {
            auto* deps = reinterpret_cast<LPENUM_SERVICE_STATUSW>(dep_buf.data());
            for (DWORD i = 0; i < count; ++i) {
                UniqueScHandle dep_svc(OpenServiceW(scm, deps[i].lpServiceName,
                                                    SERVICE_STOP | SERVICE_QUERY_STATUS));
                if (dep_svc) {
                    stop_service_tree(scm, dep_svc.get(), deps[i].lpServiceName, wait_seconds);
                }
            }
        }
    }

    SERVICE_STATUS status{};
    ControlService(svc, SERVICE_CONTROL_STOP, &status);

    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(wait_seconds);
    while (std::chrono::steady_clock::now() < deadline) {
        if (QueryServiceStatusEx(svc, SC_STATUS_PROCESS_INFO, reinterpret_cast<LPBYTE>(&ssp),
                                 sizeof(ssp), &bytes_needed)) {
            if (ssp.dwCurrentState == SERVICE_STOPPED) {
                return true;
            }
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    // Stuck in STOP_PENDING: terminate the host process PID
    if (ssp.dwProcessId != 0) {
        Logger::debug(L"Service " + name + L" stuck in stop pending; killing PID " +
                      std::to_wstring(ssp.dwProcessId));
        UniqueHandle hProc(OpenProcess(PROCESS_TERMINATE, FALSE, ssp.dwProcessId));
        if (hProc) {
            TerminateProcess(hProc.get(), 1);
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
            if (QueryServiceStatusEx(svc, SC_STATUS_PROCESS_INFO, reinterpret_cast<LPBYTE>(&ssp),
                                     sizeof(ssp), &bytes_needed)) {
                return ssp.dwCurrentState == SERVICE_STOPPED;
            }
        }
    }

    return false;
}

ServiceReport ServiceManager::remove_services_and_tasks(const std::wstring& target_root_path) {
    ServiceReport report;
    if (target_root_path.empty()) {
        return report;
    }

    const auto target_services = find_target_services(target_root_path);

    UniqueScHandle scm(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS));
    if (!scm) {
        scm.reset(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT | SC_MANAGER_ENUMERATE_SERVICE));
    }

    if (scm) {
        for (const auto& svc_info : target_services) {
            if (svc_info.is_driver) {
                report.drivers_found++;
            } else {
                report.services_found++;
            }

            const DWORD desired_access = SERVICE_STOP | SERVICE_QUERY_STATUS |
                                        SERVICE_ENUMERATE_DEPENDENTS | DELETE;
            UniqueScHandle svc(OpenServiceW(scm.get(), svc_info.name.c_str(), desired_access));
            if (!svc) {
                report.warnings.push_back(L"Failed to open service for deletion: " + svc_info.name);
                continue;
            }

            const bool stopped = stop_service_tree(scm.get(), svc.get(), svc_info.name, 5);
            if (stopped) {
                if (svc_info.is_driver) {
                    report.drivers_stopped++;
                } else {
                    report.services_stopped++;
                }
            } else {
                report.warnings.push_back(L"Service could not be stopped immediately: " + svc_info.name);
            }

            if (DeleteService(svc.get())) {
                if (svc_info.is_driver) {
                    report.drivers_deleted++;
                } else {
                    report.services_deleted++;
                }
                Logger::debug(L"Deleted service: " + svc_info.name);
            } else {
                const DWORD err = GetLastError();
                if (err == ERROR_SERVICE_MARKED_FOR_DELETE) {
                    if (svc_info.is_driver) {
                        report.drivers_deleted++;
                        report.reboot_required = true;
                    } else {
                        report.services_deleted++;
                    }
                } else {
                    report.warnings.push_back(L"DeleteService failed for " + svc_info.name +
                                              L": " + Win32Error::from_code(err).message());
                    if (svc_info.is_driver) {
                        report.reboot_required = true;
                    }
                }
            }
        }
    } else {
        report.warnings.push_back(L"Could not open Service Control Manager to remove services");
    }

    // Delete scheduled tasks
    ScopedCom com;
    if (com.ok()) {
        ComPtr<ITaskService> task_service;
        if (SUCCEEDED(CoCreateInstance(CLSID_TaskScheduler, nullptr, CLSCTX_INPROC_SERVER,
                                       IID_ITaskService, task_service.put_void())) && task_service) {
            if (SUCCEEDED(task_service->Connect(_variant_t(), _variant_t(), _variant_t(), _variant_t()))) {
                ComPtr<ITaskFolder> root_folder;
                if (SUCCEEDED(task_service->GetFolder(_bstr_t(L"\\"), root_folder.put())) && root_folder) {
                    std::vector<ScheduledTaskInfo> tasks;
                    process_task_folder(root_folder.get(), target_root_path,
                                        tasks, true, report.tasks_deleted);
                    report.tasks_found = tasks.size();
                }
            }
        }
    } else {
        report.warnings.push_back(L"Could not initialize COM for scheduled tasks removal");
    }

    return report;
}

} // namespace obliterator
