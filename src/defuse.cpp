#include "obliterator/defuse.hpp"
#include "obliterator/handles.hpp"
#include "obliterator/log.hpp"
#include "obliterator/path.hpp"
#include "obliterator/registry_cleaner.hpp"

#include <comdef.h>
#include <taskschd.h>
#include <wbemidl.h>

#include <algorithm>
#include <cwctype>
#include <vector>

namespace obliterator {

class ScopedComInit {
public:
    ScopedComInit() noexcept : m_hr(CoInitializeEx(nullptr, COINIT_MULTITHREADED)) {}
    ~ScopedComInit() noexcept {
        if (SUCCEEDED(m_hr)) {
            CoUninitialize();
        }
    }
    ScopedComInit(const ScopedComInit&) = delete;
    ScopedComInit& operator=(const ScopedComInit&) = delete;
    [[nodiscard]] bool ok() const noexcept { return SUCCEEDED(m_hr); }
private:
    HRESULT m_hr;
};

bool RecoveryDefuser::defuse_service(SC_HANDLE scm, const std::wstring& service_name) {
    if (!scm || service_name.empty()) {
        return false;
    }

    const DWORD access = SERVICE_CHANGE_CONFIG | SERVICE_QUERY_CONFIG;
    UniqueScHandle svc(OpenServiceW(scm, service_name.c_str(), access));
    if (!svc) {
        return false;
    }

    SC_ACTION dummy_action{};
    SERVICE_FAILURE_ACTIONSW sfa{};
    sfa.dwResetPeriod = 0;
    sfa.lpRebootMsg = nullptr;
    sfa.lpCommand = nullptr;
    sfa.cActions = 0;
    sfa.lpsaActions = &dummy_action;
    ChangeServiceConfig2W(svc.get(), SERVICE_CONFIG_FAILURE_ACTIONS, &sfa);

    SERVICE_FAILURE_ACTIONS_FLAG flag{FALSE};
    ChangeServiceConfig2W(svc.get(), SERVICE_CONFIG_FAILURE_ACTIONS_FLAG, &flag);

    ChangeServiceConfigW(svc.get(),
                         SERVICE_NO_CHANGE,
                         SERVICE_DISABLED,
                         SERVICE_NO_CHANGE,
                         nullptr,
                         nullptr,
                         nullptr,
                         nullptr,
                         nullptr,
                         nullptr,
                         nullptr);

    Logger::debug(L"Defused failure actions and disabled service: " + service_name);
    return true;
}

bool RecoveryDefuser::disable_task(const std::wstring& task_name) {
    if (task_name.empty()) {
        return false;
    }

    bool disabled = false;
    ScopedComInit com;
    if (com.ok()) {
        ComPtr<ITaskService> task_service;
        if (SUCCEEDED(CoCreateInstance(CLSID_TaskScheduler, nullptr, CLSCTX_INPROC_SERVER,
                                       IID_ITaskService, task_service.put_void())) && task_service) {
            if (SUCCEEDED(task_service->Connect(_variant_t(), _variant_t(), _variant_t(), _variant_t()))) {
                ComPtr<ITaskFolder> root_folder;
                if (SUCCEEDED(task_service->GetFolder(_bstr_t(L"\\"), root_folder.put())) && root_folder) {
                    ComPtr<IRegisteredTask> task;
                    if (SUCCEEDED(root_folder->GetTask(_bstr_t(task_name.c_str()), task.put())) && task) {
                        task->Stop(0);
                        if (SUCCEEDED(task->put_Enabled(VARIANT_FALSE))) {
                            disabled = true;
                        }
                    }
                }
            }
        }
    }

    if (!disabled) {
        std::wstring cmd = L"schtasks.exe /Change /TN \"" + task_name + L"\" /DISABLE";
        STARTUPINFOW si{};
        si.cb = sizeof(si);
        si.dwFlags = STARTF_USESHOWWINDOW;
        si.wShowWindow = SW_HIDE;
        PROCESS_INFORMATION pi{};
        if (CreateProcessW(nullptr, cmd.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
            WaitForSingleObject(pi.hProcess, 3000);
            DWORD exit_code = 1;
            GetExitCodeProcess(pi.hProcess, &exit_code);
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
            if (exit_code == 0) {
                disabled = true;
            }
        }
    }

    if (disabled) {
        Logger::debug(L"Disabled scheduled task: " + task_name);
    }
    return disabled;
}

size_t RecoveryDefuser::defuse_autorun_entries(const Target& target) {
    if (target.root_path.empty()) {
        return 0;
    }

    const auto entries = RegistryCleaner::find_autorun_entries(target.root_path);
    size_t removed = 0;

    for (const auto& entry : entries) {
        UniqueHKey key;
        if (RegOpenKeyExW(entry.root_key, entry.subkey_path.c_str(), 0,
                          KEY_SET_VALUE | entry.sam_view, key.put()) == ERROR_SUCCESS) {
            if (RegDeleteValueW(key.get(), entry.value_name.c_str()) == ERROR_SUCCESS) {
                removed++;
                Logger::debug(L"Defused autorun entry: " + entry.value_name + L" in " + entry.subkey_path);
            }
        }
    }

    return removed;
}

static bool wmi_string_contains_target(const _variant_t& var, const std::wstring& target_lower) {
    if (var.vt != VT_BSTR || var.bstrVal == nullptr) {
        return false;
    }
    std::wstring text = PathHelper::to_lower_unicode(var.bstrVal);
    return text.find(target_lower) != std::wstring::npos;
}

size_t RecoveryDefuser::defuse_wmi_subscriptions(const Target& target) {
    if (target.root_path.empty() && target.name.empty()) {
        return 0;
    }

    ScopedComInit com;
    if (!com.ok()) {
        return 0;
    }

    ComPtr<IWbemLocator> locator;
    if (FAILED(CoCreateInstance(CLSID_WbemLocator, nullptr, CLSCTX_INPROC_SERVER,
                                IID_IWbemLocator, locator.put_void())) || !locator) {
        return 0;
    }

    ComPtr<IWbemServices> services;
    HRESULT hr = locator->ConnectServer(
        _bstr_t(L"ROOT\\subscription"),
        nullptr, nullptr, nullptr, 0, nullptr, nullptr, services.put()
    );
    if (FAILED(hr) || !services) {
        return 0;
    }

    CoSetProxyBlanket(
        services.get(),
        RPC_C_AUTHN_WINNT,
        RPC_C_AUTHZ_NONE,
        nullptr,
        RPC_C_AUTHN_LEVEL_CALL,
        RPC_C_IMP_LEVEL_IMPERSONATE,
        nullptr,
        EOAC_NONE
    );

    const std::wstring target_root_lower = PathHelper::to_lower_unicode(target.root_path);
    const std::wstring target_name_lower = PathHelper::to_lower_unicode(target.name);
    size_t removed_count = 0;

    auto check_and_delete_consumers = [&](const wchar_t* wql_query, const wchar_t* consumer_class) {
        ComPtr<IEnumWbemClassObject> enumerator;
        if (FAILED(services->ExecQuery(
            _bstr_t(L"WQL"),
            _bstr_t(wql_query),
            WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
            nullptr,
            enumerator.put()
        )) || !enumerator) {
            return;
        }

        IWbemClassObject* obj = nullptr;
        ULONG returned = 0;

        while (enumerator->Next(WBEM_INFINITE, 1, &obj, &returned) == WBEM_S_NO_ERROR && returned > 0) {
            ComPtr<IWbemClassObject> class_obj(obj);
            _variant_t name_var;
            _variant_t cmd_var;
            _variant_t exe_var;
            _variant_t script_var;

            class_obj->Get(L"Name", 0, &name_var, nullptr, nullptr);
            class_obj->Get(L"CommandLineTemplate", 0, &cmd_var, nullptr, nullptr);
            class_obj->Get(L"ExecutablePath", 0, &exe_var, nullptr, nullptr);
            class_obj->Get(L"ScriptText", 0, &script_var, nullptr, nullptr);

            bool matches = false;
            if (!target_root_lower.empty()) {
                matches = wmi_string_contains_target(cmd_var, target_root_lower) ||
                          wmi_string_contains_target(exe_var, target_root_lower) ||
                          wmi_string_contains_target(script_var, target_root_lower);
            }
            if (!matches && !target_name_lower.empty() && name_var.vt == VT_BSTR && name_var.bstrVal != nullptr) {
                std::wstring name_lower = PathHelper::to_lower_unicode(name_var.bstrVal);
                if (name_lower == target_name_lower || name_lower.find(target_name_lower) != std::wstring::npos) {
                    matches = true;
                }
            }

            if (matches && name_var.vt == VT_BSTR && name_var.bstrVal != nullptr) {
                std::wstring cname = name_var.bstrVal;
                std::wstring consumer_relpath = std::wstring(consumer_class) + L".Name=\"" + cname + L"\"";

                ComPtr<IEnumWbemClassObject> bind_enum;
                if (SUCCEEDED(services->ExecQuery(
                    _bstr_t(L"WQL"),
                    _bstr_t(L"SELECT * FROM __FilterToConsumerBinding"),
                    WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
                    nullptr,
                    bind_enum.put()
                )) && bind_enum) {
                    IWbemClassObject* bind_obj = nullptr;
                    ULONG bind_returned = 0;
                    while (bind_enum->Next(WBEM_INFINITE, 1, &bind_obj, &bind_returned) == WBEM_S_NO_ERROR && bind_returned > 0) {
                        ComPtr<IWbemClassObject> binding(bind_obj);
                        _variant_t c_ref;
                        _variant_t f_ref;
                        binding->Get(L"Consumer", 0, &c_ref, nullptr, nullptr);
                        binding->Get(L"Filter", 0, &f_ref, nullptr, nullptr);

                        if (c_ref.vt == VT_BSTR && c_ref.bstrVal != nullptr) {
                            std::wstring cref_str = PathHelper::to_lower_unicode(c_ref.bstrVal);
                            if (cref_str.find(PathHelper::to_lower_unicode(cname)) != std::wstring::npos) {
                                _variant_t path_var;
                                binding->Get(L"__RELPATH", 0, &path_var, nullptr, nullptr);
                                if (path_var.vt == VT_BSTR) {
                                    services->DeleteInstance(path_var.bstrVal, 0, nullptr, nullptr);
                                }
                                if (f_ref.vt == VT_BSTR) {
                                    services->DeleteInstance(f_ref.bstrVal, 0, nullptr, nullptr);
                                }
                            }
                        }
                    }
                }

                if (SUCCEEDED(services->DeleteInstance(_bstr_t(consumer_relpath.c_str()), 0, nullptr, nullptr))) {
                    removed_count++;
                    Logger::debug(L"Deleted WMI event consumer: " + consumer_relpath);
                }
            }
        }
    };

    check_and_delete_consumers(L"SELECT * FROM CommandLineEventConsumer", L"CommandLineEventConsumer");
    check_and_delete_consumers(L"SELECT * FROM ActiveScriptEventConsumer", L"ActiveScriptEventConsumer");

    return removed_count;
}

DefuseReport RecoveryDefuser::defuse_all(const Target& target,
                                       const std::vector<PlanService>& services,
                                       const std::vector<PlanTask>& tasks) {
    DefuseReport report;

    UniqueScHandle scm(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS));
    if (!scm) {
        scm.reset(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT | SC_MANAGER_ENUMERATE_SERVICE));
    }

    if (scm) {
        for (const auto& svc : services) {
            if (defuse_service(scm.get(), svc.name)) {
                report.service_failure_actions_cleared++;
                report.services_disabled++;
            } else {
                report.warnings.push_back(L"Could not defuse failure actions for service: " + svc.name);
            }
        }
    } else if (!services.empty()) {
        report.warnings.push_back(L"Could not open SCManager to defuse services");
    }

    for (const auto& task : tasks) {
        if (disable_task(task.name)) {
            report.tasks_disabled++;
        } else {
            report.warnings.push_back(L"Could not disable scheduled task: " + task.name);
        }
    }

    report.autorun_entries_defused = defuse_autorun_entries(target);
    report.wmi_subscriptions_removed = defuse_wmi_subscriptions(target);

    return report;
}

DefuseReport RecoveryDefuser::defuse_all(const Target& target,
                                       const std::vector<ServiceInfo>& services,
                                       const std::vector<ScheduledTaskInfo>& tasks) {
    DefuseReport report;

    UniqueScHandle scm(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS));
    if (!scm) {
        scm.reset(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT | SC_MANAGER_ENUMERATE_SERVICE));
    }

    if (scm) {
        for (const auto& svc : services) {
            if (defuse_service(scm.get(), svc.name)) {
                report.service_failure_actions_cleared++;
                report.services_disabled++;
            } else {
                report.warnings.push_back(L"Could not defuse failure actions for service: " + svc.name);
            }
        }
    } else if (!services.empty()) {
        report.warnings.push_back(L"Could not open SCManager to defuse services");
    }

    for (const auto& task : tasks) {
        if (disable_task(task.name)) {
            report.tasks_disabled++;
        } else {
            report.warnings.push_back(L"Could not disable scheduled task: " + task.name);
        }
    }

    report.autorun_entries_defused = defuse_autorun_entries(target);
    report.wmi_subscriptions_removed = defuse_wmi_subscriptions(target);

    return report;
}

} // namespace obliterator
