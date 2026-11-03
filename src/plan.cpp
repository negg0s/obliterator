#include "obliterator/plan.hpp"
#include "obliterator/log.hpp"

#include <iostream>

namespace obliterator {

static const wchar_t* root_key_to_string(HKEY root) {
    if (root == HKEY_LOCAL_MACHINE) {
        return L"HKLM";
    }
    if (root == HKEY_CURRENT_USER) {
        return L"HKCU";
    }
    if (root == HKEY_CLASSES_ROOT) {
        return L"HKCR";
    }
    return L"HKEY";
}

Plan::Plan(Target t) : target(std::move(t)) {
    if (!target.root_path.empty()) {
        directories_to_remove.push_back(target.root_path);
    }

    for (const auto& reg : target.registry_entries) {
        registry_keys_to_remove.push_back({
            reg.root_key,
            reg.subkey_path,
            reg.sam_view,
            reg.display_name
        });
    }
}

bool Plan::is_empty() const noexcept {
    return processes_to_terminate.empty() &&
           locked_files_to_release.empty() &&
           services_to_remove.empty() &&
           tasks_to_remove.empty() &&
           directories_to_remove.empty() &&
           registry_keys_to_remove.empty();
}

void Plan::print() const {
    std::wcout << L"\nExecution Plan for: " << target.name << L"\n";
    std::wcout << L"Root path: " << target.root_path << L"\n\n";

    if (!processes_to_terminate.empty()) {
        std::wcout << L"Processes to terminate (" << processes_to_terminate.size() << L"):\n";
        for (const auto& proc : processes_to_terminate) {
            std::wcout << L"  [PID " << proc.pid << L"] " << proc.name;
            if (!proc.match_reason.empty()) {
                std::wcout << L" (" << proc.match_reason << L")";
            }
            std::wcout << L"\n";
            if (!proc.image_path.empty()) {
                std::wcout << L"        " << proc.image_path << L"\n";
            }
        }
        std::wcout << L"\n";
    }

    if (!locked_files_to_release.empty()) {
        std::wcout << L"Locked files to release (" << locked_files_to_release.size() << L"):\n";
        for (const auto& item : locked_files_to_release) {
            std::wcout << L"  [PID " << item.pid << L"] " << item.process_name;
            if (!item.path.empty()) {
                std::wcout << L" -> " << item.path;
            }
            std::wcout << L"\n";
        }
        std::wcout << L"\n";
    }

    if (!services_to_remove.empty()) {
        std::wcout << L"Services and drivers to delete (" << services_to_remove.size() << L"):\n";
        for (const auto& svc : services_to_remove) {
            std::wcout << (svc.is_driver ? L"  [DRIVER]  " : L"  [SERVICE] ")
                       << svc.name << L" (" << svc.display_name << L")\n"
                       << L"            " << svc.binary_path << L"\n";
        }
        std::wcout << L"\n";
    }

    if (!tasks_to_remove.empty()) {
        std::wcout << L"Scheduled tasks to delete (" << tasks_to_remove.size() << L"):\n";
        for (const auto& task : tasks_to_remove) {
            std::wcout << L"  [TASK] " << task.folder_path << L"\\" << task.name << L"\n"
                       << L"         " << task.action_path << L"\n";
        }
        std::wcout << L"\n";
    }

    if (!directories_to_remove.empty()) {
        std::wcout << L"Directories to delete (" << directories_to_remove.size() << L"):\n";
        for (const auto& dir : directories_to_remove) {
            std::wcout << L"  [DIR] " << dir << L"\n";
        }
    }

    if (!registry_keys_to_remove.empty()) {
        std::wcout << L"\nRegistry entries to remove (" << registry_keys_to_remove.size() << L"):\n";
        for (const auto& reg : registry_keys_to_remove) {
            std::wcout << L"  [REG] " << root_key_to_string(reg.root_key)
                       << L"\\" << reg.subkey_path;
            if (!reg.description.empty()) {
                std::wcout << L" (" << reg.description << L")";
            }
            std::wcout << L"\n";
        }
    }

    std::wcout << L"\n";
}

} // namespace obliterator
