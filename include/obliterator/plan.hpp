#pragma once

#include "obliterator/target.hpp"

#include <string>
#include <vector>

namespace obliterator {

struct PlanProcess {
    DWORD pid{0};
    std::wstring name;
    std::wstring image_path;
    std::wstring match_reason;
};

struct PlanLockedFile {
    std::wstring path;
    DWORD pid{0};
    std::wstring process_name;
};

struct PlanService {
    std::wstring name;
    std::wstring display_name;
    std::wstring binary_path;
    bool is_driver{false};
};

struct PlanTask {
    std::wstring name;
    std::wstring folder_path;
    std::wstring action_path;
};

struct PlanRegistryKey {
    HKEY root_key;
    std::wstring subkey_path;
    REGSAM sam_view;
    std::wstring description;
};

struct Plan {
    Target target;
    std::vector<PlanProcess> processes_to_terminate;
    std::vector<PlanLockedFile> locked_files_to_release;
    std::vector<PlanService> services_to_remove;
    std::vector<PlanTask> tasks_to_remove;
    std::vector<std::wstring> directories_to_remove;
    std::vector<PlanRegistryKey> registry_keys_to_remove;

    explicit Plan(Target t);

    void print() const;
    [[nodiscard]] bool is_empty() const noexcept;
};

} // namespace obliterator
