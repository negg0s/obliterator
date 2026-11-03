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
#include <vector>

namespace obliterator {

struct ServiceInfo {
    std::wstring name;
    std::wstring display_name;
    std::wstring binary_path;
    bool is_driver{false};
    bool is_running{false};
};

struct ScheduledTaskInfo {
    std::wstring name;
    std::wstring folder_path;
    std::wstring action_path;
};

struct ServiceReport {
    size_t services_found{0};
    size_t services_stopped{0};
    size_t services_deleted{0};
    size_t drivers_found{0};
    size_t drivers_stopped{0};
    size_t drivers_deleted{0};
    size_t tasks_found{0};
    size_t tasks_deleted{0};
    bool reboot_required{false};
    std::vector<std::wstring> warnings;
};

class ServiceManager {
public:
    static std::vector<ServiceInfo> find_target_services(const std::wstring& target_root_path);
    static std::vector<ScheduledTaskInfo> find_target_tasks(const std::wstring& target_root_path);

    static ServiceReport remove_services_and_tasks(const std::wstring& target_root_path);

    static std::wstring normalize_service_image_path(std::wstring_view raw_path);
};

} // namespace obliterator
