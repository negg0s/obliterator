#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include <cstdint>
#include <string>
#include <vector>

namespace obliterator {

namespace ExitCode {
    constexpr int Success = 0;
    constexpr int Error = 1;
    constexpr int SuccessRebootRequired = 2;
    constexpr int SafetyViolation = 3;
}

struct FinalReport {
    std::wstring target_name;
    std::wstring target_root;
    bool success{true};
    bool reboot_required{false};
    int exit_code{ExitCode::Success};

    // Processes
    size_t processes_found{0};
    size_t processes_killed{0};
    size_t processes_failed{0};

    // File locks
    size_t handles_closed{0};

    // Services and tasks
    size_t services_stopped{0};
    size_t services_deleted{0};
    size_t drivers_stopped{0};
    size_t drivers_deleted{0};
    size_t tasks_deleted{0};

    // Filesystem
    size_t files_deleted{0};
    size_t directories_deleted{0};
    size_t junctions_deleted{0};
    size_t acl_resets{0};
    uint64_t bytes_freed{0};
    size_t files_scheduled_for_reboot{0};
    size_t directories_scheduled_for_reboot{0};

    // Registry
    size_t uninstall_keys_deleted{0};
    size_t autorun_values_deleted{0};
    size_t shell_entries_deleted{0};
    size_t product_keys_deleted{0};
    size_t total_reg_keys_deleted{0};
    size_t total_reg_values_deleted{0};
    size_t items_backed_up{0};
    std::wstring backup_directory;

    // Leftovers
    size_t folders_deleted{0};
    size_t shortcuts_deleted{0};
    size_t firewall_rules_deleted{0};
    size_t possible_leftovers_skipped{0};

    // Pending reboot
    std::vector<std::wstring> pending_reboot_items;

    void print_text() const;
    void print_json() const;
};

} // namespace obliterator
