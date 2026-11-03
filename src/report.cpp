#include "obliterator/report.hpp"
#include "obliterator/wiper.hpp"

#include <iostream>

namespace obliterator {

static std::wstring escape_json(std::wstring_view input) {
    std::wstring out;
    out.reserve(input.size() + 16);
    for (wchar_t c : input) {
        if (c == L'\\') {
            out += L"\\\\";
        } else if (c == L'\"') {
            out += L"\\\"";
        } else if (c == L'\n') {
            out += L"\\n";
        } else if (c == L'\r') {
            out += L"\\r";
        } else if (c == L'\t') {
            out += L"\\t";
        } else {
            out += c;
        }
    }
    return out;
}

void FinalReport::print_text() const {
    std::wcout << L"\n================================================================================\n"
               << L" Obliterator Final Summary\n"
               << L"================================================================================\n"
               << L" Target: " << target_name << L" (" << target_root << L")\n"
               << L" Status: " << (success ? (reboot_required ? L"Pending Reboot" : L"Completed") : L"Failed") << L"\n\n"
               << L" - Processes:       found " << processes_found
               << L", killed " << processes_killed
               << L", failed " << processes_failed << L"\n"
               << L" - File locks:      " << handles_closed << L" handles released\n"
               << L" - Services:        " << services_stopped << L" stopped, " << services_deleted << L" deleted\n"
               << L" - Drivers:         " << drivers_stopped << L" stopped, " << drivers_deleted << L" deleted\n"
               << L" - Scheduled tasks: " << tasks_deleted << L" deleted\n"
               << L" - Filesystem:      " << files_deleted << L" files deleted, "
               << directories_deleted << L" directories deleted, "
               << junctions_deleted << L" junctions deleted\n"
               << L" - Volume freed:    " << FileWiper::format_bytes(bytes_freed)
               << L" (" << bytes_freed << L" bytes)\n"
               << L" - ACL take-overs:  " << acl_resets << L" performed\n"
               << L" - Registry:        " << total_reg_keys_deleted << L" keys deleted, "
               << total_reg_values_deleted << L" values deleted\n";

    if (items_backed_up > 0 && !backup_directory.empty()) {
        std::wcout << L" - Registry backup: " << items_backed_up << L" items backed up to "
                   << backup_directory << L"\n";
    }

    std::wcout << L" - Leftovers:       " << folders_deleted << L" folders, "
               << shortcuts_deleted << L" shortcuts, "
               << firewall_rules_deleted << L" firewall rules removed\n";

    if (possible_leftovers_skipped > 0) {
        std::wcout << L" - Possible skips:  " << possible_leftovers_skipped
                   << L" items skipped (re-run with --aggressive to delete)\n";
    }

    if (reboot_required || !pending_reboot_items.empty()) {
        std::wcout << L"\n Pending deletion on system reboot:\n";
        if (files_scheduled_for_reboot > 0 || directories_scheduled_for_reboot > 0) {
            std::wcout << L"   * " << files_scheduled_for_reboot << L" files and "
                       << directories_scheduled_for_reboot << L" directories scheduled\n";
        }
        for (const auto& item : pending_reboot_items) {
            std::wcout << L"   * " << item << L"\n";
        }
    }

    std::wcout << L"================================================================================\n\n";
}

void FinalReport::print_json() const {
    std::wcout << L"{\n"
               << L"  \"target\": {\n"
               << L"    \"name\": \"" << escape_json(target_name) << L"\",\n"
               << L"    \"root_path\": \"" << escape_json(target_root) << L"\"\n"
               << L"  },\n"
               << L"  \"success\": " << (success ? L"true" : L"false") << L",\n"
               << L"  \"reboot_required\": " << (reboot_required ? L"true" : L"false") << L",\n"
               << L"  \"exit_code\": " << exit_code << L",\n"
               << L"  \"processes\": {\n"
               << L"    \"found\": " << processes_found << L",\n"
               << L"    \"killed\": " << processes_killed << L",\n"
               << L"    \"failed\": " << processes_failed << L"\n"
               << L"  },\n"
               << L"  \"locks\": {\n"
               << L"    \"handles_closed\": " << handles_closed << L"\n"
               << L"  },\n"
               << L"  \"services\": {\n"
               << L"    \"services_stopped\": " << services_stopped << L",\n"
               << L"    \"services_deleted\": " << services_deleted << L",\n"
               << L"    \"drivers_stopped\": " << drivers_stopped << L",\n"
               << L"    \"drivers_deleted\": " << drivers_deleted << L",\n"
               << L"    \"tasks_deleted\": " << tasks_deleted << L"\n"
               << L"  },\n"
               << L"  \"filesystem\": {\n"
               << L"    \"files_deleted\": " << files_deleted << L",\n"
               << L"    \"directories_deleted\": " << directories_deleted << L",\n"
               << L"    \"junctions_deleted\": " << junctions_deleted << L",\n"
               << L"    \"acl_resets\": " << acl_resets << L",\n"
               << L"    \"bytes_freed\": " << bytes_freed << L",\n"
               << L"    \"bytes_freed_formatted\": \"" << escape_json(FileWiper::format_bytes(bytes_freed)) << L"\",\n"
               << L"    \"files_scheduled_for_reboot\": " << files_scheduled_for_reboot << L",\n"
               << L"    \"directories_scheduled_for_reboot\": " << directories_scheduled_for_reboot << L"\n"
               << L"  },\n"
               << L"  \"registry\": {\n"
               << L"    \"uninstall_keys_deleted\": " << uninstall_keys_deleted << L",\n"
               << L"    \"autorun_values_deleted\": " << autorun_values_deleted << L",\n"
               << L"    \"shell_entries_deleted\": " << shell_entries_deleted << L",\n"
               << L"    \"product_keys_deleted\": " << product_keys_deleted << L",\n"
               << L"    \"total_keys_deleted\": " << total_reg_keys_deleted << L",\n"
               << L"    \"total_values_deleted\": " << total_reg_values_deleted << L",\n"
               << L"    \"items_backed_up\": " << items_backed_up << L",\n"
               << L"    \"backup_directory\": \"" << escape_json(backup_directory) << L"\"\n"
               << L"  },\n"
               << L"  \"leftovers\": {\n"
               << L"    \"folders_deleted\": " << folders_deleted << L",\n"
               << L"    \"shortcuts_deleted\": " << shortcuts_deleted << L",\n"
               << L"    \"firewall_rules_deleted\": " << firewall_rules_deleted << L",\n"
               << L"    \"possible_skipped\": " << possible_leftovers_skipped << L"\n"
               << L"  },\n"
               << L"  \"pending_reboot\": [";

    for (size_t i = 0; i < pending_reboot_items.size(); ++i) {
        std::wcout << L"\"" << escape_json(pending_reboot_items[i]) << L"\"";
        if (i + 1 < pending_reboot_items.size()) {
            std::wcout << L", ";
        }
    }

    std::wcout << L"]\n}\n";
}

} // namespace obliterator
