#include "obliterator/error.hpp"
#include "obliterator/leftovers.hpp"
#include "obliterator/log.hpp"
#include "obliterator/plan.hpp"
#include "obliterator/privileges.hpp"
#include "obliterator/process.hpp"
#include "obliterator/registry_cleaner.hpp"
#include "obliterator/service.hpp"
#include "obliterator/target.hpp"
#include "obliterator/unlocker.hpp"
#include "obliterator/wiper.hpp"

#include <iostream>
#include <string>
#include <string_view>

namespace obliterator {

struct CommandLineOptions {
    std::wstring target;
    bool dry_run{false};
    bool yes{false};
    bool verbose{false};
    bool no_handle_kill{false};
    bool no_backup{false};
    bool aggressive{false};
    uint32_t timeout_seconds{5};
};

static void print_usage() {
    std::wcout << L"Usage: obliterator <target-name-or-path> [options]\n\n"
               << L"Arguments:\n"
               << L"  <target-name-or-path>  Target directory or application name to wipe\n\n"
               << L"Options:\n"
               << L"  --dry-run              Inspect and plan without modifying the system\n"
               << L"  --yes, -y              Skip confirmation prompt\n"
               << L"  --verbose, -v          Enable debug output\n"
               << L"  --timeout <sec>        Process kill wait timeout in seconds (default: 5)\n"
               << L"  --no-handle-kill       Disable remote file handle duplication and closure\n"
               << L"  --no-backup            Disable registry export to .reg before deletion\n"
               << L"  --aggressive           Delete possible leftovers matching heuristic\n"
               << L"  --help, -h             Display this help message\n";
}

static Result<CommandLineOptions> parse_arguments(int argc, wchar_t* argv[]) {
    CommandLineOptions options;

    for (int i = 1; i < argc; ++i) {
        std::wstring_view arg = argv[i];

        if (arg == L"--dry-run") {
            options.dry_run = true;
        } else if (arg == L"--yes" || arg == L"-y") {
            options.yes = true;
        } else if (arg == L"--verbose" || arg == L"-v") {
            options.verbose = true;
        } else if (arg == L"--no-handle-kill") {
            options.no_handle_kill = true;
        } else if (arg == L"--no-backup") {
            options.no_backup = true;
        } else if (arg == L"--aggressive") {
            options.aggressive = true;
        } else if (arg == L"--timeout") {
            if (i + 1 < argc) {
                try {
                    options.timeout_seconds = static_cast<uint32_t>(std::stoul(argv[++i]));
                } catch (...) {
                    Logger::error(L"Invalid timeout value provided");
                    return Win32Error::from_code(ERROR_INVALID_PARAMETER);
                }
            } else {
                Logger::error(L"Missing argument for --timeout");
                return Win32Error::from_code(ERROR_INVALID_PARAMETER);
            }
        } else if (arg == L"--help" || arg == L"-h") {
            print_usage();
            ExitProcess(0);
        } else if (arg.starts_with(L"-")) {
            Logger::error(std::wstring(L"Unknown option: ") + std::wstring(arg));
            return Win32Error::from_code(ERROR_INVALID_PARAMETER);
        } else {
            if (options.target.empty()) {
                options.target = arg;
            } else {
                Logger::error(L"Multiple targets specified; provide exactly one target.");
                return Win32Error::from_code(ERROR_INVALID_PARAMETER);
            }
        }
    }

    if (options.target.empty()) {
        print_usage();
        return Win32Error::from_code(ERROR_BAD_ARGUMENTS);
    }

    return options;
}

} // namespace obliterator

int wmain(int argc, wchar_t* argv[]) {
    using namespace obliterator;

    auto parse_res = parse_arguments(argc, argv);
    if (!parse_res) {
        return 1;
    }

    const auto& options = parse_res.value();
    Logger::set_verbose(options.verbose);

    Logger::debug(L"Verbosity enabled");
    Logger::debug(std::wstring(L"Input target: ") + options.target);

    auto priv_res = enable_required_privileges();
    if (!priv_res) {
        Logger::warn(std::wstring(L"Could not assign all process privileges: ") +
                     priv_res.error().message());
    } else {
        Logger::debug(L"Required privileges enabled");
    }

    auto target_res = TargetResolver::resolve(options.target);
    if (!target_res) {
        Logger::error(L"Failed to resolve target: " + target_res.error().message());
        return 1;
    }

    const auto& target = target_res.value();
    Plan plan(target);

    // Discover processes associated with the target directory
    const auto target_procs = ProcessManager::find_target_processes(target.root_path);
    for (const auto& proc : target_procs) {
        std::wstring reason = L"image path";
        if (proc.matched_as_descendant) {
            reason = L"descendant process";
        } else if (proc.matched_by_module) {
            reason = L"loaded module";
        }
        plan.processes_to_terminate.push_back({proc.pid, proc.name, proc.image_path, reason});
    }

    // Level 1 lock inspection via Restart Manager
    const auto locked_files = FileUnlocker::inspect_locks(target.root_path);
    for (const auto& lock : locked_files) {
        plan.locked_files_to_release.push_back({lock.path, lock.pid, lock.process_name});
    }

    // Inspect services and drivers
    const auto target_services = ServiceManager::find_target_services(target.root_path);
    for (const auto& svc : target_services) {
        plan.services_to_remove.push_back({svc.name, svc.display_name, svc.binary_path, svc.is_driver});
    }

    // Inspect scheduled tasks
    const auto target_tasks = ServiceManager::find_target_tasks(target.root_path);
    for (const auto& task : target_tasks) {
        plan.tasks_to_remove.push_back({task.name, task.folder_path, task.action_path});
    }

    // Inspect registry autorun entries
    const auto target_autoruns = RegistryCleaner::find_autorun_entries(target.root_path);
    for (const auto& ar : target_autoruns) {
        plan.registry_keys_to_remove.push_back({
            ar.root_key,
            ar.subkey_path + L" [" + ar.value_name + L"]",
            ar.sam_view,
            L"autorun value"
        });
    }

    // Inspect shell verbs and context menu extensions
    const auto target_shells = RegistryCleaner::find_shell_entries(target.root_path);
    for (const auto& sh : target_shells) {
        plan.registry_keys_to_remove.push_back({
            sh.root_key,
            sh.subkey_path,
            0,
            sh.is_clsid ? L"shell extension CLSID" : L"context menu verb"
        });
    }

    // Inspect product and vendor keys
    const auto target_prod_keys = RegistryCleaner::find_product_keys(target);
    for (const auto& pk : target_prod_keys) {
        plan.registry_keys_to_remove.push_back({
            pk.root_key,
            pk.subkey_path,
            pk.sam_view,
            L"product/vendor key"
        });
    }

    // Inspect leftovers
    const auto target_leftovers = LeftoversCleaner::find_leftovers(target);
    for (const auto& left : target_leftovers) {
        std::wstring type_str = (left.kind == LeftoverKind::Folder) ? L"FOLDER" :
                                (left.kind == LeftoverKind::Shortcut) ? L"SHORTCUT" : L"FIREWALL";
        std::wstring conf_str = (left.confidence == LeftoverConfidence::Definite) ? L"DEFINITE" : L"POSSIBLE";
        plan.leftovers_to_remove.push_back({left.path_or_name, type_str, conf_str, left.detail});
    }

    if (options.dry_run) {
        Logger::info(L"Dry-run mode active; displaying plan without making modifications");
        plan.print();
        return 0;
    }

    plan.print();

    if (!plan.processes_to_terminate.empty()) {
        Logger::info(L"Terminating target processes...");
        const auto report = ProcessManager::terminate_target_processes(
            target.root_path, options.timeout_seconds);

        std::wcout << L"Process summary: found " << report.found
                   << L", killed " << report.killed
                   << L", failed " << report.failed << L"\n";

        if (!report.failures.empty()) {
            std::wcout << L"Failed process terminations:\n";
            for (const auto& f : report.failures) {
                std::wcout << L"  [PID " << f.pid << L"] " << f.name
                           << L" - " << f.reason << L"\n";
            }
        }
    }

    Logger::info(L"Releasing file locks...");
    const auto unlock_report = FileUnlocker::release_locks(
        target.root_path, !options.no_handle_kill);

    std::wcout << L"Lock release summary: "
               << unlock_report.handles_closed << L" handles closed\n";

    if (!plan.services_to_remove.empty() || !plan.tasks_to_remove.empty()) {
        Logger::info(L"Removing services, drivers, and scheduled tasks...");
        const auto svc_report = ServiceManager::remove_services_and_tasks(target.root_path);

        std::wcout << L"Service summary: "
                   << svc_report.services_stopped << L" services stopped, "
                   << svc_report.services_deleted << L" services deleted, "
                   << svc_report.drivers_stopped << L" drivers stopped, "
                   << svc_report.drivers_deleted << L" drivers deleted, "
                   << svc_report.tasks_deleted << L" tasks deleted\n";

        if (svc_report.reboot_required) {
            Logger::warn(L"One or more drivers were marked for deletion; system reboot required");
        }

        for (const auto& w : svc_report.warnings) {
            Logger::warn(w);
        }
    }

    Logger::info(L"Deleting directory tree...");
    PhysicalWipeReport wipe_report;
    auto wipe_res = FileWiper::wipe_physical_tree(target.root_path, wipe_report);

    std::wcout << L"Filesystem summary: "
               << wipe_report.files_deleted << L" files deleted, "
               << wipe_report.directories_deleted << L" directories deleted, "
               << wipe_report.junctions_deleted << L" junctions deleted, "
               << wipe_report.acl_resets << L" ACL take-overs performed, "
               << FileWiper::format_bytes(wipe_report.bytes_freed) << L" freed\n";

    if (wipe_report.files_scheduled_for_reboot > 0 || wipe_report.directories_scheduled_for_reboot > 0) {
        std::wcout << L"Reboot pending: "
                   << wipe_report.files_scheduled_for_reboot << L" files and "
                   << wipe_report.directories_scheduled_for_reboot
                   << L" directories scheduled for removal upon reboot\n";
    }

    if (wipe_report.reboot_required) {
        Logger::warn(L"One or more locked items require a system reboot to complete deletion");
    }

    if (!wipe_res) {
        Logger::warn(L"Some filesystem items could not be deleted: " + wipe_res.error().message());
    }

    Logger::info(L"Cleaning registry entries...");
    RegistryCleanReport reg_report;
    auto reg_res = RegistryCleaner::clean(target, reg_report, options.no_backup);

    std::wcout << L"Registry summary: "
               << reg_report.total_keys_deleted << L" keys deleted, "
               << reg_report.total_values_deleted << L" values deleted, "
               << reg_report.items_backed_up << L" backed up to .reg\n";

    if (reg_report.items_backed_up > 0 && !reg_report.backup_directory.empty()) {
        std::wcout << L"Backup location: " << reg_report.backup_directory << L"\n";
    }

    if (!reg_res) {
        Logger::warn(L"Some registry items could not be deleted: " + reg_res.error().message());
    }

    Logger::info(L"Cleaning leftovers on disk and firewall rules...");
    const auto left_report = LeftoversCleaner::clean_leftovers(target, options.aggressive);

    std::wcout << L"Leftovers summary: "
               << left_report.folders_deleted << L" folders deleted, "
               << left_report.shortcuts_deleted << L" shortcuts deleted, "
               << left_report.firewall_rules_deleted << L" firewall rules deleted\n";

    if (left_report.possible_leftovers_skipped > 0) {
        std::wcout << L"Possible leftovers skipped: "
                   << left_report.possible_leftovers_skipped
                   << L" (re-run with --aggressive to remove)\n";
    }

    return 0;
}
