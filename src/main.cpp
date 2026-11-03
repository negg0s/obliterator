#include "obliterator/cli.hpp"
#include "obliterator/confidence_engine.hpp"
#include "obliterator/defuse.hpp"
#include "obliterator/error.hpp"
#include "obliterator/leftovers.hpp"
#include "obliterator/log.hpp"
#include "obliterator/plan.hpp"
#include "obliterator/portable.hpp"
#include "obliterator/privileges.hpp"
#include "obliterator/process.hpp"
#include "obliterator/profile.hpp"
#include "obliterator/registry_cleaner.hpp"
#include "obliterator/report.hpp"
#include "obliterator/restore_point.hpp"
#include "obliterator/resume.hpp"
#include "obliterator/safe_mode.hpp"
#include "obliterator/safety.hpp"
#include "obliterator/service.hpp"
#include "obliterator/target.hpp"
#include "obliterator/ui.hpp"
#include "obliterator/uninstaller.hpp"
#include "obliterator/unlocker.hpp"
#include "obliterator/uwp.hpp"
#include "obliterator/quarantine.hpp"
#include "obliterator/audit.hpp"
#include "obliterator/crypto.hpp"
#include "obliterator/wiper.hpp"
#include "obliterator/tui.hpp"
#include "obliterator/executor.hpp"

#include <fcntl.h>
#include <filesystem>
#include <io.h>
#include <iostream>
#include <string>

int wmain(int argc, wchar_t* argv[]) {
    _setmode(_fileno(stdout), _O_U8TEXT);
    _setmode(_fileno(stderr), _O_U8TEXT);

    using namespace obliterator;

    auto parse_res = CommandLineParser::parse(argc, argv);
    if (!parse_res) {
        return ExitCode::Error;
    }

    auto options = parse_res.value();
    if (options.help_requested) {
        CommandLineParser::print_usage();
        return ExitCode::Success;
    }
    Logger::set_verbose(options.verbose);
    if (options.json) {
        Logger::set_json_mode(true);
    }

    if (options.list_sessions) {
        auto sessions = QuarantineManager::list_sessions();
        if (sessions.empty()) {
            std::wcout << L"No quarantine sessions found.\n";
            return ExitCode::Success;
        }
        std::wcout << L"\nQuarantine Sessions (" << sessions.size() << L"):\n";
        std::wcout << L"--------------------------------------------------------------------------------\n";
        for (const auto& s : sessions) {
            std::wcout << L" ID:       " << s.session_id << L"\n"
                       << L" Date:     " << s.timestamp << L"\n"
                       << L" Target:   " << s.target_name << L" (" << s.target_root << L")\n"
                       << L" Files:    " << s.files_count << L" (" << FileWiper::format_bytes(s.total_bytes) << L")\n"
                       << L" Registry: " << s.registry_keys_count << L" keys saved\n"
                       << L"--------------------------------------------------------------------------------\n";
        }
        return ExitCode::Success;
    }

    if (!options.restore_session_id.empty()) {
        enable_required_privileges();
        auto res = QuarantineManager::restore_session(options.restore_session_id);
        if (!res) {
            Logger::error(L"Failed to restore session: " + res.error().message());
            return ExitCode::Error;
        }
        const auto& rep = res.value();
        std::wcout << L"\nRestore Summary for " << rep.session_id << L":\n"
                   << L" - Files restored:     " << rep.files_restored << L"\n"
                   << L" - ACLs restored:      " << rep.acls_restored << L"\n"
                   << L" - Timestamps updated: " << rep.timestamps_restored << L"\n"
                   << L" - Registry keys:      " << rep.registry_keys_restored << L"\n";
        return rep.success ? ExitCode::Success : ExitCode::Error;
    }

    if (!options.purge_quarantine_arg.empty()) {
        enable_required_privileges();
        if (options.purge_quarantine_arg.starts_with(L"--older-than ")) {
            std::wstring days_str = options.purge_quarantine_arg.substr(13);
            if (!days_str.empty() && (days_str.back() == L'd' || days_str.back() == L'D')) {
                days_str.pop_back();
            }
            uint32_t days = static_cast<uint32_t>(std::stoul(days_str));
            auto res = QuarantineManager::purge_older_than(days);
            if (res) {
                std::wcout << L"Purged " << res.value() << L" quarantine session(s) older than " << days << L" days.\n";
                return ExitCode::Success;
            }
            return ExitCode::Error;
        } else {
            auto res = QuarantineManager::purge_session(options.purge_quarantine_arg);
            if (res) {
                std::wcout << L"Purged quarantine session: " << options.purge_quarantine_arg << L"\n";
                return ExitCode::Success;
            }
            Logger::error(L"Failed to purge quarantine session: " + res.error().message());
            return ExitCode::Error;
        }
    }

    if (options.resume) {
        enable_required_privileges();
        return ResumeManager::execute_resume();
    }

    if (options.safe_mode_plan) {
        enable_required_privileges();
        return SafeModeManager::execute_safe_mode_plan(options.yes, options.target);
    }

    if (options.install_menu) {
        auto res = UserInterface::install_context_menu();
        if (res) {
            std::wcout << L"Context menu item 'Force Obliterate' added successfully to HKCU.\n";
            return ExitCode::Success;
        }
        Logger::error(L"Failed to install context menu: " + res.error().message());
        return ExitCode::Error;
    }

    if (options.uninstall_menu) {
        auto res = UserInterface::uninstall_context_menu();
        if (res) {
            std::wcout << L"Context menu item 'Force Obliterate' removed successfully from HKCU.\n";
            return ExitCode::Success;
        }
        Logger::error(L"Failed to uninstall context menu: " + res.error().message());
        return ExitCode::Error;
    }

    if (!options.scan_portable_dir.empty()) {
        auto candidates = PortableScanner::scan(options.scan_portable_dir);
        PortableScanner::print_report(candidates, options.json);
        return ExitCode::Success;
    }

    if (!options.explain_artifact.empty()) {
        const auto apps = UserInterface::enumerate_installed_apps();
        ConfidenceEngine::explain(options.explain_artifact, apps);
        return ExitCode::Success;
    }

    if (options.bench) {
        if (options.target.empty()) {
            Logger::error(L"No target specified for benchmark. Usage: obliterator --bench <path>");
            return ExitCode::Error;
        }

        auto priv_res = enable_required_privileges();
        if (!priv_res) {
            Logger::warn(std::wstring(L"Could not assign all process privileges: ") +
                         priv_res.error().message());
        }

        struct BenchmarkTimer {
            LARGE_INTEGER freq;
            LARGE_INTEGER start;
            BenchmarkTimer() {
                QueryPerformanceFrequency(&freq);
                QueryPerformanceCounter(&start);
            }
            double elapsed_ms() const {
                LARGE_INTEGER now;
                QueryPerformanceCounter(&now);
                return static_cast<double>(now.QuadPart - start.QuadPart) * 1000.0 /
                       static_cast<double>(freq.QuadPart);
            }
        };

        BenchmarkTimer total_timer;

        BenchmarkTimer proc_timer;
        const auto procs = ProcessManager::find_target_processes(options.target);
        const double proc_ms = proc_timer.elapsed_ms();

        PhysicalWipeReport wipe_report;
        const auto wipe_res = FileWiper::wipe_physical_tree(options.target, wipe_report);

        BenchmarkTimer reg_timer;
        RegistryCleanReport reg_report;
        Target bench_target;
        bench_target.name = L"BenchmarkTarget";
        bench_target.root_path = options.target;
        const auto reg_res = RegistryCleaner::clean(bench_target, reg_report, true);
        const double reg_ms = reg_timer.elapsed_ms();

        const double total_ms = total_timer.elapsed_ms();

        std::wcout << L"\nBenchmark Results for: " << options.target << L"\n";
        std::wcout << L"  Process search:    " << proc_ms << L" ms (" << procs.size() << L" processes)\n";
        std::wcout << L"  File enumeration:  " << wipe_report.enumeration_ms << L" ms\n";
        std::wcout << L"  File deletion:     " << wipe_report.deletion_ms << L" ms ("
                   << wipe_report.files_deleted << L" files, "
                   << wipe_report.directories_deleted << L" dirs)\n";
        std::wcout << L"  Registry scan:     " << reg_ms << L" ms\n";
        std::wcout << L"  Total duration:    " << total_ms << L" ms\n";
        std::wcout << L"  Bytes freed:       " << FileWiper::format_bytes(wipe_report.bytes_freed) << L"\n";

        return wipe_res.has_value() ? ExitCode::Success : ExitCode::Error;
    }

    // Interactive mode if no target is provided
    if (options.target.empty()) {
        if (options.json) {
            Logger::error(L"No target specified for JSON mode. Provide a target name or path.");
            return ExitCode::Error;
        }

        if (is_console_interactive()) {
            return TuiRunner::run(options);
        }

        const auto apps = UserInterface::enumerate_installed_apps();
        auto chosen = UserInterface::select_app_interactive(apps);
        if (!chosen.has_value()) {
            return ExitCode::Success;
        }

        options.target = chosen->name;
        options.yes = true;
    }

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
        const DWORD err_code = target_res.error().code();
        Logger::error(L"Failed to resolve target: " + target_res.error().message());

        if (err_code == ERROR_ACCESS_DENIED) {
            return ExitCode::SafetyViolation;
        }
        return ExitCode::Error;
    }

    const auto& target = target_res.value();
    if (!target.is_uwp && !SafetyValidator::validate_path(target.root_path)) {
        Logger::error(L"Target path rejected by safety checks: " + target.root_path);
        return ExitCode::SafetyViolation;
    }

    std::vector<UserProfileInfo> target_profiles;
    if (options.all_users || !options.user_filter.empty()) {
        target_profiles = ProfileManager::enumerate_profiles(
            options.include_system_profiles,
            options.user_filter
        );
        if (options.all_users) {
            Logger::info(L"Targeting all user profiles (" + std::to_wstring(target_profiles.size()) + L" profiles discovered)");
        } else {
            Logger::info(L"Targeting user: " + options.user_filter + L" (" + std::to_wstring(target_profiles.size()) + L" profiles matched)");
        }
    } else {
        const std::wstring cur_sid = ProfileManager::get_current_user_sid();
        auto all_profs = ProfileManager::enumerate_profiles(options.include_system_profiles);
        for (const auto& p : all_profs) {
            if (p.sid == cur_sid) {
                target_profiles.push_back(p);
                break;
            }
        }
        if (target_profiles.empty() && !all_profs.empty()) {
            target_profiles.push_back(all_profs.front());
        }
    }

    // Native uninstaller strategy ("gentle first, force after")
    const auto native_info = NativeUninstaller::detect(target);
    if (native_info.type != UninstallerType::None) {
        Logger::info(std::wstring(L"Detected native uninstaller: ") +
                     NativeUninstaller::type_name(native_info.type));
    }

    if (options.force) {
        Logger::info(L"--force specified; skipping native uninstaller.");
    } else if (native_info.type == UninstallerType::Unknown) {
        Logger::warn(L"Unrecognized native uninstaller format. Skipping silent execution to prevent interactive prompts.");
    } else if (native_info.type != UninstallerType::None) {
        if (options.dry_run) {
            std::wcout << L"[DRY RUN] Would execute native uninstaller ("
                       << NativeUninstaller::type_name(native_info.type)
                       << L"): " << native_info.quiet_command << L"\n";
        } else {
            if (native_info.type == UninstallerType::Uwp) {
                Logger::info(L"Removing UWP package: " + native_info.package_full_name);
                auto uwp_res = UwpManager::remove_package(native_info.package_full_name);
                if (!uwp_res) {
                    Logger::warn(L"UWP package removal returned error: " + uwp_res.error().message());
                } else {
                    Logger::info(L"UWP package removed successfully.");
                }
            } else {
                Logger::info(L"Running native uninstaller with " +
                             std::to_wstring(options.native_timeout_seconds) + L"s timeout...");
                auto uninst_res = NativeUninstaller::execute_with_timeout(
                    native_info,
                    options.native_timeout_seconds
                );
                if (!uninst_res) {
                    Logger::warn(L"Native uninstaller did not complete successfully: " +
                                 uninst_res.error().message());
                } else {
                    Logger::info(L"Native uninstaller completed.");
                }
            }

            if (options.native_only) {
                Logger::info(L"--native-only flag active; skipping forced obliteration.");
                return ExitCode::Success;
            }
        }
    } else if (options.native_only) {
        Logger::error(L"No native uninstaller found for target, cannot satisfy --native-only.");
        return ExitCode::Error;
    }

    Plan plan(target);

    if (target.is_uwp) {
        for (const auto& rem_folder : UwpManager::get_remnant_folders(target.uwp_package_family_name)) {
            plan.leftovers_to_remove.push_back({rem_folder, L"FOLDER", L"DEFINITE", L"UWP package data directory"});
        }
        for (const auto& rem_subkey : UwpManager::get_remnant_registry_subkeys(target.uwp_package_family_name)) {
            plan.registry_keys_to_remove.push_back({HKEY_CURRENT_USER, rem_subkey, 0, L"UWP AppModel registration"});
        }
    }

    // 1. Discover processes associated with the target directory
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

    // 2. Discover file locks
    const auto locked_files = FileUnlocker::inspect_locks(target.root_path);
    for (const auto& lock : locked_files) {
        plan.locked_files_to_release.push_back({lock.path, lock.pid, lock.process_name});
    }

    // 3. Discover services and drivers
    const auto target_services = ServiceManager::find_target_services(target.root_path);
    for (const auto& svc : target_services) {
        plan.services_to_remove.push_back({svc.name, svc.display_name, svc.binary_path, svc.is_driver});
    }

    // 4. Discover scheduled tasks
    const auto target_tasks = ServiceManager::find_target_tasks(target.root_path);
    for (const auto& task : target_tasks) {
        plan.tasks_to_remove.push_back({task.name, task.folder_path, task.action_path});
    }

    // 5. Discover autorun entries
    const auto target_autoruns = RegistryCleaner::find_autorun_entries(target.root_path);
    for (const auto& ar : target_autoruns) {
        plan.registry_keys_to_remove.push_back({
            ar.root_key,
            ar.subkey_path + L" [" + ar.value_name + L"]",
            ar.sam_view,
            L"autorun value"
        });
    }

    // 6. Discover shell verbs and context menu extensions
    const auto target_shells = RegistryCleaner::find_shell_entries(target.root_path);
    for (const auto& sh : target_shells) {
        plan.registry_keys_to_remove.push_back({
            sh.root_key,
            sh.subkey_path,
            0,
            sh.is_clsid ? L"shell extension CLSID" : L"context menu verb"
        });
    }

    // 7. Discover product and vendor keys
    const auto target_prod_keys = RegistryCleaner::find_product_keys(target);
    for (const auto& pk : target_prod_keys) {
        plan.registry_keys_to_remove.push_back({
            pk.root_key,
            pk.subkey_path,
            pk.sam_view,
            L"product/vendor key"
        });
    }

    // 8. Discover leftovers with confidence scoring
    const auto all_installed_apps = UserInterface::enumerate_installed_apps();
    const auto scored_artifacts = ConfidenceEngine::discover_artifacts(target, all_installed_apps, target_profiles);
    for (const auto& art : scored_artifacts) {
        if (art.category == ArtifactConfidenceCategory::Skip) {
            continue;
        }
        std::wstring conf_str = (art.category == ArtifactConfidenceCategory::Safe) ? L"SAFE" : L"REVIEW";
        plan.leftovers_to_remove.push_back({
            art.identifier,
            art.kind_string(),
            conf_str,
            L"Score: " + std::to_wstring(art.score)
        });
    }

    if (options.dry_run) {
        Logger::info(L"Dry-run mode active; displaying plan without making modifications");
        plan.print();
        return ExitCode::Success;
    }

    if (!options.yes) {
        plan.print();
        if (!UserInterface::prompt_confirmation(target.name)) {
            std::wcout << L"Operation cancelled by user.\n";
            return ExitCode::Success;
        }
    }

    FinalReport final_report = execute_obliteration(target, options, {});

    if (options.json) {
        final_report.print_json();
    } else {
        final_report.print_text();
    }

    return final_report.exit_code;
}
