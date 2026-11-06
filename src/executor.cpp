#include "obliterator/executor.hpp"

#include "obliterator/confidence_engine.hpp"
#include "obliterator/defuse.hpp"
#include "obliterator/error.hpp"
#include "obliterator/leftovers.hpp"
#include "obliterator/log.hpp"
#include "obliterator/plan.hpp"
#include "obliterator/process.hpp"
#include "obliterator/profile.hpp"
#include "obliterator/quarantine.hpp"
#include "obliterator/registry_cleaner.hpp"
#include "obliterator/restore_point.hpp"
#include "obliterator/resume.hpp"
#include "obliterator/service.hpp"
#include "obliterator/shell_cleaner.hpp"
#include "obliterator/ui.hpp"
#include "obliterator/uninstaller.hpp"
#include "obliterator/unlocker.hpp"
#include "obliterator/uwp.hpp"
#include "obliterator/volume.hpp"
#include "obliterator/wiper.hpp"

#include <chrono>
#include <filesystem>
#include <string>

namespace obliterator {

static bool is_item_excluded(const std::wstring& id, const std::vector<ScoredArtifact>& excluded) {
    for (const auto& item : excluded) {
        if (_wcsicmp(item.identifier.c_str(), id.c_str()) == 0) {
            return true;
        }
    }
    return false;
}

FinalReport execute_obliteration(
    const Target& target,
    const CommandLineOptions& options,
    const std::vector<ScoredArtifact>& excluded_artifacts,
    PhaseCallback on_phase,
    LogCallback on_log,
    CancelCheck is_cancelling
) {
    auto emit_log = [&](const std::wstring& msg) {
        Logger::info(msg);
        if (on_log) {
            on_log(msg);
        }
    };

    auto check_cancelled = [&]() -> bool {
        if (is_cancelling && is_cancelling()) {
            emit_log(L"Execution halted between phases upon user request.");
            return true;
        }
        return false;
    };

    FinalReport final_report;
    final_report.target_name = target.name;
    final_report.target_root = target.root_path;

    const auto volume_snapshots = VolumeManager::snapshot_volumes();

    std::vector<UserProfileInfo> target_profiles;
    if (options.all_users || !options.user_filter.empty()) {
        target_profiles = ProfileManager::enumerate_profiles(
            options.include_system_profiles,
            options.user_filter
        );
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

    Plan plan(target);

    if (target.is_uwp) {
        for (const auto& rem_folder : UwpManager::get_remnant_folders(target.uwp_package_family_name)) {
            if (!is_item_excluded(rem_folder, excluded_artifacts)) {
                plan.leftovers_to_remove.push_back({rem_folder, L"FOLDER", L"DEFINITE", L"UWP package data directory"});
            }
        }
        for (const auto& rem_subkey : UwpManager::get_remnant_registry_subkeys(target.uwp_package_family_name)) {
            if (!is_item_excluded(rem_subkey, excluded_artifacts)) {
                plan.registry_keys_to_remove.push_back({HKEY_CURRENT_USER, rem_subkey, 0, L"UWP AppModel registration"});
            }
        }
    }

    // 1. Discover processes
    const auto target_procs = ProcessManager::find_target_processes(target.root_path);
    for (const auto& proc : target_procs) {
        if (!is_item_excluded(proc.name, excluded_artifacts) &&
            !is_item_excluded(proc.image_path, excluded_artifacts)) {
            std::wstring reason = proc.matched_as_descendant ? L"descendant process" :
                                 (proc.matched_by_module ? L"loaded module" : L"image path");
            plan.processes_to_terminate.push_back({proc.pid, proc.name, proc.image_path, reason});
        }
    }

    // 2. Discover file locks
    const auto locked_files = FileUnlocker::inspect_locks(target.root_path);
    for (const auto& lock : locked_files) {
        plan.locked_files_to_release.push_back({lock.path, lock.pid, lock.process_name});
    }

    // 3. Discover services and drivers
    const auto target_services = ServiceManager::find_target_services(target.root_path);
    for (const auto& svc : target_services) {
        if (!is_item_excluded(svc.name, excluded_artifacts)) {
            plan.services_to_remove.push_back({svc.name, svc.display_name, svc.binary_path, svc.is_driver});
        }
    }

    // 4. Discover scheduled tasks
    const auto target_tasks = ServiceManager::find_target_tasks(target.root_path);
    for (const auto& task : target_tasks) {
        if (!is_item_excluded(task.name, excluded_artifacts)) {
            plan.tasks_to_remove.push_back({task.name, task.folder_path, task.action_path});
        }
    }

    // 5. Discover autorun entries
    const auto target_autoruns = RegistryCleaner::find_autorun_entries(target.root_path);
    for (const auto& ar : target_autoruns) {
        if (!is_item_excluded(ar.value_name, excluded_artifacts)) {
            plan.registry_keys_to_remove.push_back({
                ar.root_key,
                ar.subkey_path + L" [" + ar.value_name + L"]",
                ar.sam_view,
                L"autorun value"
            });
        }
    }

    // 6. Discover shell verbs
    const auto target_shells = RegistryCleaner::find_shell_entries(target.root_path);
    for (const auto& sh : target_shells) {
        if (!is_item_excluded(sh.subkey_path, excluded_artifacts)) {
            plan.registry_keys_to_remove.push_back({
                sh.root_key,
                sh.subkey_path,
                0,
                sh.is_clsid ? L"shell extension CLSID" : L"context menu verb"
            });
        }
    }

    // 7. Discover product keys
    const auto target_prod_keys = RegistryCleaner::find_product_keys(target);
    for (const auto& pk : target_prod_keys) {
        if (!is_item_excluded(pk.subkey_path, excluded_artifacts)) {
            plan.registry_keys_to_remove.push_back({
                pk.root_key,
                pk.subkey_path,
                pk.sam_view,
                L"product/vendor key"
            });
        }
    }

    // 8. Discover leftovers
    const auto all_installed_apps = UserInterface::enumerate_installed_apps();
    const auto scored_artifacts = ConfidenceEngine::discover_artifacts(target, all_installed_apps, target_profiles);
    for (const auto& art : scored_artifacts) {
        if (art.category == ArtifactConfidenceCategory::Skip) {
            continue;
        }
        if (!is_item_excluded(art.identifier, excluded_artifacts)) {
            std::wstring conf_str = (art.category == ArtifactConfidenceCategory::Safe) ? L"SAFE" : L"REVIEW";
            plan.leftovers_to_remove.push_back({
                art.identifier,
                art.kind_string(),
                conf_str,
                L"Score: " + std::to_wstring(art.score)
            });
        }
    }

    final_report.artifacts = scored_artifacts;

    // Restore Point
    int64_t restore_pt_seq = 0;
    if (!options.no_restore_point && !options.dry_run) {
        emit_log(L"Creating System Restore Point...");
        auto rp_res = RestorePointManager::create_restore_point(target.name, options.require_restore_point);
        if (rp_res) {
            restore_pt_seq = rp_res.value().sequence_number;
            emit_log(L"System Restore Point created (seq " + std::to_wstring(restore_pt_seq) + L").");
        } else {
            emit_log(L"Restore Point notice: " + rp_res.error().message());
        }
    }

    if (check_cancelled()) {
        final_report.success = false;
        final_report.exit_code = ExitCode::Error;
        return final_report;
    }

    // Native uninstaller strategy ("gentle first, force after")
    const auto native_info = NativeUninstaller::detect(target);
    if (native_info.type != UninstallerType::None) {
        emit_log(std::wstring(L"Detected native uninstaller: ") +
                 NativeUninstaller::type_name(native_info.type));
    }

    if (options.force) {
        emit_log(L"--force specified; skipping native uninstaller.");
    } else if (native_info.type == UninstallerType::Unknown) {
        emit_log(L"Unrecognized native uninstaller format. Skipping silent execution.");
    } else if (native_info.type != UninstallerType::None) {
        if (options.dry_run) {
            emit_log(L"[DRY RUN] Would execute native uninstaller: " + native_info.quiet_command);
        } else {
            if (native_info.type == UninstallerType::Uwp) {
                emit_log(L"Removing UWP package: " + native_info.package_full_name);
                auto uwp_res = UwpManager::remove_package(native_info.package_full_name);
                if (!uwp_res) {
                    emit_log(L"UWP removal notice: " + uwp_res.error().message());
                } else {
                    emit_log(L"UWP package removed successfully.");
                }
            } else {
                emit_log(L"Running native uninstaller with " +
                         std::to_wstring(options.native_timeout_seconds) + L"s timeout...");
                auto uninst_res = NativeUninstaller::execute_with_timeout(
                    native_info,
                    options.native_timeout_seconds
                );
                if (!uninst_res) {
                    emit_log(L"Native uninstaller did not complete successfully: " +
                             uninst_res.error().message());
                } else {
                    emit_log(L"Native uninstaller completed.");
                }
            }

            if (options.native_only) {
                emit_log(L"--native-only flag active; skipping forced obliteration.");
                final_report.success = true;
                final_report.exit_code = ExitCode::Success;
                return final_report;
            }
        }
    } else if (options.native_only) {
        emit_log(L"No native uninstaller found for target, cannot satisfy --native-only.");
        final_report.success = false;
        final_report.exit_code = ExitCode::Error;
        return final_report;
    }

    if (check_cancelled()) {
        final_report.success = false;
        final_report.exit_code = ExitCode::Error;
        return final_report;
    }

    // Phase 1: Defuse restart mechanisms
    if (on_phase) on_phase(1, L"Defuse restart mechanisms");
    emit_log(L"Phase 1: Defusing restart mechanisms, service failure actions, and tasks...");
    RecoveryDefuser::defuse_all(target, plan.services_to_remove, plan.tasks_to_remove);

    if (check_cancelled()) {
        final_report.success = false;
        final_report.exit_code = ExitCode::Error;
        return final_report;
    }

    // Phase 2: Freeze processes
    if (on_phase) on_phase(2, L"Freeze target processes");
    if (!plan.processes_to_terminate.empty()) {
        emit_log(L"Phase 2: Freezing target processes to prevent watchdog respawning...");
        ProcessManager::suspend_target_processes(target.root_path);
    }

    if (check_cancelled()) {
        final_report.success = false;
        final_report.exit_code = ExitCode::Error;
        return final_report;
    }

    // Phase 3: Terminate processes
    if (on_phase) on_phase(3, L"Terminate target processes");
    if (!plan.processes_to_terminate.empty()) {
        emit_log(L"Phase 3: Terminating target processes...");
        const auto report = ProcessManager::terminate_target_processes(
            target.root_path, options.timeout_seconds);
        final_report.processes_found = report.found;
        final_report.processes_killed = report.killed;
        final_report.processes_failed = report.failed;
        emit_log(L"Processes terminated: " + std::to_wstring(report.killed) +
                 L" of " + std::to_wstring(report.found));
    }

    if (check_cancelled()) {
        final_report.success = false;
        final_report.exit_code = ExitCode::Error;
        return final_report;
    }

    // Phase 4: Release file locks
    if (on_phase) on_phase(4, L"Release file locks");
    emit_log(L"Phase 4: Releasing file locks...");
    const auto unlock_report = FileUnlocker::release_locks(
        target.root_path, !options.no_handle_kill);
    final_report.handles_closed = unlock_report.handles_closed;
    emit_log(L"Handles closed: " + std::to_wstring(unlock_report.handles_closed));

    if (check_cancelled()) {
        final_report.success = false;
        final_report.exit_code = ExitCode::Error;
        return final_report;
    }

    // Phase 5: Remove services and tasks
    if (on_phase) on_phase(5, L"Remove services and tasks");
    if (!plan.services_to_remove.empty() || !plan.tasks_to_remove.empty()) {
        emit_log(L"Phase 5: Removing services, drivers, and scheduled tasks...");
        const auto svc_report = ServiceManager::remove_services_and_tasks(target.root_path);
        final_report.services_stopped = svc_report.services_stopped;
        final_report.services_deleted = svc_report.services_deleted;
        final_report.drivers_stopped = svc_report.drivers_stopped;
        final_report.drivers_deleted = svc_report.drivers_deleted;
        final_report.tasks_deleted = svc_report.tasks_deleted;

        if (svc_report.reboot_required) {
            final_report.reboot_required = true;
            final_report.pending_reboot_items.push_back(L"One or more drivers marked for deletion");
        }
        emit_log(L"Services deleted: " + std::to_wstring(svc_report.services_deleted) +
                 L", tasks deleted: " + std::to_wstring(svc_report.tasks_deleted));
    }

    if (check_cancelled()) {
        final_report.success = false;
        final_report.exit_code = ExitCode::Error;
        return final_report;
    }

    // Phase 6: Wipe or Quarantine
    if (on_phase) on_phase(6, L"Wipe physical files");
    PhysicalWipeReport wipe_report;
    Result<void> wipe_res = Result<void>::success();

    if (options.quarantine) {
        emit_log(L"Phase 6: Quarantining target files...");
        auto q_res = QuarantineManager::quarantine_target(target, options.quarantine_dir);
        if (!q_res) {
            emit_log(L"Quarantine failed: " + q_res.error().message());
            wipe_res = q_res.error();
        } else {
            const auto& q_rep = q_res.value();
            final_report.files_deleted = q_rep.files_quarantined;
            final_report.bytes_freed = q_rep.bytes_quarantined;
            emit_log(L"Quarantined " + std::to_wstring(q_rep.files_quarantined) + L" files (" +
                     FileWiper::format_bytes(q_rep.bytes_quarantined) + L")");
        }
    } else {
        emit_log(L"Phase 6: Deleting physical directory tree...");
        if (!target.root_path.empty() && !is_item_excluded(target.root_path, excluded_artifacts)) {
            wipe_res = FileWiper::wipe_physical_tree(target.root_path, wipe_report, true);
        }

        final_report.files_deleted = wipe_report.files_deleted;
        final_report.directories_deleted = wipe_report.directories_deleted;
        final_report.junctions_deleted = wipe_report.junctions_deleted;
        final_report.acl_resets = wipe_report.acl_resets;
        final_report.bytes_freed = wipe_report.bytes_freed;
        final_report.files_scheduled_for_reboot = wipe_report.files_scheduled_for_reboot;
        final_report.directories_scheduled_for_reboot = wipe_report.directories_scheduled_for_reboot;

        if (wipe_report.reboot_required) {
            final_report.reboot_required = true;
            for (const auto& path : wipe_report.failed_paths) {
                final_report.pending_reboot_items.push_back(path);
            }
        }
        emit_log(L"Files wiped: " + std::to_wstring(wipe_report.files_deleted) +
                 L", freed: " + FileWiper::format_bytes(wipe_report.bytes_freed));
    }

    if (check_cancelled()) {
        final_report.success = false;
        final_report.exit_code = ExitCode::Error;
        return final_report;
    }

    // Phase 7: Clean registry
    if (on_phase) on_phase(7, L"Clean registry keys and shell extensions");
    emit_log(L"Phase 7: Cleaning registry entries and shell extensions...");
    RegistryCleanReport reg_report;
    auto reg_res = RegistryCleaner::clean(target, reg_report, options.no_backup);
    for (const auto& prof : target_profiles) {
        ProfileManager::clean_profile_registry(prof, target, reg_report, options.no_backup);
    }

    const auto shell_rep = ShellCleaner::clean_shell_extensions(target.root_path, target.name);
    reg_report.shell_entries_deleted += (shell_rep.clsids_deleted + shell_rep.context_menu_handlers_deleted + shell_rep.icon_overlays_deleted);
    reg_report.total_keys_deleted += (shell_rep.clsids_deleted + shell_rep.context_menu_handlers_deleted + shell_rep.icon_overlays_deleted);

    final_report.uninstall_keys_deleted = reg_report.uninstall_keys_deleted;
    final_report.autorun_values_deleted = reg_report.autorun_values_deleted;
    final_report.shell_entries_deleted = reg_report.shell_entries_deleted;
    final_report.product_keys_deleted = reg_report.product_keys_deleted;
    final_report.total_reg_keys_deleted = reg_report.total_keys_deleted;
    final_report.total_reg_values_deleted = reg_report.total_values_deleted;
    final_report.items_backed_up = reg_report.items_backed_up;
    final_report.backup_directory = reg_report.backup_directory;
    emit_log(L"Registry keys deleted: " + std::to_wstring(reg_report.total_keys_deleted));

    if (check_cancelled()) {
        final_report.success = false;
        final_report.exit_code = ExitCode::Error;
        return final_report;
    }

    // Phase 8: Clean leftovers
    if (on_phase) on_phase(8, L"Clean disk leftovers and firewall");
    emit_log(L"Phase 8: Cleaning leftovers on disk and firewall rules...");
    const auto left_report = LeftoversCleaner::clean_leftovers(target, options.aggressive, all_installed_apps);
    final_report.folders_deleted = left_report.folders_deleted;
    final_report.shortcuts_deleted = left_report.shortcuts_deleted;
    final_report.firewall_rules_deleted = left_report.firewall_rules_deleted;
    final_report.possible_leftovers_skipped = left_report.possible_leftovers_skipped;

    namespace fs = std::filesystem;
    for (const auto& prof : target_profiles) {
        const auto prof_items = ProfileManager::find_profile_file_leftovers(prof, target);
        for (const auto& item : prof_items) {
            if (is_item_excluded(item.path_or_name, excluded_artifacts)) {
                continue;
            }
            ArtifactKind k = (item.kind == LeftoverKind::Shortcut) ? ArtifactKind::Shortcut : ArtifactKind::Folder;
            std::wstring ref_path;
            if (item.kind == LeftoverKind::Shortcut) {
                ref_path = LeftoversCleaner::resolve_shortcut_target(item.path_or_name);
            }
            ScoredArtifact scored = ConfidenceEngine::evaluate(item.path_or_name, k, target, all_installed_apps, ref_path);
            if (scored.category == ArtifactConfidenceCategory::Skip) {
                continue;
            }
            if (scored.category == ArtifactConfidenceCategory::Review && !options.aggressive) {
                final_report.possible_leftovers_skipped++;
                continue;
            }
            if (item.kind == LeftoverKind::Folder) {
                PhysicalWipeReport wipe_rep;
                auto del_res = FileWiper::wipe_physical_tree(item.path_or_name, wipe_rep);
                if (del_res && !fs::exists(item.path_or_name)) {
                    final_report.folders_deleted++;
                }
            } else if (item.kind == LeftoverKind::Shortcut) {
                WipeReport wipe_rep;
                auto del_res = FileWiper::delete_file_lazy(item.path_or_name, wipe_rep);
                if (del_res && !fs::exists(item.path_or_name)) {
                    final_report.shortcuts_deleted++;
                }
            }
        }
    }

    // Phase 9: Verification & resumption
    if (on_phase) on_phase(9, L"Finalize and schedule resumption");
    if (final_report.reboot_required) {
        ResumeState resume_state;
        resume_state.target_name = target.name;
        resume_state.target_root = target.root_path;
        resume_state.aggressive = options.aggressive;
        resume_state.pending_files = wipe_report.failed_paths;
        for (const auto& dir : wipe_report.failed_paths) {
            std::error_code ec;
            if (fs::is_directory(dir, ec)) {
                resume_state.pending_directories.push_back(dir);
            }
        }
        for (const auto& s : plan.services_to_remove) {
            if (s.is_driver) {
                resume_state.pending_drivers.push_back(s.name);
            } else {
                resume_state.pending_services.push_back(s.name);
            }
        }

        auto now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
        wchar_t time_buf[64]{};
        _wctime_s(time_buf, 64, &now);
        resume_state.created_at = time_buf;
        while (!resume_state.created_at.empty() &&
               (resume_state.created_at.back() == L'\n' || resume_state.created_at.back() == L'\r')) {
            resume_state.created_at.pop_back();
        }

        ResumeManager::save_resume_state(resume_state);
        emit_log(L"Scheduled post-reboot resumption via RunOnce and resume.json");
    }

    final_report.success = wipe_res.has_value() && reg_res.has_value();
    if (!final_report.success) {
        final_report.exit_code = ExitCode::Error;
    } else if (final_report.reboot_required) {
        final_report.exit_code = ExitCode::SuccessRebootRequired;
    } else {
        final_report.exit_code = ExitCode::Success;
    }

    if (restore_pt_seq > 0) {
        RestorePointManager::finish_restore_point(restore_pt_seq, !final_report.success);
    }

    final_report.volume_deltas = VolumeManager::compute_deltas(volume_snapshots);

    emit_log(L"Operation finished with exit code: " + std::to_wstring(final_report.exit_code));
    return final_report;
}

} // namespace obliterator
