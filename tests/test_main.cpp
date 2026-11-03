#include "obliterator/error.hpp"
#include "obliterator/handles.hpp"
#include "obliterator/leftovers.hpp"
#include "obliterator/path.hpp"
#include "obliterator/plan.hpp"
#include "obliterator/privileges.hpp"
#include "obliterator/process.hpp"
#include "obliterator/registry_cleaner.hpp"
#include "obliterator/report.hpp"
#include "obliterator/result.hpp"
#include "obliterator/safety.hpp"
#include "obliterator/service.hpp"
#include "obliterator/target.hpp"
#include "obliterator/ui.hpp"
#include "obliterator/unlocker.hpp"
#include "obliterator/wiper.hpp"

#include <crtdbg.h>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
#include <winioctl.h>

using namespace obliterator;

static void check(bool condition, const char* message) {
    if (!condition) {
        std::cerr << "Assertion failed: " << message << std::endl;
        std::exit(1);
    }
}

static void test_unique_handle() {
    UniqueHandle empty;
    check(!empty.is_valid(), "empty handle is not valid");
    check(!empty, "empty handle bool operator is false");
    check(empty.get() == INVALID_HANDLE_VALUE, "empty handle is INVALID_HANDLE_VALUE");

    HANDLE raw_event = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    check(raw_event != nullptr && raw_event != INVALID_HANDLE_VALUE, "created event handle");

    UniqueHandle h1(raw_event);
    check(h1.is_valid(), "h1 is valid");
    check(h1.get() == raw_event, "h1 matches raw event");

    UniqueHandle h2 = std::move(h1);
    check(!h1.is_valid(), "h1 invalid after move");
    check(h1.get() == INVALID_HANDLE_VALUE, "h1 handle reset after move");
    check(h2.is_valid(), "h2 valid after move");
    check(h2.get() == raw_event, "h2 owns raw event");

    HANDLE released = h2.release();
    check(!h2.is_valid(), "h2 invalid after release");
    check(released == raw_event, "released matches raw event");

    UniqueHandle h3(released);
    h3.reset();
    check(!h3.is_valid(), "h3 invalid after reset");
}

static void test_unique_hkey() {
    UniqueHKey empty;
    check(!empty.is_valid(), "empty hkey is not valid");
    check(empty.get() == nullptr, "empty hkey is nullptr");

    HKEY raw = nullptr;
    const LSTATUS status = RegOpenKeyExW(HKEY_CURRENT_USER, L"Software", 0, KEY_READ, &raw);
    check(status == ERROR_SUCCESS, "open HKCU\\Software");
    check(raw != nullptr, "raw hkey non-null");

    UniqueHKey k1(raw);
    check(k1.is_valid(), "k1 is valid");
    check(k1.get() == raw, "k1 owns raw");

    UniqueHKey k2 = std::move(k1);
    check(!k1.is_valid(), "k1 invalid after move");
    check(k1.get() == nullptr, "k1 null after move");
    check(k2.is_valid(), "k2 valid after move");

    k2.reset();
    check(!k2.is_valid(), "k2 invalid after reset");
}

static void test_unique_sc_handle() {
    UniqueScHandle empty;
    check(!empty.is_valid(), "empty sc handle is invalid");
    check(empty.get() == nullptr, "empty sc handle is null");

    UniqueScHandle sc1;
    UniqueScHandle sc2 = std::move(sc1);
    check(!sc2.is_valid(), "moved empty sc handle is invalid");
}

static void test_win32_error_and_result() {
    auto err = Win32Error::from_code(ERROR_ACCESS_DENIED);
    check(err.code() == ERROR_ACCESS_DENIED, "error code matches");
    check(!err.message().empty(), "error message non-empty");
    check(!err.to_string().empty(), "error to_string non-empty");

    Result<int> ok_result(42);
    check(ok_result.has_value(), "ok result has value");
    check(ok_result.value() == 42, "ok result value is 42");
    check(*ok_result == 42, "ok result deref is 42");

    Result<int> err_result(err);
    check(!err_result.has_value(), "err result has no value");
    check(err_result.error().code() == ERROR_ACCESS_DENIED, "err result error code");

    Result<void> void_ok = Result<void>::success();
    check(void_ok.has_value(), "void result has value");

    Result<void> void_err(err);
    check(!void_err.has_value(), "void err has no value");
    check(void_err.error().code() == ERROR_ACCESS_DENIED, "void err code");
}

static void test_safety_validation() {
    check(SafetyValidator::is_drive_root(L"C:\\"), "C:\\ is drive root");
    check(SafetyValidator::is_drive_root(L"c:"), "c: is drive root");
    check(SafetyValidator::is_drive_root(L"D:\\"), "D:\\ is drive root");
    check(!SafetyValidator::is_drive_root(L"C:\\Windows"), "C:\\Windows is not drive root");
    check(!SafetyValidator::is_drive_root(L"D:\\Projects"), "D:\\Projects is not drive root");

    const std::wstring norm_slashes = SafetyValidator::normalize_path(L"c:/windows/system32/");
    check(norm_slashes == L"C:\\Windows\\System32" || norm_slashes == L"C:\\windows\\system32",
          "normalized slashes and drive letter");

    // All drive roots must be rejected
    check(!SafetyValidator::validate_path(L"C:\\").has_value(), "reject C:\\");
    check(!SafetyValidator::validate_path(L"c:").has_value(), "reject c:");
    check(!SafetyValidator::validate_path(L"D:\\").has_value(), "reject D:\\");
    check(!SafetyValidator::validate_path(L"d:").has_value(), "reject d:");

    // Critical system folders must be rejected
    check(!SafetyValidator::validate_path(L"C:\\Windows").has_value(), "reject C:\\Windows");
    check(!SafetyValidator::validate_path(L"c:\\windows\\").has_value(), "reject c:\\windows\\");
    check(!SafetyValidator::validate_path(L"C:\\Windows\\System32").has_value(), "reject System32");
    check(!SafetyValidator::validate_path(L"C:\\Windows\\System32\\drivers").has_value(), "reject System32\\drivers");
    check(!SafetyValidator::validate_path(L"C:\\Users").has_value(), "reject C:\\Users");
    check(!SafetyValidator::validate_path(L"C:\\Program Files").has_value(), "reject Program Files");
    check(!SafetyValidator::validate_path(L"C:\\Program Files (x86)").has_value(), "reject Program Files (x86)");
    check(!SafetyValidator::validate_path(L"C:\\ProgramData").has_value(), "reject ProgramData");

    // Protected paths list must be non-empty and well-populated
    const auto protected_list = SafetyValidator::get_protected_paths();
    check(protected_list.size() >= 5, "protected list size >= 5");

    for (const auto& item : protected_list) {
        check(!SafetyValidator::validate_path(item.path).has_value(), "reject item in protected list");
    }

    // Safe non-system project path should pass validation
    const std::wstring safe_path = L"D:\\Projects\\TestDummySoftware";
    check(SafetyValidator::validate_path(safe_path).has_value(), "accept safe path");
}

static void test_install_folder_deduction() {
    const std::wstring deduced_loc =
        TargetResolver::deduce_install_folder(L"D:\\Games\\SampleGame", L"", L"");
    check(deduced_loc == L"D:\\Games\\SampleGame", "deduce from install_loc");

    const std::wstring deduced_cmd =
        TargetResolver::deduce_install_folder(L"", L"", L"\"D:\\Games\\SampleGame\\unins000.exe\" /SILENT");
    check(deduced_cmd == L"D:\\Games\\SampleGame", "deduce from uninstall command");

    const std::wstring deduced_cmd_unquoted =
        TargetResolver::deduce_install_folder(L"", L"", L"D:\\Games\\SampleGame\\uninstall.exe");
    check(deduced_cmd_unquoted == L"D:\\Games\\SampleGame", "deduce from unquoted uninstall exe");
}

static void test_process_management() {
    check(ProcessManager::is_system_process(L"C:\\Windows\\System32\\svchost.exe"), "svchost is system");
    check(ProcessManager::is_system_process(L"C:\\Windows\\explorer.exe"), "explorer is system");
    check(!ProcessManager::is_system_process(L"D:\\Games\\Game.exe"), "game is not system");
    check(!ProcessManager::is_system_process(L""), "empty is not system");

    FILETIME creation{};
    check(ProcessManager::query_process_times(GetCurrentProcess(), &creation), "query current process times");
    check(creation.dwLowDateTime != 0 || creation.dwHighDateTime != 0, "creation time non-zero");

    const DWORD parent_pid = ProcessManager::get_parent_process_id(GetCurrentProcessId());
    check(parent_pid != 0, "parent process id non-zero");

    const auto procs = ProcessManager::find_target_processes(L"D:\\Projects\\ObliteratorNonExistentTargetDir");
    check(procs.empty(), "target processes for non-existent path is empty");
}

static void test_unlocker() {
    check(FileUnlocker::is_critical_process(0), "pid 0 is critical");
    check(FileUnlocker::is_critical_process(4), "pid 4 is critical");
    check(FileUnlocker::is_critical_process(GetCurrentProcessId()), "self pid is critical");

    const auto locks = FileUnlocker::inspect_locks(L"D:\\Projects\\ObliteratorNonExistentLockPath");
    check(locks.empty(), "inspect locks on non-existent path is empty");

    const auto report = FileUnlocker::release_locks(L"D:\\Projects\\ObliteratorNonExistentLockPath", false);
    check(report.handles_closed == 0, "handles closed on non-existent path is 0");
}

static void test_service_manager() {
    const std::wstring driver_nt =
        ServiceManager::normalize_service_image_path(L"\\??\\C:\\Program Files\\App\\driver.sys");
    check(driver_nt == L"C:\\Program Files\\App\\driver.sys", "normalize driver NT prefix");

    const std::wstring quoted_svc =
        ServiceManager::normalize_service_image_path(L"\"C:\\Program Files\\App\\service.exe\" -run");
    check(quoted_svc == L"C:\\Program Files\\App\\service.exe", "normalize quoted service command");

    const auto target_services =
        ServiceManager::find_target_services(L"D:\\Projects\\ObliteratorNonExistentSvcDir");
    check(target_services.empty(), "find target services on non-existent path is empty");

    const auto target_tasks =
        ServiceManager::find_target_tasks(L"D:\\Projects\\ObliteratorNonExistentTaskDir");
    check(target_tasks.empty(), "find target tasks on non-existent path is empty");
}

static void test_extended_path_formatting() {
    check(FileWiper::ensure_extended_path(L"C:\\Foo") == L"\\\\?\\C:\\Foo", "ensure extended format");
    check(FileWiper::ensure_extended_path(L"\\\\?\\C:\\Foo") == L"\\\\?\\C:\\Foo", "already extended format");
    check(FileWiper::ensure_extended_path(L"\\\\server\\share") == L"\\\\?\\UNC\\server\\share", "unc extended format");
}

static void test_reparse_point_and_acl() {
    namespace fs = std::filesystem;
    const fs::path base = L"D:\\Projects\\obliterator\\build\\test_sandbox";
    fs::create_directories(base);

    // Test 1: Deletion of Read-Only file
    const fs::path ro_file = base / L"readonly_test.txt";
    {
        std::ofstream out(ro_file);
        out << "test content";
    }
    SetFileAttributesW(ro_file.c_str(), FILE_ATTRIBUTE_READONLY);

    WipeReport ro_report;
    auto ro_res = FileWiper::delete_file_lazy(ro_file.wstring(), ro_report);
    check(ro_res.has_value(), "delete readonly file succeeds");
    check(!fs::exists(ro_file), "readonly file removed from disk");
    check(ro_report.files_deleted == 1, "report records 1 deleted file");

    // Test 2: Reparse point (Junction) safety
    // The junction inside target_dir points to outside_dir containing a canary file.
    // Deleting target_dir must remove the junction, but MUST NOT delete outside_dir or canary!
    const fs::path outside_dir = base / L"outside_folder";
    const fs::path canary_file = outside_dir / L"canary.txt";
    fs::create_directories(outside_dir);
    {
        std::ofstream out(canary_file);
        out << "canary intact";
    }

    const fs::path target_dir = base / L"target_to_wipe";
    const fs::path junction_path = target_dir / L"junction_link";
    fs::create_directories(target_dir);

    // Create directory junction using Windows mklink /J
    std::wstring cmd = L"cmd.exe /c mklink /J \"" + junction_path.wstring() +
                       L"\" \"" + outside_dir.wstring() + L"\" >nul";
    _wsystem(cmd.c_str());

    check(fs::exists(junction_path), "junction created successfully");
    check(FileWiper::is_reparse_point(junction_path.wstring()), "junction recognized as reparse point");

    WipeReport tree_report;
    auto wipe_res = FileWiper::wipe_directory_tree(target_dir.wstring(), tree_report);
    check(wipe_res.has_value(), "wipe directory tree succeeds");
    check(!fs::exists(target_dir), "target tree removed");
    check(tree_report.junctions_deleted >= 1, "junction recorded as deleted");

    // Critical assertion: outside directory and canary file must remain untouched
    check(fs::exists(outside_dir), "outside directory preserved");
    check(fs::exists(canary_file), "canary file preserved");

    // Clean up outside directory
    fs::remove_all(outside_dir);
    fs::remove_all(base);
}

static void test_format_bytes() {
    check(FileWiper::format_bytes(0) == L"0 B", "format 0 B");
    check(FileWiper::format_bytes(512) == L"512 B", "format 512 B");
    check(FileWiper::format_bytes(1024) == L"1.00 KB", "format 1.00 KB");
    check(FileWiper::format_bytes(1048576) == L"1.00 MB", "format 1.00 MB");
    check(FileWiper::format_bytes(1073741824) == L"1.00 GB", "format 1.00 GB");
}

static void test_physical_wipe_tree() {
    namespace fs = std::filesystem;
    const fs::path base = L"D:\\Projects\\obliterator\\build\\test_physical_sandbox";
    const fs::path root = base / L"nested_app";
    const fs::path sub1 = root / L"sub1";
    const fs::path sub2 = sub1 / L"sub2";

    fs::create_directories(sub2);

    const std::string content1(1000, 'A');
    const std::string content2(500, 'B');
    const std::string content3(2000, 'C');

    {
        std::ofstream out(sub2 / L"file1.bin", std::ios::binary);
        out.write(content1.data(), static_cast<std::streamsize>(content1.size()));
    }
    {
        std::ofstream out(sub1 / L"file2.txt", std::ios::binary);
        out.write(content2.data(), static_cast<std::streamsize>(content2.size()));
    }
    {
        std::ofstream out(root / L"root_file.dat", std::ios::binary);
        out.write(content3.data(), static_cast<std::streamsize>(content3.size()));
    }

    PhysicalWipeReport report;
    auto res = FileWiper::wipe_physical_tree(root.wstring(), report);

    check(res.has_value(), "wipe_physical_tree returns success");
    check(!fs::exists(root), "root directory completely removed");
    check(report.files_deleted == 3, "exactly 3 files deleted");
    check(report.directories_deleted == 3, "exactly 3 directories deleted");
    check(report.bytes_freed == 3500, "freed 3500 bytes accurately counted");
    check(report.failed_paths.empty(), "no failed paths in physical wipe");

    fs::remove_all(base);
}

static void test_plan_structure() {
    Target target;
    target.name = L"SampleApp";
    target.root_path = L"D:\\Apps\\SampleApp";
    target.registry_entries.push_back({
        HKEY_LOCAL_MACHINE,
        L"Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\SampleApp",
        KEY_WOW64_64KEY,
        L"Sample App 1.0"
    });

    Plan plan(target);
    plan.processes_to_terminate.push_back({1234, L"Sample.exe", L"D:\\Apps\\SampleApp\\Sample.exe", L"image path"});
    plan.locked_files_to_release.push_back({L"D:\\Apps\\SampleApp\\data.db", 5678, L"DataServer.exe"});
    plan.services_to_remove.push_back({L"SampleSvc", L"Sample Service", L"D:\\Apps\\SampleApp\\svc.exe", false});
    plan.tasks_to_remove.push_back({L"SampleUpdater", L"\\", L"D:\\Apps\\SampleApp\\updater.exe"});

    check(!plan.is_empty(), "plan is not empty");
    check(plan.processes_to_terminate.size() == 1, "1 process in plan");
    check(plan.locked_files_to_release.size() == 1, "1 locked file in plan");
    check(plan.services_to_remove.size() == 1, "1 service in plan");
    check(plan.tasks_to_remove.size() == 1, "1 task in plan");
    check(plan.directories_to_remove.size() == 1, "1 directory in plan");
    check(plan.directories_to_remove[0] == L"D:\\Apps\\SampleApp", "directory matches target root");
    check(plan.registry_keys_to_remove.size() == 1, "1 registry key in plan");
    check(plan.registry_keys_to_remove[0].subkey_path ==
          L"Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\SampleApp",
          "registry key matches");
}

static void test_registry_backup() {
    namespace fs = std::filesystem;
    const fs::path backup_dir = L"D:\\Projects\\obliterator\\build\\test_reg_backup";
    fs::create_directories(backup_dir);
    RegistryBackup::set_custom_backup_directory(backup_dir.wstring());
    RegistryBackup::set_enabled(true);

    const std::wstring test_key_path = L"Software\\ObliteratorUnitTestKey";
    UniqueHKey test_key;
    LSTATUS st = RegCreateKeyExW(HKEY_CURRENT_USER, test_key_path.c_str(), 0, nullptr,
                                 0, KEY_READ | KEY_WRITE, nullptr, test_key.put(), nullptr);
    check(st == ERROR_SUCCESS, "create test registry key");

    const std::wstring val_data = L"TestStringData";
    st = RegSetValueExW(test_key.get(), L"StringVal", 0, REG_SZ,
                        reinterpret_cast<const BYTE*>(val_data.c_str()),
                        static_cast<DWORD>((val_data.size() + 1) * sizeof(wchar_t)));
    check(st == ERROR_SUCCESS, "set string value");

    const DWORD dword_data = 0x12345678;
    st = RegSetValueExW(test_key.get(), L"DwordVal", 0, REG_DWORD,
                        reinterpret_cast<const BYTE*>(&dword_data), sizeof(DWORD));
    check(st == ERROR_SUCCESS, "set dword value");

    // Test exporting key to .reg
    auto exp_key_res = RegistryBackup::export_key(HKEY_CURRENT_USER, test_key_path);
    check(exp_key_res.has_value(), "export_key succeeds");
    check(fs::exists(exp_key_res.value()), "exported .reg file exists on disk");
    check(fs::file_size(exp_key_res.value()) > 0, "exported .reg file non-empty");

    // Test exporting single value to .reg
    auto exp_val_res = RegistryBackup::export_value(HKEY_CURRENT_USER, test_key_path, L"StringVal");
    check(exp_val_res.has_value(), "export_value succeeds");
    check(fs::exists(exp_val_res.value()), "exported value .reg file exists");

    // Delete test key
    test_key.reset();
    auto del_res = RegistryCleaner::delete_key_tree(HKEY_CURRENT_USER, test_key_path);
    check(del_res.has_value(), "delete test key tree succeeds");

    // Clean up test backup files
    fs::remove_all(backup_dir);
}

static void test_registry_cleaner_autorun() {
    const std::wstring run_path = L"Software\\Microsoft\\Windows\\CurrentVersion\\Run";
    UniqueHKey run_key;
    LSTATUS st = RegOpenKeyExW(HKEY_CURRENT_USER, run_path.c_str(), 0,
                               KEY_READ | KEY_WRITE, run_key.put());
    check(st == ERROR_SUCCESS, "open HKCU Run key");

    const std::wstring val_name = L"ObliteratorTestAutorunEntry";
    const std::wstring fake_cmd = L"\"D:\\Projects\\ObliteratorFakeApp\\app.exe\" --silent";
    st = RegSetValueExW(run_key.get(), val_name.c_str(), 0, REG_SZ,
                        reinterpret_cast<const BYTE*>(fake_cmd.c_str()),
                        static_cast<DWORD>((fake_cmd.size() + 1) * sizeof(wchar_t)));
    check(st == ERROR_SUCCESS, "set fake autorun value");

    const auto found = RegistryCleaner::find_autorun_entries(L"D:\\Projects\\ObliteratorFakeApp");
    check(!found.empty(), "found autorun entry for target path");
    check(found[0].value_name == val_name, "matched autorun value name");

    st = RegDeleteValueW(run_key.get(), val_name.c_str());
    check(st == ERROR_SUCCESS, "cleaned up fake autorun value");
}

static void test_context_menu_installation() {
    auto install_res = UserInterface::install_context_menu();
    check(install_res.has_value(), "install_context_menu succeeds");

    UniqueHKey key;
    LSTATUS st = RegOpenKeyExW(HKEY_CURRENT_USER,
                               L"Software\\Classes\\Directory\\shell\\Obliterator",
                               0, KEY_READ, key.put());
    check(st == ERROR_SUCCESS, "context menu key exists in HKCU");

    auto uninstall_res = UserInterface::uninstall_context_menu();
    check(uninstall_res.has_value(), "uninstall_context_menu succeeds");

    key.reset();
    st = RegOpenKeyExW(HKEY_CURRENT_USER,
                       L"Software\\Classes\\Directory\\shell\\Obliterator",
                       0, KEY_READ, key.put());
    check(st != ERROR_SUCCESS, "context menu key removed from HKCU");
}

static void test_installed_apps_enumeration() {
    const auto apps = UserInterface::enumerate_installed_apps();
    // apps should be a valid list (might be non-empty on real system)
    for (size_t i = 1; i < apps.size(); ++i) {
        check(apps[i - 1].size_bytes >= apps[i].size_bytes, "apps sorted by size descending");
    }
}

static void test_final_report_json() {
    FinalReport rep;
    rep.target_name = L"TestApp";
    rep.target_root = L"D:\\Apps\\TestApp";
    rep.success = true;
    rep.exit_code = ExitCode::Success;
    rep.files_deleted = 42;
    rep.bytes_freed = 1048576;

    std::wstringstream ss;
    auto* old_buf = std::wcout.rdbuf(ss.rdbuf());
    rep.print_json();
    std::wcout.rdbuf(old_buf);

    const std::wstring json_str = ss.str();
    check(json_str.find(L"\"TestApp\"") != std::wstring::npos, "json contains target name");
    check(json_str.find(L"\"files_deleted\": 42") != std::wstring::npos, "json contains files_deleted");
    check(json_str.find(L"\"exit_code\": 0") != std::wstring::npos, "json contains exit_code");
}

static void test_path_normalization() {
    const std::wstring norm1 = SafetyValidator::normalize_path(L"c:/windows/system32/");
    check(norm1 == L"C:\\Windows\\System32" || norm1 == L"C:\\windows\\system32", "normalize forward slashes");

    const std::wstring norm2 = SafetyValidator::normalize_path(L"D:\\Projects\\obliterator\\build\\..\\src");
    check(norm2.find(L"..") == std::wstring::npos, "normalize removes dotdot");

    check(SafetyValidator::is_drive_root(L"C:\\"), "C:\\ is drive root");
    check(SafetyValidator::is_drive_root(L"c:"), "c: is drive root");
    check(!SafetyValidator::is_drive_root(L"C:\\Windows"), "C:\\Windows not drive root");
}

static void test_target_name_resolution_mock() {
    namespace fs = std::filesystem;
    const fs::path mock_dir = L"D:\\Projects\\obliterator\\build\\mock_test_install";
    fs::create_directories(mock_dir);

    const std::wstring subkey_path = L"Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\MockObliteratorApp";
    UniqueHKey key;
    LSTATUS st = RegCreateKeyExW(HKEY_CURRENT_USER, subkey_path.c_str(), 0, nullptr,
                                 0, KEY_WRITE, nullptr, key.put(), nullptr);
    check(st == ERROR_SUCCESS, "create mock uninstall key in HKCU");

    const std::wstring name = L"Mock Obliterator App";
    const std::wstring loc = mock_dir.wstring();
    const std::wstring uninst = L"\"" + loc + L"\\uninstall.exe\" /S";

    RegSetValueExW(key.get(), L"DisplayName", 0, REG_SZ,
                   reinterpret_cast<const BYTE*>(name.c_str()),
                   static_cast<DWORD>((name.size() + 1) * sizeof(wchar_t)));
    RegSetValueExW(key.get(), L"InstallLocation", 0, REG_SZ,
                   reinterpret_cast<const BYTE*>(loc.c_str()),
                   static_cast<DWORD>((loc.size() + 1) * sizeof(wchar_t)));
    RegSetValueExW(key.get(), L"UninstallString", 0, REG_SZ,
                   reinterpret_cast<const BYTE*>(uninst.c_str()),
                   static_cast<DWORD>((uninst.size() + 1) * sizeof(wchar_t)));

    key.reset();

    auto target_res = TargetResolver::resolve(L"Mock Obliterator");
    check(target_res.has_value(), "resolve mock target by name");
    check(target_res->name == name, "target name matches mock display name");
    check(target_res->root_path == loc, "target root path matches mock install location");

    RegistryCleaner::delete_key_tree(HKEY_CURRENT_USER, subkey_path);
    fs::remove_all(mock_dir);
}

static void test_integration_blocker_and_wipe() {
    namespace fs = std::filesystem;
    const fs::path sandbox = L"D:\\Projects\\obliterator\\build\\test_integration_sandbox";
    const fs::path target_dir = sandbox / L"StubbornApp";
    fs::create_directories(target_dir);

    wchar_t test_exe_path[MAX_PATH]{};
    GetModuleFileNameW(nullptr, test_exe_path, MAX_PATH);
    fs::path bin_dir = fs::path(test_exe_path).parent_path();
    fs::path blocker_src = bin_dir / L"test_blocker.exe";
    check(fs::exists(blocker_src), "test_blocker.exe binary found in build output");

    fs::path blocker_dst = target_dir / L"blocker.exe";
    fs::copy_file(blocker_src, blocker_dst, fs::copy_options::overwrite_existing);

    STARTUPINFOW si{};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};
    std::wstring cmd = L"\"" + blocker_dst.wstring() + L"\"";

    BOOL started = CreateProcessW(
        nullptr,
        cmd.data(),
        nullptr,
        nullptr,
        FALSE,
        0,
        nullptr,
        target_dir.wstring().c_str(),
        &si,
        &pi
    );
    check(started, "launched blocker.exe process");

    const DWORD parent_pid = pi.dwProcessId;
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    Sleep(500);

    const auto procs_before = ProcessManager::find_target_processes(target_dir.wstring());
    check(procs_before.size() >= 2, "found blocker parent and watchdog child processes");

    const fs::path locked_file = target_dir / L"locked_file.bin";
    check(fs::exists(locked_file), "locked_file.bin created on disk");

    HANDLE hTry = CreateFileW(locked_file.c_str(), GENERIC_READ | GENERIC_WRITE,
                              0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    check(hTry == INVALID_HANDLE_VALUE, "file is actively locked by blocker process");

    auto term_report = ProcessManager::terminate_target_processes(target_dir.wstring(), 5);
    check(term_report.killed >= 2, "terminated at least 2 target processes");

    auto unlock_report = FileUnlocker::release_locks(target_dir.wstring(), true);
    (void)unlock_report;

    PhysicalWipeReport wipe_rep;
    auto wipe_res = FileWiper::wipe_physical_tree(target_dir.wstring(), wipe_rep);
    check(wipe_res.has_value(), "wipe_physical_tree succeeds on stubborn directory");
    check(!fs::exists(target_dir), "stubborn directory completely removed from disk");
    check(wipe_rep.files_deleted >= 2, "files deleted counted correctly");

    UniqueHandle hParent(OpenProcess(SYNCHRONIZE, FALSE, parent_pid));
    check(!hParent || WaitForSingleObject(hParent.get(), 0) == WAIT_OBJECT_0, "parent process dead");

    fs::remove_all(sandbox);
}

static void test_path_component_matching_regression() {
    // Regression check: C:\Apps\Foo must NOT match C:\Apps\FooBar
    check(!PathHelper::is_same_or_subpath(L"C:\\Apps\\Foo", L"C:\\Apps\\FooBar"),
          "Foo does not match FooBar");
    check(PathHelper::is_same_or_subpath(L"C:\\Apps\\Foo", L"C:\\Apps\\Foo\\Sub\\app.exe"),
          "Foo matches Foo\\Sub\\app.exe");
    check(PathHelper::is_same_or_subpath(L"C:\\Apps\\Foo", L"C:\\Apps\\Foo"),
          "Foo matches Foo exactly");
    check(PathHelper::is_same_or_subpath(L"c:/apps/foo/", L"C:\\APPS\\FOO\\sub"),
          "slash and case differences handled correctly");

    // Regression check: contains_path_reference inside command lines
    check(!PathHelper::contains_path_reference(L"\"C:\\Apps\\FooBar\\app.exe\" -arg", L"C:\\Apps\\Foo"),
          "FooBar command does not match Foo target");
    check(PathHelper::contains_path_reference(L"\"C:\\Apps\\Foo\\app.exe\" -arg", L"C:\\Apps\\Foo"),
          "Foo command matches Foo target");
    check(PathHelper::contains_path_reference(L"C:\\Apps\\Foo\\app.exe", L"C:\\Apps\\Foo"),
          "unquoted Foo path matches");
    check(!PathHelper::contains_path_reference(L"C:\\Apps\\FooBar\\app.exe", L"C:\\Apps\\Foo"),
          "unquoted FooBar path does not match");
}

static void test_service_image_path_with_dots_regression() {
    // Path containing .exe in directory name must not truncate at directory boundary
    const std::wstring p1 = ServiceManager::normalize_service_image_path(L"C:\\Tools.exe.backup\\sub\\svc.exe -run");
    check(p1 == L"C:\\Tools.exe.backup\\sub\\svc.exe", "dot exe in folder not truncated");

    const std::wstring p2 = ServiceManager::normalize_service_image_path(L"\"C:\\My.sys.dir\\driver.sys\" /d");
    check(p2 == L"C:\\My.sys.dir\\driver.sys", "dot sys in folder not truncated");
}

static void test_unique_find_handle_regression() {
    namespace fs = std::filesystem;
    const fs::path test_dir = L"D:\\Projects\\obliterator\\build\\test_find_handle";
    fs::create_directories(test_dir);
    {
        std::ofstream out(test_dir / L"file.tmp");
        out << "test";
    }

    WIN32_FIND_DATAW fd{};
    std::wstring pattern = test_dir.wstring() + L"\\*";
    UniqueFindHandle h(FindFirstFileW(pattern.c_str(), &fd));
    check(h.is_valid(), "UniqueFindHandle valid");
    check(static_cast<bool>(h), "UniqueFindHandle bool conversion true");

    h.reset();
    check(!h.is_valid(), "UniqueFindHandle closed cleanly via FindClose");

    fs::remove_all(test_dir);
}

static void test_surrogate_pair_to_lower_regression() {
    // Deseret Capital Letter Long I (U+10400) surrogate pair: D801 DC00
    // Lowercase is Deseret Small Letter Long I (U+10428): D801 DC28
    const std::wstring upper = L"\xD801\xDC00";
    const std::wstring lower = PathHelper::to_lower_unicode(upper);
    check(lower == L"\xD801\xDC28", "Unicode surrogate pair case folded properly");
}

static void test_malformed_path_exception_regression() {
    // Malformed paths with illegal NT device characters or raw prefixes must not throw std::filesystem_error
    try {
        const std::wstring malformed = L"\\\\?\\;\\bad:path*?\\test";
        (void)TargetResolver::deduce_install_folder(malformed, malformed, malformed);
        (void)TargetResolver::resolve(malformed);
    } catch (const std::exception& e) {
        check(false, e.what());
    }
}

int main() {
    _set_abort_behavior(0, _WRITE_ABORT_MSG | _CALL_REPORTFAULT);

    std::wcout << L"[RUN] test_unique_handle\n" << std::flush;
    test_unique_handle();
    std::wcout << L"[RUN] test_unique_hkey\n" << std::flush;
    test_unique_hkey();
    std::wcout << L"[RUN] test_unique_sc_handle\n" << std::flush;
    test_unique_sc_handle();
    std::wcout << L"[RUN] test_win32_error_and_result\n" << std::flush;
    test_win32_error_and_result();
    std::wcout << L"[RUN] test_safety_validation\n" << std::flush;
    test_safety_validation();
    std::wcout << L"[RUN] test_install_folder_deduction\n" << std::flush;
    test_install_folder_deduction();
    std::wcout << L"[RUN] test_process_management\n" << std::flush;
    test_process_management();
    std::wcout << L"[RUN] test_unlocker\n" << std::flush;
    test_unlocker();
    std::wcout << L"[RUN] test_service_manager\n" << std::flush;
    test_service_manager();
    std::wcout << L"[RUN] test_extended_path_formatting\n" << std::flush;
    test_extended_path_formatting();
    std::wcout << L"[RUN] test_reparse_point_and_acl\n" << std::flush;
    test_reparse_point_and_acl();
    std::wcout << L"[RUN] test_format_bytes\n" << std::flush;
    test_format_bytes();
    std::wcout << L"[RUN] test_physical_wipe_tree\n" << std::flush;
    test_physical_wipe_tree();
    std::wcout << L"[RUN] test_plan_structure\n" << std::flush;
    test_plan_structure();
    std::wcout << L"[RUN] test_registry_backup\n" << std::flush;
    test_registry_backup();
    std::wcout << L"[RUN] test_registry_cleaner_autorun\n" << std::flush;
    test_registry_cleaner_autorun();
    std::wcout << L"[RUN] test_context_menu_installation\n" << std::flush;
    test_context_menu_installation();
    std::wcout << L"[RUN] test_installed_apps_enumeration\n" << std::flush;
    test_installed_apps_enumeration();
    std::wcout << L"[RUN] test_final_report_json\n" << std::flush;
    test_final_report_json();
    std::wcout << L"[RUN] test_path_normalization\n" << std::flush;
    test_path_normalization();
    std::wcout << L"[RUN] test_target_name_resolution_mock\n" << std::flush;
    test_target_name_resolution_mock();
    std::wcout << L"[RUN] test_integration_blocker_and_wipe\n" << std::flush;
    test_integration_blocker_and_wipe();
    std::wcout << L"[RUN] test_path_component_matching_regression\n" << std::flush;
    test_path_component_matching_regression();
    std::wcout << L"[RUN] test_service_image_path_with_dots_regression\n" << std::flush;
    test_service_image_path_with_dots_regression();
    std::wcout << L"[RUN] test_unique_find_handle_regression\n" << std::flush;
    test_unique_find_handle_regression();
    std::wcout << L"[RUN] test_surrogate_pair_to_lower_regression\n" << std::flush;
    test_surrogate_pair_to_lower_regression();
    std::wcout << L"[RUN] test_malformed_path_exception_regression\n" << std::flush;
    test_malformed_path_exception_regression();

    std::wcout << L"All tests passed successfully.\n" << std::flush;
    return 0;
}
