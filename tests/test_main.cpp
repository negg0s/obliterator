#include "obliterator/error.hpp"
#include "obliterator/handles.hpp"
#include "obliterator/plan.hpp"
#include "obliterator/privileges.hpp"
#include "obliterator/process.hpp"
#include "obliterator/result.hpp"
#include "obliterator/safety.hpp"
#include "obliterator/service.hpp"
#include "obliterator/target.hpp"
#include "obliterator/unlocker.hpp"
#include "obliterator/wiper.hpp"

#include <crtdbg.h>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
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

int main() {
    _set_abort_behavior(0, _WRITE_ABORT_MSG | _CALL_REPORTFAULT);

    test_unique_handle();
    test_unique_hkey();
    test_unique_sc_handle();
    test_win32_error_and_result();
    test_safety_validation();
    test_install_folder_deduction();
    test_process_management();
    test_unlocker();
    test_service_manager();
    test_extended_path_formatting();
    test_reparse_point_and_acl();
    test_format_bytes();
    test_physical_wipe_tree();
    test_plan_structure();

    std::cout << "All tests passed successfully.\n";
    return 0;
}
