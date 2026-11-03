#include "obliterator/error.hpp"
#include "obliterator/handles.hpp"
#include "obliterator/plan.hpp"
#include "obliterator/privileges.hpp"
#include "obliterator/result.hpp"
#include "obliterator/safety.hpp"
#include "obliterator/target.hpp"

#include <crtdbg.h>
#include <cstdlib>
#include <iostream>

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
    check(!plan.is_empty(), "plan is not empty");
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
    test_plan_structure();

    std::cout << "All tests passed successfully.\n";
    return 0;
}
