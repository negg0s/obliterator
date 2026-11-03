#include "obliterator/error.hpp"
#include "obliterator/handles.hpp"
#include "obliterator/privileges.hpp"
#include "obliterator/result.hpp"

#include <cstdlib>
#include <iostream>

using namespace obliterator;

static void check(bool condition) {
    if (!condition) {
        std::cerr << "Check failed\n";
        std::abort();
    }
}

static void test_unique_handle() {
    UniqueHandle empty;
    check(!empty.is_valid());
    check(!empty);
    check(empty.get() == INVALID_HANDLE_VALUE);

    HANDLE raw_event = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    check(raw_event != nullptr && raw_event != INVALID_HANDLE_VALUE);

    UniqueHandle h1(raw_event);
    check(h1.is_valid());
    check(h1.get() == raw_event);

    UniqueHandle h2 = std::move(h1);
    check(!h1.is_valid());
    check(h1.get() == INVALID_HANDLE_VALUE);
    check(h2.is_valid());
    check(h2.get() == raw_event);

    HANDLE released = h2.release();
    check(!h2.is_valid());
    check(released == raw_event);

    UniqueHandle h3(released);
    h3.reset();
    check(!h3.is_valid());
}

static void test_unique_hkey() {
    UniqueHKey empty;
    check(!empty.is_valid());
    check(empty.get() == nullptr);

    HKEY raw = nullptr;
    const LSTATUS status = RegOpenKeyExW(HKEY_CURRENT_USER, L"Software", 0, KEY_READ, &raw);
    check(status == ERROR_SUCCESS);
    check(raw != nullptr);

    UniqueHKey k1(raw);
    check(k1.is_valid());
    check(k1.get() == raw);

    UniqueHKey k2 = std::move(k1);
    check(!k1.is_valid());
    check(k1.get() == nullptr);
    check(k2.is_valid());

    k2.reset();
    check(!k2.is_valid());
}

static void test_unique_sc_handle() {
    UniqueScHandle empty;
    check(!empty.is_valid());
    check(empty.get() == nullptr);

    UniqueScHandle sc1;
    UniqueScHandle sc2 = std::move(sc1);
    check(!sc2.is_valid());
}

static void test_win32_error_and_result() {
    auto err = Win32Error::from_code(ERROR_ACCESS_DENIED);
    check(err.code() == ERROR_ACCESS_DENIED);
    check(!err.message().empty());
    check(!err.to_string().empty());

    Result<int> ok_result(42);
    check(ok_result.has_value());
    check(ok_result.value() == 42);
    check(*ok_result == 42);

    Result<int> err_result(err);
    check(!err_result.has_value());
    check(err_result.error().code() == ERROR_ACCESS_DENIED);

    Result<void> void_ok = Result<void>::success();
    check(void_ok.has_value());

    Result<void> void_err(err);
    check(!void_err.has_value());
    check(void_err.error().code() == ERROR_ACCESS_DENIED);
}

int main() {
    test_unique_handle();
    test_unique_hkey();
    test_unique_sc_handle();
    test_win32_error_and_result();

    std::cout << "All tests passed successfully.\n";
    return 0;
}
