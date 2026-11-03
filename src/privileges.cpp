#include "obliterator/privileges.hpp"
#include "obliterator/handles.hpp"
#include "obliterator/log.hpp"

#include <array>

namespace obliterator {

static Result<void> adjust_token_privilege(HANDLE token, const wchar_t* privilege_name) {
    LUID luid{};
    if (!LookupPrivilegeValueW(nullptr, privilege_name, &luid)) {
        return Win32Error::last();
    }

    TOKEN_PRIVILEGES tp{};
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    // AdjustTokenPrivileges returns non-zero even if not all requested privileges
    // were assigned, so caller must check GetLastError against ERROR_NOT_ALL_ASSIGNED.
    SetLastError(ERROR_SUCCESS);
    if (!AdjustTokenPrivileges(token, FALSE, &tp, sizeof(tp), nullptr, nullptr)) {
        return Win32Error::last();
    }

    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
        return Win32Error::from_code(ERROR_NOT_ALL_ASSIGNED);
    }

    return Result<void>::success();
}

Result<void> enable_privilege(const wchar_t* privilege_name) {
    UniqueHandle token;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, token.put())) {
        return Win32Error::last();
    }

    return adjust_token_privilege(token.get(), privilege_name);
}

Result<void> enable_required_privileges() {
    UniqueHandle token;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, token.put())) {
        return Win32Error::last();
    }

    constexpr std::array<const wchar_t*, 4> privileges = {
        L"SeDebugPrivilege",
        L"SeTakeOwnershipPrivilege",
        L"SeRestorePrivilege",
        L"SeBackupPrivilege"
    };

    for (const wchar_t* priv : privileges) {
        auto res = adjust_token_privilege(token.get(), priv);
        if (!res) {
            Logger::debug(std::wstring(L"Failed to grant ") + priv + L": " +
                          res.error().message());
            return res;
        }
        Logger::debug(std::wstring(L"Granted privilege: ") + priv);
    }

    return Result<void>::success();
}

} // namespace obliterator
