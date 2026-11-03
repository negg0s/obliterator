#include "obliterator/wiper.hpp"
#include "obliterator/handles.hpp"
#include "obliterator/log.hpp"
#include "obliterator/safety.hpp"

#include <aclapi.h>

#include <algorithm>
#include <vector>

namespace obliterator {

std::wstring FileWiper::ensure_extended_path(const std::wstring& path) {
    if (path.starts_with(L"\\\\?\\")) {
        return path;
    }
    if (path.starts_with(L"\\\\")) {
        // UNC path: \\server\share -> \\?\UNC\server\share
        return L"\\\\?\\UNC" + path.substr(1);
    }
    return L"\\\\?\\" + path;
}

bool FileWiper::is_reparse_point(const std::wstring& path) {
    const std::wstring ext = ensure_extended_path(path);
    const DWORD attrs = GetFileAttributesW(ext.c_str());
    return (attrs != INVALID_FILE_ATTRIBUTES) && ((attrs & FILE_ATTRIBUTE_REPARSE_POINT) != 0);
}

bool FileWiper::strip_file_attributes(const std::wstring& path) {
    const std::wstring ext = ensure_extended_path(path);
    const DWORD attrs = GetFileAttributesW(ext.c_str());
    if (attrs == INVALID_FILE_ATTRIBUTES) {
        return false;
    }

    if ((attrs & (FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM)) != 0) {
        DWORD new_attrs = FILE_ATTRIBUTE_NORMAL;
        if ((attrs & FILE_ATTRIBUTE_DIRECTORY) != 0) {
            new_attrs = FILE_ATTRIBUTE_DIRECTORY;
        }
        return SetFileAttributesW(ext.c_str(), new_attrs) != 0;
    }
    return true;
}

Result<void> FileWiper::take_ownership_and_reset_dacl(const std::wstring& path) {
    const std::wstring ext = ensure_extended_path(path);

    BYTE admin_sid[SECURITY_MAX_SID_SIZE]{};
    DWORD sid_size = sizeof(admin_sid);
    if (!CreateWellKnownSid(WinBuiltinAdministratorsSid, nullptr, admin_sid, &sid_size)) {
        return Win32Error::last();
    }

    // Assign ownership to the Administrators group
    DWORD err = SetNamedSecurityInfoW(
        const_cast<LPWSTR>(ext.c_str()),
        SE_FILE_OBJECT,
        OWNER_SECURITY_INFORMATION,
        admin_sid,
        nullptr,
        nullptr,
        nullptr
    );
    if (err != ERROR_SUCCESS) {
        Logger::debug(L"Failed to set owner on " + path + L": " + std::to_wstring(err));
    }

    // Set new DACL giving Full Control to Administrators with no inheritance and no Deny ACE
    EXPLICIT_ACCESS_W ea{};
    ea.grfAccessPermissions = GENERIC_ALL;
    ea.grfAccessMode = SET_ACCESS;
    ea.grfInheritance = NO_INHERITANCE;
    ea.Trustee.TrusteeForm = TRUSTEE_IS_SID;
    ea.Trustee.TrusteeType = TRUSTEE_IS_GROUP;
    ea.Trustee.ptstrName = reinterpret_cast<LPWSTR>(admin_sid);

    PACL pDacl = nullptr;
    err = SetEntriesInAclW(1, &ea, nullptr, &pDacl);
    if (err == ERROR_SUCCESS && pDacl != nullptr) {
        err = SetNamedSecurityInfoW(
            const_cast<LPWSTR>(ext.c_str()),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            nullptr,
            nullptr,
            pDacl,
            nullptr
        );
        LocalFree(pDacl);
    }

    if (err != ERROR_SUCCESS) {
        return Win32Error::from_code(err);
    }

    return Result<void>::success();
}

Result<void> FileWiper::delete_file_lazy(const std::wstring& path, WipeReport& report) {
    const std::wstring ext = ensure_extended_path(path);
    strip_file_attributes(ext);

    if (DeleteFileW(ext.c_str())) {
        report.files_deleted++;
        return Result<void>::success();
    }

    DWORD err = GetLastError();
    if (err == ERROR_ACCESS_DENIED) {
        auto acl_res = take_ownership_and_reset_dacl(ext);
        if (acl_res) {
            report.acl_resets++;
            strip_file_attributes(ext);
            if (DeleteFileW(ext.c_str())) {
                report.files_deleted++;
                return Result<void>::success();
            }
            err = GetLastError();
        }
    }

    report.failed_paths.push_back(path);
    return Win32Error::from_code(err);
}

Result<void> FileWiper::delete_directory_lazy(const std::wstring& path, WipeReport& report) {
    const std::wstring ext = ensure_extended_path(path);
    strip_file_attributes(ext);

    if (RemoveDirectoryW(ext.c_str())) {
        report.directories_deleted++;
        return Result<void>::success();
    }

    DWORD err = GetLastError();
    if (err == ERROR_ACCESS_DENIED) {
        auto acl_res = take_ownership_and_reset_dacl(ext);
        if (acl_res) {
            report.acl_resets++;
            strip_file_attributes(ext);
            if (RemoveDirectoryW(ext.c_str())) {
                report.directories_deleted++;
                return Result<void>::success();
            }
            err = GetLastError();
        }
    }

    report.failed_paths.push_back(path);
    return Win32Error::from_code(err);
}

Result<void> FileWiper::wipe_directory_tree(const std::wstring& target_root, WipeReport& report) {
    const std::wstring norm_target = SafetyValidator::normalize_path(target_root);
    auto safe = SafetyValidator::validate_path(norm_target);
    if (!safe) {
        return safe.error();
    }

    const std::wstring ext_root = ensure_extended_path(norm_target);
    const DWORD root_attrs = GetFileAttributesW(ext_root.c_str());
    if (root_attrs == INVALID_FILE_ATTRIBUTES) {
        return Win32Error::last();
    }

    // If target itself is a reparse point or a file, remove it directly
    if ((root_attrs & FILE_ATTRIBUTE_REPARSE_POINT) != 0) {
        return delete_directory_lazy(norm_target, report);
    }
    if ((root_attrs & FILE_ATTRIBUTE_DIRECTORY) == 0) {
        return delete_file_lazy(norm_target, report);
    }

    const std::wstring search_pattern = ext_root + L"\\*";
    WIN32_FIND_DATAW find_data{};
    UniqueHandle find_handle(FindFirstFileExW(
        search_pattern.c_str(),
        FindExInfoBasic,
        &find_data,
        FindExSearchNameMatch,
        nullptr,
        FIND_FIRST_EX_LARGE_FETCH
    ));

    if (find_handle) {
        do {
            if (wcscmp(find_data.cFileName, L".") == 0 ||
                wcscmp(find_data.cFileName, L"..") == 0) {
                continue;
            }

            const std::wstring child_path = norm_target + L"\\" + find_data.cFileName;

            // Reparse points (junctions and symlinks): delete the link itself, never recurse inside
            if ((find_data.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0) {
                if ((find_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0) {
                    delete_directory_lazy(child_path, report);
                } else {
                    delete_file_lazy(child_path, report);
                }
                report.junctions_deleted++;
            } else if ((find_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0) {
                wipe_directory_tree(child_path, report);
            } else {
                delete_file_lazy(child_path, report);
            }
        } while (FindNextFileW(find_handle.get(), &find_data));
    }

    // Remove the containing directory once all children are gone
    return delete_directory_lazy(norm_target, report);
}

} // namespace obliterator
