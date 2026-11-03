#include "obliterator/wiper.hpp"
#include "obliterator/handles.hpp"
#include "obliterator/log.hpp"
#include "obliterator/safety.hpp"

#include <aclapi.h>

#include <algorithm>
#include <atomic>
#include <cwchar>
#include <thread>
#include <vector>

namespace obliterator {

std::wstring FileWiper::ensure_extended_path(const std::wstring& path) {
    if (path.starts_with(L"\\\\?\\")) {
        return path;
    }
    if (path.starts_with(L"\\\\")) {
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
    PhysicalWipeReport phys_report;
    auto res = wipe_physical_tree(target_root, phys_report);

    report.files_deleted = phys_report.files_deleted;
    report.directories_deleted = phys_report.directories_deleted;
    report.junctions_deleted = phys_report.junctions_deleted;
    report.acl_resets = phys_report.acl_resets;
    report.failed_paths = phys_report.failed_paths;

    return res;
}

std::wstring FileWiper::format_bytes(uint64_t bytes) {
    const wchar_t* units[] = {L"B", L"KB", L"MB", L"GB", L"TB"};
    int unit_idx = 0;
    double size = static_cast<double>(bytes);
    while (size >= 1024.0 && unit_idx < 4) {
        size /= 1024.0;
        unit_idx++;
    }
    if (unit_idx == 0) {
        return std::to_wstring(bytes) + L" B";
    }
    wchar_t buf[64];
    swprintf_s(buf, L"%.2f %s", size, units[unit_idx]);
    return std::wstring(buf);
}

Result<void> FileWiper::wipe_physical_tree(const std::wstring& target_root,
                                           PhysicalWipeReport& report) {
    const std::wstring norm_target = SafetyValidator::normalize_path(target_root);
    auto safe = SafetyValidator::validate_path(norm_target);
    if (!safe) {
        return safe.error();
    }

    const std::wstring ext_root = ensure_extended_path(norm_target);
    const DWORD root_attrs = GetFileAttributesW(ext_root.c_str());
    if (root_attrs == INVALID_FILE_ATTRIBUTES) {
        const DWORD err = GetLastError();
        if (err == ERROR_FILE_NOT_FOUND || err == ERROR_PATH_NOT_FOUND) {
            return Result<void>::success();
        }
        return Win32Error::from_code(err);
    }

    struct DirEntry {
        std::wstring path;
        bool is_reparse{false};
    };

    struct FileEntry {
        std::wstring path;
        uint64_t size{0};
        bool is_reparse{false};
    };

    std::vector<DirEntry> all_dirs;
    std::vector<FileEntry> files;

    if ((root_attrs & FILE_ATTRIBUTE_REPARSE_POINT) != 0) {
        if ((root_attrs & FILE_ATTRIBUTE_DIRECTORY) != 0) {
            all_dirs.push_back({norm_target, true});
        } else {
            files.push_back({norm_target, 0, true});
        }
    } else if ((root_attrs & FILE_ATTRIBUTE_DIRECTORY) == 0) {
        ULARGE_INTEGER sz{};
        UniqueHandle h(CreateFileW(
            ext_root.c_str(),
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            nullptr,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            nullptr
        ));
        if (h) {
            sz.LowPart = GetFileSize(h.get(), &sz.HighPart);
        }
        files.push_back({norm_target, sz.QuadPart, false});
    } else {
        std::vector<std::wstring> dir_stack;
        all_dirs.push_back({norm_target, false});
        dir_stack.push_back(norm_target);

        while (!dir_stack.empty()) {
            std::wstring curr = std::move(dir_stack.back());
            dir_stack.pop_back();

            const std::wstring ext_curr = ensure_extended_path(curr);
            const std::wstring pattern = ext_curr + L"\\*";
            WIN32_FIND_DATAW fd{};
            UniqueHandle find_h(FindFirstFileExW(
                pattern.c_str(),
                FindExInfoBasic,
                &fd,
                FindExSearchNameMatch,
                nullptr,
                FIND_FIRST_EX_LARGE_FETCH
            ));
            if (!find_h) {
                continue;
            }

            do {
                if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0) {
                    continue;
                }

                const std::wstring child = curr + L"\\" + fd.cFileName;
                const bool is_reparse = (fd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0;
                const bool is_dir = (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;

                if (is_reparse) {
                    if (is_dir) {
                        all_dirs.push_back({child, true});
                    } else {
                        files.push_back({child, 0, true});
                    }
                } else if (is_dir) {
                    all_dirs.push_back({child, false});
                    dir_stack.push_back(child);
                } else {
                    ULARGE_INTEGER sz{};
                    sz.LowPart = fd.nFileSizeLow;
                    sz.HighPart = fd.nFileSizeHigh;
                    files.push_back({child, sz.QuadPart, false});
                }
            } while (FindNextFileW(find_h.get(), &fd));
        }
    }

    std::sort(files.begin(), files.end(), [](const FileEntry& a, const FileEntry& b) {
        return a.path < b.path;
    });

    const size_t num_files = files.size();
    if (num_files > 0) {
        const unsigned int hw = std::thread::hardware_concurrency();
        const size_t max_threads = std::max(1u, std::min(hw == 0 ? 4u : hw, 8u));
        const size_t actual_threads = std::min(max_threads, num_files);

        struct FileResult {
            bool deleted{false};
            bool scheduled_for_reboot{false};
            bool acl_reset{false};
            DWORD error_code{0};
        };

        std::vector<FileResult> results(num_files);
        std::atomic<size_t> next_index{0};

        auto worker = [&]() {
            while (true) {
                const size_t idx = next_index.fetch_add(1, std::memory_order_relaxed);
                if (idx >= num_files) {
                    break;
                }

                const auto& file = files[idx];
                auto& res = results[idx];
                const std::wstring ext = ensure_extended_path(file.path);

                strip_file_attributes(ext);
                if (DeleteFileW(ext.c_str())) {
                    res.deleted = true;
                    continue;
                }

                DWORD err = GetLastError();
                if (err == ERROR_ACCESS_DENIED) {
                    auto acl_res = take_ownership_and_reset_dacl(ext);
                    if (acl_res) {
                        res.acl_reset = true;
                        strip_file_attributes(ext);
                        if (DeleteFileW(ext.c_str())) {
                            res.deleted = true;
                            continue;
                        }
                        err = GetLastError();
                    }
                }

                if (MoveFileExW(ext.c_str(), nullptr, MOVEFILE_DELAY_UNTIL_REBOOT)) {
                    res.scheduled_for_reboot = true;
                } else {
                    res.error_code = (err != 0) ? err : GetLastError();
                }
            }
        };

        std::vector<std::thread> pool;
        pool.reserve(actual_threads);
        for (size_t t = 0; t < actual_threads; ++t) {
            pool.emplace_back(worker);
        }
        for (auto& th : pool) {
            if (th.joinable()) {
                th.join();
            }
        }

        for (size_t i = 0; i < num_files; ++i) {
            const auto& file = files[i];
            const auto& res = results[i];

            if (res.acl_reset) {
                report.acl_resets++;
            }

            if (res.deleted) {
                report.files_deleted++;
                report.bytes_freed += file.size;
                if (file.is_reparse) {
                    report.junctions_deleted++;
                }
            } else if (res.scheduled_for_reboot) {
                report.files_scheduled_for_reboot++;
                report.reboot_required = true;
                Logger::debug(L"File locked, scheduled for reboot removal: " + file.path);
            } else {
                report.failed_paths.push_back(file.path);
                Logger::error(L"Failed to delete file: " + file.path + L" (error " +
                             std::to_wstring(res.error_code) + L")");
            }
        }
    }

    for (auto it = all_dirs.rbegin(); it != all_dirs.rend(); ++it) {
        const auto& dir = *it;
        const std::wstring ext = ensure_extended_path(dir.path);

        strip_file_attributes(ext);
        if (RemoveDirectoryW(ext.c_str())) {
            report.directories_deleted++;
            if (dir.is_reparse) {
                report.junctions_deleted++;
            }
            continue;
        }

        DWORD err = GetLastError();
        if (err == ERROR_ACCESS_DENIED) {
            auto acl_res = take_ownership_and_reset_dacl(ext);
            if (acl_res) {
                report.acl_resets++;
                strip_file_attributes(ext);
                if (RemoveDirectoryW(ext.c_str())) {
                    report.directories_deleted++;
                    if (dir.is_reparse) {
                        report.junctions_deleted++;
                    }
                    continue;
                }
                err = GetLastError();
            }
        }

        if (MoveFileExW(ext.c_str(), nullptr, MOVEFILE_DELAY_UNTIL_REBOOT)) {
            report.directories_scheduled_for_reboot++;
            report.reboot_required = true;
            Logger::debug(L"Directory scheduled for reboot removal: " + dir.path);
        } else {
            report.failed_paths.push_back(dir.path);
            Logger::error(L"Failed to remove directory: " + dir.path + L" (error " +
                         std::to_wstring(err != 0 ? err : GetLastError()) + L")");
        }
    }

    if (!report.failed_paths.empty()) {
        return Win32Error::from_code(ERROR_CAN_NOT_COMPLETE);
    }
    return Result<void>::success();
}

} // namespace obliterator
