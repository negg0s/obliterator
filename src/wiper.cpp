#include "obliterator/wiper.hpp"
#include "obliterator/handles.hpp"
#include "obliterator/log.hpp"
#include "obliterator/safety.hpp"

#include <aclapi.h>

#include <algorithm>
#include <atomic>
#include <cwchar>
#include <iterator>
#include <string_view>
#include <thread>
#include <vector>

#ifndef FILE_DISPOSITION_FLAG_DELETE
#define FILE_DISPOSITION_FLAG_DELETE 0x00000001
#endif
#ifndef FILE_DISPOSITION_FLAG_POSIX_SEMANTICS
#define FILE_DISPOSITION_FLAG_POSIX_SEMANTICS 0x00000002
#endif
#ifndef FILE_DISPOSITION_FLAG_IGNORE_READONLY_ATTRIBUTE
#define FILE_DISPOSITION_FLAG_IGNORE_READONLY_ATTRIBUTE 0x00000010
#endif

namespace obliterator {

static bool delete_file_fast(const std::wstring& ext_path, DWORD& out_error) {
    UniqueHandle hFile(CreateFileW(
        ext_path.c_str(),
        DELETE | SYNCHRONIZE,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
        nullptr
    ));

    if (hFile) {
        FILE_DISPOSITION_INFO_EX disp{};
        disp.Flags = FILE_DISPOSITION_FLAG_DELETE |
                     FILE_DISPOSITION_FLAG_POSIX_SEMANTICS |
                     FILE_DISPOSITION_FLAG_IGNORE_READONLY_ATTRIBUTE;
        if (SetFileInformationByHandle(hFile.get(), FileDispositionInfoEx, &disp, sizeof(disp))) {
            return true;
        }

        FILE_DISPOSITION_INFO disp_std{};
        disp_std.DeleteFile = TRUE;
        if (SetFileInformationByHandle(hFile.get(), FileDispositionInfo, &disp_std, sizeof(disp_std))) {
            return true;
        }
    }

    UniqueHandle hDelete(CreateFileW(
        ext_path.c_str(),
        DELETE,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr,
        OPEN_EXISTING,
        FILE_FLAG_DELETE_ON_CLOSE | FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
        nullptr
    ));
    if (hDelete) {
        return true;
    }

    FileWiper::strip_file_attributes(ext_path);
    if (DeleteFileW(ext_path.c_str())) {
        return true;
    }

    out_error = GetLastError();
    if (out_error == ERROR_ACCESS_DENIED) {
        if (FileWiper::take_ownership_and_reset_dacl(ext_path)) {
            FileWiper::strip_file_attributes(ext_path);
            if (DeleteFileW(ext_path.c_str())) {
                return true;
            }
            out_error = GetLastError();
        }
    }
    return false;
}

static bool delete_directory_fast(const std::wstring& ext_path, DWORD& out_error) {
    UniqueHandle hDir(CreateFileW(
        ext_path.c_str(),
        DELETE | SYNCHRONIZE,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
        nullptr
    ));
    if (hDir) {
        FILE_DISPOSITION_INFO_EX disp{};
        disp.Flags = FILE_DISPOSITION_FLAG_DELETE |
                     FILE_DISPOSITION_FLAG_POSIX_SEMANTICS |
                     FILE_DISPOSITION_FLAG_IGNORE_READONLY_ATTRIBUTE;
        if (SetFileInformationByHandle(hDir.get(), FileDispositionInfoEx, &disp, sizeof(disp))) {
            return true;
        }
    }

    FileWiper::strip_file_attributes(ext_path);
    if (RemoveDirectoryW(ext_path.c_str())) {
        return true;
    }

    out_error = GetLastError();
    if (out_error == ERROR_ACCESS_DENIED) {
        if (FileWiper::take_ownership_and_reset_dacl(ext_path)) {
            FileWiper::strip_file_attributes(ext_path);
            if (RemoveDirectoryW(ext_path.c_str())) {
                return true;
            }
            out_error = GetLastError();
        }
    }
    return false;
}

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
    DWORD err = 0;
    if (delete_file_fast(ext, err)) {
        report.files_deleted++;
        return Result<void>::success();
    }
    report.failed_paths.push_back(path);
    return Win32Error::from_code(err != 0 ? err : GetLastError());
}

Result<void> FileWiper::delete_directory_lazy(const std::wstring& path, WipeReport& report) {
    const std::wstring ext = ensure_extended_path(path);
    DWORD err = 0;
    if (delete_directory_fast(ext, err)) {
        report.directories_deleted++;
        return Result<void>::success();
    }
    report.failed_paths.push_back(path);
    return Win32Error::from_code(err != 0 ? err : GetLastError());
}

Result<void> FileWiper::wipe_directory_tree(const std::wstring& target_root,
                                            WipeReport& report,
                                            bool compute_sizes) {
    PhysicalWipeReport phys_report;
    auto res = wipe_physical_tree(target_root, phys_report, compute_sizes);

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
                                           PhysicalWipeReport& report,
                                           bool compute_sizes,
                                           size_t thread_count) {
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

    struct FolderBatch {
        std::wstring folder_path;
        std::vector<FileEntry> files;
    };

    std::vector<DirEntry> all_dirs;
    std::vector<FolderBatch> folder_batches;

    struct ScopedTimer {
        LARGE_INTEGER freq;
        LARGE_INTEGER start;
        ScopedTimer() {
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

    ScopedTimer enum_timer;

    if ((root_attrs & FILE_ATTRIBUTE_REPARSE_POINT) != 0) {
        if ((root_attrs & FILE_ATTRIBUTE_DIRECTORY) != 0) {
            all_dirs.push_back({norm_target, true});
        } else {
            folder_batches.push_back(FolderBatch{norm_target, {{norm_target, 0, true}}});
        }
    } else if ((root_attrs & FILE_ATTRIBUTE_DIRECTORY) == 0) {
        uint64_t sz = 0;
        if (compute_sizes) {
            ULARGE_INTEGER u_sz{};
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
                u_sz.LowPart = GetFileSize(h.get(), &u_sz.HighPart);
                sz = u_sz.QuadPart;
            }
        }
        folder_batches.push_back(FolderBatch{norm_target, {{norm_target, sz, false}}});
    } else {
        std::vector<std::wstring> dir_stack;
        all_dirs.push_back({norm_target, false});
        dir_stack.push_back(norm_target);

        constexpr DWORD kDirBufferSize = 64 * 1024;
        std::vector<BYTE> dir_buffer(kDirBufferSize);

        while (!dir_stack.empty()) {
            std::wstring curr = std::move(dir_stack.back());
            dir_stack.pop_back();

            const std::wstring ext_curr = ensure_extended_path(curr);
            UniqueHandle hDir(CreateFileW(
                ext_curr.c_str(),
                FILE_LIST_DIRECTORY | SYNCHRONIZE,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                nullptr,
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS,
                nullptr
            ));

            if (!hDir) {
                DWORD err = GetLastError();
                if (err == ERROR_ACCESS_DENIED) {
                    if (take_ownership_and_reset_dacl(ext_curr)) {
                        hDir.reset(CreateFileW(
                            ext_curr.c_str(),
                            FILE_LIST_DIRECTORY | SYNCHRONIZE,
                            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                            nullptr,
                            OPEN_EXISTING,
                            FILE_FLAG_BACKUP_SEMANTICS,
                            nullptr
                        ));
                    }
                }
                if (!hDir) {
                    continue;
                }
            }

            std::vector<FileEntry> current_folder_files;

            while (GetFileInformationByHandleEx(
                hDir.get(),
                FileIdBothDirectoryInfo,
                dir_buffer.data(),
                static_cast<DWORD>(dir_buffer.size())
            )) {
                auto* info = reinterpret_cast<const FILE_ID_BOTH_DIR_INFO*>(dir_buffer.data());
                while (info != nullptr) {
                    std::wstring_view name(info->FileName, info->FileNameLength / sizeof(wchar_t));
                    if (name != L"." && name != L"..") {
                        const bool is_reparse = (info->FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0;
                        const bool is_dir = (info->FileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
                        const std::wstring child = curr + L"\\" + std::wstring(name);

                        if (is_reparse) {
                            if (is_dir) {
                                all_dirs.push_back({child, true});
                            } else {
                                current_folder_files.push_back({child, 0, true});
                            }
                        } else if (is_dir) {
                            all_dirs.push_back({child, false});
                            dir_stack.push_back(child);
                        } else {
                            const uint64_t file_sz = compute_sizes ? static_cast<uint64_t>(info->EndOfFile.QuadPart) : 0;
                            current_folder_files.push_back({child, file_sz, false});
                        }
                    }

                    if (info->NextEntryOffset == 0) {
                        break;
                    }
                    info = reinterpret_cast<const FILE_ID_BOTH_DIR_INFO*>(
                        reinterpret_cast<const BYTE*>(info) + info->NextEntryOffset
                    );
                }
            }

            if (!current_folder_files.empty()) {
                constexpr size_t kMaxChunk = 512;
                if (current_folder_files.size() > kMaxChunk) {
                    for (size_t start = 0; start < current_folder_files.size(); start += kMaxChunk) {
                        size_t count = std::min(kMaxChunk, current_folder_files.size() - start);
                        std::vector<FileEntry> chunk(
                            std::make_move_iterator(current_folder_files.begin() + start),
                            std::make_move_iterator(current_folder_files.begin() + start + count)
                        );
                        folder_batches.push_back(FolderBatch{curr, std::move(chunk)});
                    }
                } else {
                    folder_batches.push_back(FolderBatch{curr, std::move(current_folder_files)});
                }
            }
        }
    }

    report.enumeration_ms = enum_timer.elapsed_ms();

    ScopedTimer del_timer;

    const size_t num_batches = folder_batches.size();
    if (num_batches > 0) {
        size_t actual_threads = thread_count;
        if (actual_threads == 0) {
            const unsigned int hw = std::thread::hardware_concurrency();
            actual_threads = std::max(1u, std::min(hw == 0 ? 4u : hw, 12u));
        }
        actual_threads = std::min(actual_threads, num_batches);

        struct WorkerThreadStats {
            size_t files_deleted{0};
            size_t junctions_deleted{0};
            size_t acl_resets{0};
            uint64_t bytes_freed{0};
            size_t files_scheduled_for_reboot{0};
            std::vector<std::wstring> failed_paths;
        };

        std::vector<WorkerThreadStats> thread_stats(actual_threads);
        std::atomic<size_t> next_batch_idx{0};

        auto worker = [&](size_t thread_id) {
            auto& stats = thread_stats[thread_id];
            while (true) {
                const size_t batch_idx = next_batch_idx.fetch_add(1, std::memory_order_relaxed);
                if (batch_idx >= num_batches) {
                    break;
                }

                const auto& batch = folder_batches[batch_idx];
                for (const auto& file : batch.files) {
                    const std::wstring ext = ensure_extended_path(file.path);
                    DWORD err = 0;
                    if (delete_file_fast(ext, err)) {
                        stats.files_deleted++;
                        stats.bytes_freed += file.size;
                        if (file.is_reparse) {
                            stats.junctions_deleted++;
                        }
                    } else if (MoveFileExW(ext.c_str(), nullptr, MOVEFILE_DELAY_UNTIL_REBOOT)) {
                        stats.files_scheduled_for_reboot++;
                    } else {
                        stats.failed_paths.push_back(file.path);
                    }
                }
            }
        };

        std::vector<std::thread> pool;
        pool.reserve(actual_threads);
        for (size_t t = 0; t < actual_threads; ++t) {
            pool.emplace_back(worker, t);
        }
        for (auto& th : pool) {
            if (th.joinable()) {
                th.join();
            }
        }

        for (const auto& s : thread_stats) {
            report.files_deleted += s.files_deleted;
            report.junctions_deleted += s.junctions_deleted;
            report.acl_resets += s.acl_resets;
            report.bytes_freed += s.bytes_freed;
            report.files_scheduled_for_reboot += s.files_scheduled_for_reboot;
            if (s.files_scheduled_for_reboot > 0) {
                report.reboot_required = true;
            }
            for (const auto& fail : s.failed_paths) {
                report.failed_paths.push_back(fail);
            }
        }
    }

    std::sort(all_dirs.begin(), all_dirs.end(), [](const DirEntry& a, const DirEntry& b) {
        return a.path.size() > b.path.size();
    });

    for (const auto& dir : all_dirs) {
        const std::wstring ext = ensure_extended_path(dir.path);
        DWORD err = 0;
        if (delete_directory_fast(ext, err)) {
            report.directories_deleted++;
            if (dir.is_reparse) {
                report.junctions_deleted++;
            }
            continue;
        }

        if (MoveFileExW(ext.c_str(), nullptr, MOVEFILE_DELAY_UNTIL_REBOOT)) {
            report.directories_scheduled_for_reboot++;
            report.reboot_required = true;
        } else {
            report.failed_paths.push_back(dir.path);
        }
    }

    report.deletion_ms = del_timer.elapsed_ms();

    if (!report.failed_paths.empty()) {
        return Win32Error::from_code(ERROR_CAN_NOT_COMPLETE);
    }
    return Result<void>::success();
}

} // namespace obliterator
