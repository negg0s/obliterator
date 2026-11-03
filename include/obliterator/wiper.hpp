#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include "obliterator/result.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace obliterator {

struct WipeReport {
    size_t files_deleted{0};
    size_t directories_deleted{0};
    size_t junctions_deleted{0};
    size_t acl_resets{0};
    std::vector<std::wstring> failed_paths;
};

struct PhysicalWipeReport {
    size_t files_deleted{0};
    size_t directories_deleted{0};
    size_t junctions_deleted{0};
    size_t files_scheduled_for_reboot{0};
    size_t directories_scheduled_for_reboot{0};
    size_t acl_resets{0};
    uint64_t bytes_freed{0};
    bool reboot_required{false};
    std::vector<std::wstring> failed_paths;
    double enumeration_ms{0.0};
    double deletion_ms{0.0};
};

class FileWiper {
public:
    static Result<void> wipe_physical_tree(const std::wstring& target_root,
                                           PhysicalWipeReport& report,
                                           bool compute_sizes = true,
                                           size_t thread_count = 0);
    static Result<void> wipe_directory_tree(const std::wstring& target_root,
                                            WipeReport& report,
                                            bool compute_sizes = true);

    static Result<void> delete_file_lazy(const std::wstring& path, WipeReport& report);
    static Result<void> delete_directory_lazy(const std::wstring& path, WipeReport& report);

    static Result<void> take_ownership_and_reset_dacl(const std::wstring& path);
    static bool strip_file_attributes(const std::wstring& path);
    static std::wstring ensure_extended_path(const std::wstring& path);
    static bool is_reparse_point(const std::wstring& path);
    static std::wstring format_bytes(uint64_t bytes);
};

} // namespace obliterator
