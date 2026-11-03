#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include "obliterator/result.hpp"

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

class FileWiper {
public:
    static Result<void> wipe_directory_tree(const std::wstring& target_root, WipeReport& report);
    static Result<void> delete_file_lazy(const std::wstring& path, WipeReport& report);
    static Result<void> delete_directory_lazy(const std::wstring& path, WipeReport& report);

    static Result<void> take_ownership_and_reset_dacl(const std::wstring& path);
    static bool strip_file_attributes(const std::wstring& path);
    static std::wstring ensure_extended_path(const std::wstring& path);
    static bool is_reparse_point(const std::wstring& path);
};

} // namespace obliterator
