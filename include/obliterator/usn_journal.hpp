#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <winioctl.h>

#include "obliterator/result.hpp"

#include <string>
#include <vector>

namespace obliterator {

struct UsnMatchedFolder {
    std::wstring folder_name;
    uint64_t file_reference_number{0};
    uint64_t parent_reference_number{0};
    std::wstring full_path;
};

class UsnJournalScanner {
public:
    // Determines if USN change journal queries are supported on the target volume
    static bool is_usn_supported(const std::wstring& drive_root);

    // Queries USN journal records on a given volume for directory names matching target
    static Result<std::vector<UsnMatchedFolder>> scan_volume_for_directories(
        const std::wstring& drive_root,
        std::wstring_view target_name,
        std::wstring_view publisher_name = {}
    );
};

} // namespace obliterator
