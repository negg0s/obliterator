#pragma once

#include "obliterator/result.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace obliterator {

struct PortableAppCandidate {
    std::wstring folder_path;
    std::wstring name;
    std::wstring main_exe_name;
    std::wstring main_exe_path;
    uint64_t size_bytes{0};
    size_t file_count{0};
    std::wstring last_modified;
};

class PortableScanner {
public:
    static std::vector<PortableAppCandidate> scan(const std::wstring& root_folder);
    static void print_report(const std::vector<PortableAppCandidate>& candidates, bool json_mode = false);
};

} // namespace obliterator
