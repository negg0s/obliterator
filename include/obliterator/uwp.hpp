#pragma once

#include "obliterator/result.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace obliterator {

struct UwpPackageInfo {
    std::wstring name;
    std::wstring display_name;
    std::wstring full_name;
    std::wstring family_name;
    std::wstring install_location;
    std::wstring publisher;
    uint64_t size_bytes{0};
    std::wstring install_date;
};

class UwpManager {
public:
    static std::vector<UwpPackageInfo> enumerate_packages();
    static Result<void> remove_package(const std::wstring& full_name);
    static std::vector<std::wstring> get_remnant_folders(const std::wstring& family_name);
    static std::vector<std::wstring> get_remnant_registry_subkeys(const std::wstring& family_name);
};

} // namespace obliterator
