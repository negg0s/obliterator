#pragma once

#include "obliterator/target.hpp"

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace obliterator {

struct MsiPackageInfo {
    std::wstring packed_guid;
    std::wstring standard_guid;
    std::wstring display_name;
    std::wstring local_package;
    uint64_t package_size = 0;
    std::wstring install_location;
    std::wstring match_reason;
};

class MsiCacheCleaner {
public:
    static std::wstring pack_guid(std::wstring_view guid_str);
    static std::wstring unpack_guid(std::wstring_view packed_str);

    static std::vector<MsiPackageInfo> discover_packages(const Target& target);

    static size_t purge_package(const MsiPackageInfo& pkg, bool dry_run);
    static size_t purge_packages(const std::vector<MsiPackageInfo>& pkgs, bool dry_run);
};

} // namespace obliterator
