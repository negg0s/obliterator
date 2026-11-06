#pragma once

#include "obliterator/target.hpp"

#include <string>
#include <string_view>
#include <vector>

namespace obliterator {

struct OemDriverInfo {
    std::wstring inf_filename;
    std::wstring full_path;
    std::wstring provider;
    std::wstring catalog_file;
    std::wstring driver_version;
    std::vector<std::wstring> service_binaries;
    std::wstring matched_reason;
};

class DriverCleaner {
public:
    static bool is_protected_vendor(std::wstring_view provider);

    static std::vector<OemDriverInfo> discover_oem_drivers(
        const Target& target,
        const std::vector<std::wstring>& known_service_binaries
    );

    static size_t uninstall_oem_driver(const OemDriverInfo& driver, bool dry_run);
    static size_t uninstall_oem_drivers(const std::vector<OemDriverInfo>& drivers, bool dry_run);
};

} // namespace obliterator
