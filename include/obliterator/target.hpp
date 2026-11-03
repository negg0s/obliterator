#pragma once

#include "obliterator/handles.hpp"
#include "obliterator/result.hpp"

#include <string>
#include <vector>

namespace obliterator {

struct TargetRegistryEntry {
    HKEY root_key;
    std::wstring subkey_path;
    REGSAM sam_view;
    std::wstring display_name;
};

struct Target {
    std::wstring name;
    std::wstring publisher;
    std::wstring root_path;
    std::vector<TargetRegistryEntry> registry_entries;
    bool is_uwp{false};
    std::wstring uwp_package_full_name;
    std::wstring uwp_package_family_name;
    std::wstring uninstall_string;
    std::wstring quiet_uninstall_string;
};

class TargetResolver {
public:
    static Result<Target> resolve(const std::wstring& input);

    static std::wstring deduce_install_folder(const std::wstring& install_loc,
                                             const std::wstring& display_icon,
                                             const std::wstring& uninstall_str);
};

} // namespace obliterator
