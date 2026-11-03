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
#include <optional>
#include <string>
#include <vector>

namespace obliterator {

struct InstalledAppInfo {
    std::wstring name;
    std::wstring install_location;
    std::wstring install_date;
    uint64_t size_bytes{0};
    std::wstring root_path;
    bool is_uwp{false};
    std::wstring uwp_package_full_name;
    std::wstring uwp_package_family_name;
};

class UserInterface {
public:
    static std::vector<InstalledAppInfo> enumerate_installed_apps();
    static std::optional<InstalledAppInfo> select_app_interactive(
        const std::vector<InstalledAppInfo>& apps);
    static bool prompt_confirmation(const std::wstring& app_name);

    static Result<void> install_context_menu();
    static Result<void> uninstall_context_menu();
};

} // namespace obliterator
