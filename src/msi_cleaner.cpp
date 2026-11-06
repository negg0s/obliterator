#include "obliterator/msi_cleaner.hpp"
#include "obliterator/handles.hpp"
#include "obliterator/log.hpp"
#include "obliterator/path.hpp"
#include "obliterator/safety.hpp"

#include <algorithm>
#include <cwctype>
#include <filesystem>
#include <vector>

namespace obliterator {

namespace fs = std::filesystem;

static bool string_equals_ignore_case(std::wstring_view a, std::wstring_view b) {
    if (a.size() != b.size()) {
        return false;
    }
    for (size_t i = 0; i < a.size(); ++i) {
        if (std::towlower(a[i]) != std::towlower(b[i])) {
            return false;
        }
    }
    return true;
}

static bool string_contains_ignore_case(std::wstring_view text, std::wstring_view needle) {
    if (needle.empty() || text.empty()) {
        return false;
    }
    const std::wstring t_lower = PathHelper::to_lower_unicode(text);
    const std::wstring n_lower = PathHelper::to_lower_unicode(needle);
    return t_lower.find(n_lower) != std::wstring::npos;
}

static std::wstring query_reg_string(HKEY hKey, const wchar_t* value_name) {
    std::wstring result;
    DWORD bytes = 0;
    if (RegQueryValueExW(hKey, value_name, nullptr, nullptr, nullptr, &bytes) == ERROR_SUCCESS && bytes > 0) {
        std::vector<wchar_t> buf((bytes / sizeof(wchar_t)) + 2, L'\0');
        if (RegQueryValueExW(hKey, value_name, nullptr, nullptr,
                             reinterpret_cast<LPBYTE>(buf.data()), &bytes) == ERROR_SUCCESS) {
            result = buf.data();
        }
    }
    return result;
}

std::wstring MsiCacheCleaner::pack_guid(std::wstring_view guid_str) {
    std::wstring hex;
    hex.reserve(32);
    for (wchar_t c : guid_str) {
        if ((c >= L'0' && c <= L'9') || (c >= L'A' && c <= L'F') || (c >= L'a' && c <= L'f')) {
            hex.push_back(static_cast<wchar_t>(std::towupper(c)));
        }
    }

    if (hex.size() != 32) {
        return {};
    }

    std::wstring packed;
    packed.resize(32);

    // Segment 1: chars 0..7 reversed
    for (int i = 0; i < 8; ++i) {
        packed[i] = hex[7 - i];
    }
    // Segment 2: chars 8..11 reversed
    for (int i = 0; i < 4; ++i) {
        packed[8 + i] = hex[11 - i];
    }
    // Segment 3: chars 12..15 reversed
    for (int i = 0; i < 4; ++i) {
        packed[12 + i] = hex[15 - i];
    }
    // Segment 4: byte pairs swapped
    packed[16] = hex[17];
    packed[17] = hex[16];
    packed[18] = hex[19];
    packed[19] = hex[18];

    // Segment 5: byte pairs swapped for chars 20..31
    for (int i = 20; i < 32; i += 2) {
        packed[i] = hex[i + 1];
        packed[i + 1] = hex[i];
    }

    return packed;
}

std::wstring MsiCacheCleaner::unpack_guid(std::wstring_view packed_str) {
    if (packed_str.size() != 32) {
        return {};
    }

    std::wstring hex;
    hex.resize(32);

    // Segment 1: chars 0..7 reversed
    for (int i = 0; i < 8; ++i) {
        hex[i] = static_cast<wchar_t>(std::towupper(packed_str[7 - i]));
    }
    // Segment 2: chars 8..11 reversed
    for (int i = 0; i < 4; ++i) {
        hex[8 + i] = static_cast<wchar_t>(std::towupper(packed_str[11 - i]));
    }
    // Segment 3: chars 12..15 reversed
    for (int i = 0; i < 4; ++i) {
        hex[12 + i] = static_cast<wchar_t>(std::towupper(packed_str[15 - i]));
    }
    // Segment 4: byte pairs swapped
    hex[16] = static_cast<wchar_t>(std::towupper(packed_str[17]));
    hex[17] = static_cast<wchar_t>(std::towupper(packed_str[16]));
    hex[18] = static_cast<wchar_t>(std::towupper(packed_str[19]));
    hex[19] = static_cast<wchar_t>(std::towupper(packed_str[18]));

    // Segment 5: byte pairs swapped
    for (int i = 20; i < 32; i += 2) {
        hex[i] = static_cast<wchar_t>(std::towupper(packed_str[i + 1]));
        hex[i + 1] = static_cast<wchar_t>(std::towupper(packed_str[i]));
    }

    // Format as {XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}
    std::wstring guid = L"{";
    guid.append(hex.substr(0, 8));
    guid.push_back(L'-');
    guid.append(hex.substr(8, 4));
    guid.push_back(L'-');
    guid.append(hex.substr(12, 4));
    guid.push_back(L'-');
    guid.append(hex.substr(16, 4));
    guid.push_back(L'-');
    guid.append(hex.substr(20, 12));
    guid.push_back(L'}');

    return guid;
}

std::vector<MsiPackageInfo> MsiCacheCleaner::discover_packages(const Target& target) {
    std::vector<MsiPackageInfo> matches;

    const std::wstring base_path = L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Installer\\UserData\\S-1-5-18\\Products";
    UniqueHKey hProducts;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, base_path.c_str(), 0, KEY_READ, hProducts.put()) != ERROR_SUCCESS) {
        return matches;
    }

    DWORD subkey_count = 0;
    DWORD max_subkey_len = 0;
    if (RegQueryInfoKeyW(hProducts.get(), nullptr, nullptr, nullptr, &subkey_count,
                         &max_subkey_len, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) {
        return matches;
    }

    std::vector<wchar_t> key_name_buf(max_subkey_len + 2, L'\0');

    for (DWORD idx = 0; idx < subkey_count; ++idx) {
        DWORD name_len = static_cast<DWORD>(key_name_buf.size());
        if (RegEnumKeyExW(hProducts.get(), idx, key_name_buf.data(), &name_len,
                          nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) {
            continue;
        }

        const std::wstring packed_guid(key_name_buf.data(), name_len);
        const std::wstring props_subkey = packed_guid + L"\\InstallProperties";

        UniqueHKey hProps;
        if (RegOpenKeyExW(hProducts.get(), props_subkey.c_str(), 0, KEY_READ, hProps.put()) != ERROR_SUCCESS) {
            continue;
        }

        const std::wstring display_name = query_reg_string(hProps.get(), L"DisplayName");
        const std::wstring install_location = query_reg_string(hProps.get(), L"InstallLocation");
        const std::wstring local_package = query_reg_string(hProps.get(), L"LocalPackage");
        const std::wstring uninstall_string = query_reg_string(hProps.get(), L"UninstallString");
        const std::wstring standard_guid = unpack_guid(packed_guid);

        bool matched = false;
        std::wstring reason;

        if (!target.product_code.empty()) {
            if (string_equals_ignore_case(target.product_code, standard_guid) ||
                string_equals_ignore_case(target.product_code, packed_guid)) {
                matched = true;
                reason = L"product GUID exact match";
            }
        }

        if (!matched && !target.root_path.empty() && !install_location.empty()) {
            const std::wstring norm_loc = SafetyValidator::normalize_path(install_location);
            if (PathHelper::is_same_or_subpath(target.root_path, norm_loc) ||
                PathHelper::is_same_or_subpath(norm_loc, target.root_path)) {
                matched = true;
                reason = L"installation location matches target root path";
            }
        }

        if (!matched && !target.uninstall_string.empty()) {
            if (string_contains_ignore_case(target.uninstall_string, standard_guid) ||
                string_contains_ignore_case(target.uninstall_string, packed_guid)) {
                matched = true;
                reason = L"target uninstall string contains product GUID";
            }
        }

        if (!matched && !target.name.empty() && !display_name.empty()) {
            if (string_equals_ignore_case(display_name, target.name)) {
                matched = true;
                reason = L"product display name exact match";
            } else if (string_contains_ignore_case(display_name, target.name)) {
                matched = true;
                reason = L"product display name contains target name";
            }
        }

        if (matched) {
            MsiPackageInfo info;
            info.packed_guid = packed_guid;
            info.standard_guid = standard_guid;
            info.display_name = display_name;
            info.local_package = local_package;
            info.install_location = install_location;
            info.match_reason = reason;

            if (!local_package.empty()) {
                std::error_code ec;
                const fs::path pkg_path(local_package);
                if (fs::exists(pkg_path, ec)) {
                    info.package_size = fs::file_size(pkg_path, ec);
                }
            }

            matches.push_back(std::move(info));
        }
    }

    return matches;
}

size_t MsiCacheCleaner::purge_package(const MsiPackageInfo& pkg, bool dry_run) {
    if (dry_run) {
        Logger::info(L"[DRY-RUN] Would purge cached MSI package: " + pkg.local_package +
                     L" (" + pkg.display_name + L", GUID: " + pkg.standard_guid + L")");
        return 1;
    }

    size_t removed = 0;

    // 1. Delete physical cached .msi package file in C:\Windows\Installer
    if (!pkg.local_package.empty()) {
        std::error_code ec;
        const fs::path pkg_path(pkg.local_package);
        if (fs::exists(pkg_path, ec)) {
            SetFileAttributesW(pkg.local_package.c_str(), FILE_ATTRIBUTE_NORMAL);
            if (DeleteFileW(pkg.local_package.c_str())) {
                Logger::info(L"Deleted cached MSI package: " + pkg.local_package +
                             L" (" + std::to_wstring(pkg.package_size / 1024) + L" KB freed)");
                removed++;
            } else {
                Logger::warn(L"Failed to delete cached MSI package: " + pkg.local_package);
            }
        }
    }

    // 2. Remove HKLM UserData Products entry
    if (!pkg.packed_guid.empty()) {
        const std::wstring user_data_sub = L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Installer\\UserData\\S-1-5-18\\Products\\" + pkg.packed_guid;
        RegDeleteTreeW(HKEY_LOCAL_MACHINE, user_data_sub.c_str());

        // 3. Remove HKCR Installer Products & Features entries
        const std::wstring hkcr_prod = L"Installer\\Products\\" + pkg.packed_guid;
        RegDeleteTreeW(HKEY_CLASSES_ROOT, hkcr_prod.c_str());

        const std::wstring hkcr_feat = L"Installer\\Features\\" + pkg.packed_guid;
        RegDeleteTreeW(HKEY_CLASSES_ROOT, hkcr_feat.c_str());
    }

    // 4. Remove standard Uninstall key if registered
    if (!pkg.standard_guid.empty()) {
        const std::wstring uninst_path = L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\" + pkg.standard_guid;
        RegDeleteTreeW(HKEY_LOCAL_MACHINE, uninst_path.c_str());

        UniqueHKey hWow;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
                          0, KEY_WRITE | KEY_WOW64_32KEY, hWow.put()) == ERROR_SUCCESS) {
            RegDeleteTreeW(hWow.get(), pkg.standard_guid.c_str());
        }
    }

    return removed > 0 ? removed : 1;
}

size_t MsiCacheCleaner::purge_packages(const std::vector<MsiPackageInfo>& pkgs, bool dry_run) {
    size_t total = 0;
    for (const auto& pkg : pkgs) {
        total += purge_package(pkg, dry_run);
    }
    return total;
}

} // namespace obliterator
