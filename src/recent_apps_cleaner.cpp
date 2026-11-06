#include "obliterator/recent_apps_cleaner.hpp"

#include "obliterator/handles.hpp"
#include "obliterator/log.hpp"
#include "obliterator/path.hpp"
#include "obliterator/safety.hpp"

#include <algorithm>
#include <cwctype>
#include <vector>

namespace obliterator {

static bool string_contains_ignore_case(std::wstring_view text, std::wstring_view needle) {
    if (needle.empty() || text.empty()) {
        return false;
    }
    const std::wstring t_lower = PathHelper::to_lower_unicode(text);
    const std::wstring n_lower = PathHelper::to_lower_unicode(needle);
    return t_lower.find(n_lower) != std::wstring::npos;
}

static std::wstring read_reg_string_value(HKEY hKey, const wchar_t* subkey_name, const wchar_t* value_name) {
    std::wstring result;
    UniqueHKey sub;
    HKEY target_hkey = hKey;
    if (subkey_name && *subkey_name) {
        if (RegOpenKeyExW(hKey, subkey_name, 0, KEY_READ, sub.put()) != ERROR_SUCCESS) {
            return {};
        }
        target_hkey = sub.get();
    }

    DWORD bytes = 0;
    DWORD type = 0;
    if (RegQueryValueExW(target_hkey, value_name, nullptr, &type, nullptr, &bytes) == ERROR_SUCCESS && bytes > 0) {
        std::vector<wchar_t> buf((bytes / sizeof(wchar_t)) + 2, L'\0');
        if (RegQueryValueExW(target_hkey, value_name, nullptr, &type,
                             reinterpret_cast<LPBYTE>(buf.data()), &bytes) == ERROR_SUCCESS) {
            result = buf.data();
        }
    }
    return result;
}

bool RecentAppsCleaner::path_references_target(const std::wstring& path, const Target& target) {
    if (path.empty()) {
        return false;
    }

    if (!target.root_path.empty()) {
        if (PathHelper::contains_path_reference(path, target.root_path)) {
            return true;
        }
        const std::wstring norm_path = SafetyValidator::normalize_path(path);
        if (PathHelper::is_same_or_subpath(target.root_path, norm_path)) {
            return true;
        }
    }

    if (!target.name.empty() && target.name.length() >= 3) {
        if (string_contains_ignore_case(path, target.name)) {
            return true;
        }
    }

    return false;
}

RecentAppsCleanReport RecentAppsCleaner::clean_recent_apps(const Target& target, bool dry_run) {
    RecentAppsCleanReport report;
    const wchar_t* const kRecentAppsPath = L"Software\\Microsoft\\Windows\\CurrentVersion\\Search\\RecentApps";

    UniqueHKey hRecent;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, kRecentAppsPath, 0, KEY_READ | KEY_WRITE, hRecent.put()) != ERROR_SUCCESS) {
        if (RegOpenKeyExW(HKEY_CURRENT_USER, kRecentAppsPath, 0, KEY_READ, hRecent.put()) != ERROR_SUCCESS) {
            return report;
        }
    }

    DWORD subkey_count = 0;
    DWORD max_subkey_len = 0;
    if (RegQueryInfoKeyW(hRecent.get(), nullptr, nullptr, nullptr, &subkey_count,
                         &max_subkey_len, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) {
        return report;
    }

    std::vector<wchar_t> name_buf(max_subkey_len + 2, L'\0');
    std::vector<std::wstring> keys_to_delete;

    for (DWORD i = 0; i < subkey_count; ++i) {
        DWORD len = static_cast<DWORD>(name_buf.size());
        if (RegEnumKeyExW(hRecent.get(), i, name_buf.data(), &len,
                          nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) {
            continue;
        }

        const std::wstring subkey_name(name_buf.data(), len);
        UniqueHKey hSub;
        if (RegOpenKeyExW(hRecent.get(), subkey_name.c_str(), 0, KEY_READ, hSub.put()) == ERROR_SUCCESS) {
            const std::wstring app_path = read_reg_string_value(hSub.get(), nullptr, L"AppPath");
            if (!app_path.empty() && path_references_target(app_path, target)) {
                keys_to_delete.push_back(subkey_name);
            }
        }
    }

    for (const auto& k : keys_to_delete) {
        if (!dry_run) {
            RegDeleteTreeW(hRecent.get(), k.c_str());
        }
        ++report.recent_apps_removed;
        report.details.push_back(L"RecentApps entry: " + k);
    }

    return report;
}

} // namespace obliterator
