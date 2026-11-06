#include "obliterator/notification_cleaner.hpp"

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

bool NotificationCleaner::matches_target_identifier(const std::wstring& identifier, const Target& target) {
    if (identifier.empty()) {
        return false;
    }

    if (!target.name.empty() && target.name.length() >= 3) {
        if (string_contains_ignore_case(identifier, target.name)) {
            return true;
        }
    }

    if (!target.publisher.empty() && target.publisher.length() >= 4) {
        if (string_contains_ignore_case(identifier, target.publisher)) {
            return true;
        }
    }

    if (!target.product_code.empty()) {
        if (string_contains_ignore_case(identifier, target.product_code)) {
            return true;
        }
    }

    if (!target.uwp_package_family_name.empty()) {
        if (string_contains_ignore_case(identifier, target.uwp_package_family_name)) {
            return true;
        }
    }

    if (!target.root_path.empty()) {
        const std::wstring norm_root = SafetyValidator::normalize_path(target.root_path);
        const auto last_slash = norm_root.find_last_of(L"\\/");
        if (last_slash != std::wstring::npos && last_slash + 1 < norm_root.length()) {
            const std::wstring folder = norm_root.substr(last_slash + 1);
            if (folder.length() >= 3 && string_contains_ignore_case(identifier, folder)) {
                return true;
            }
        }
    }

    return false;
}

void NotificationCleaner::clean_notification_settings(const Target& target, bool dry_run, NotificationCleanReport& report) {
    const wchar_t* const kNotifPath = L"Software\\Microsoft\\Windows\\CurrentVersion\\Notifications\\Settings";
    UniqueHKey hNotif;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, kNotifPath, 0, KEY_READ | KEY_WRITE, hNotif.put()) != ERROR_SUCCESS) {
        if (RegOpenKeyExW(HKEY_CURRENT_USER, kNotifPath, 0, KEY_READ, hNotif.put()) != ERROR_SUCCESS) {
            return;
        }
    }

    DWORD subkey_count = 0;
    DWORD max_subkey_len = 0;
    if (RegQueryInfoKeyW(hNotif.get(), nullptr, nullptr, nullptr, &subkey_count,
                         &max_subkey_len, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) {
        return;
    }

    std::vector<wchar_t> name_buf(max_subkey_len + 2, L'\0');
    std::vector<std::wstring> matched_keys;

    for (DWORD i = 0; i < subkey_count; ++i) {
        DWORD len = static_cast<DWORD>(name_buf.size());
        if (RegEnumKeyExW(hNotif.get(), i, name_buf.data(), &len,
                          nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) {
            continue;
        }

        const std::wstring aumid(name_buf.data(), len);
        if (matches_target_identifier(aumid, target)) {
            matched_keys.push_back(aumid);
        }
    }

    for (const auto& k : matched_keys) {
        if (!dry_run) {
            RegDeleteTreeW(hNotif.get(), k.c_str());
        }
        ++report.notification_settings_removed;
        report.details.push_back(L"Notification settings: " + k);
    }
}

void NotificationCleaner::clean_startup_approved(const Target& target, bool dry_run, NotificationCleanReport& report) {
    struct KeyInfo {
        HKEY root;
        const wchar_t* path;
    };

    const KeyInfo targets[] = {
        { HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StartupApproved\\Run" },
        { HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StartupApproved\\Run32" },
        { HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StartupApproved\\StartupFolder" },
        { HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StartupApproved\\Run" },
        { HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StartupApproved\\StartupFolder" }
    };

    for (const auto& k : targets) {
        UniqueHKey hKey;
        if (RegOpenKeyExW(k.root, k.path, 0, KEY_READ | KEY_WRITE, hKey.put()) != ERROR_SUCCESS) {
            if (RegOpenKeyExW(k.root, k.path, 0, KEY_READ, hKey.put()) != ERROR_SUCCESS) {
                continue;
            }
        }

        DWORD val_count = 0;
        DWORD max_val_len = 0;
        if (RegQueryInfoKeyW(hKey.get(), nullptr, nullptr, nullptr, nullptr, nullptr,
                             nullptr, &val_count, &max_val_len, nullptr, nullptr, nullptr) != ERROR_SUCCESS) {
            continue;
        }

        std::vector<wchar_t> name_buf(max_val_len + 2, L'\0');
        std::vector<std::wstring> matched_vals;

        for (DWORD i = 0; i < val_count; ++i) {
            DWORD len = static_cast<DWORD>(name_buf.size());
            if (RegEnumValueW(hKey.get(), i, name_buf.data(), &len,
                              nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) {
                continue;
            }

            const std::wstring val_name(name_buf.data(), len);
            if (matches_target_identifier(val_name, target)) {
                matched_vals.push_back(val_name);
            }
        }

        for (const auto& v : matched_vals) {
            if (!dry_run) {
                RegDeleteValueW(hKey.get(), v.c_str());
            }
            ++report.startup_approved_removed;
            report.details.push_back(L"StartupApproved: " + v);
        }
    }
}

NotificationCleanReport NotificationCleaner::clean_notifications_and_startup(const Target& target, bool dry_run) {
    NotificationCleanReport report;
    clean_notification_settings(target, dry_run, report);
    clean_startup_approved(target, dry_run, report);
    return report;
}

} // namespace obliterator
