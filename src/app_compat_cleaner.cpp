#include "obliterator/app_compat_cleaner.hpp"

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

bool AppCompatCleaner::path_references_target(const std::wstring& path, const Target& target) {
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

void AppCompatCleaner::clean_layers_values(const Target& target, bool dry_run, AppCompatCleanReport& report) {
    struct KeyInfo {
        HKEY root;
        const wchar_t* path;
    };

    const KeyInfo targets[] = {
        { HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\Layers" },
        { HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\Layers" }
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
            if (path_references_target(val_name, target)) {
                matched_vals.push_back(val_name);
            }
        }

        for (const auto& val : matched_vals) {
            if (!dry_run) {
                RegDeleteValueW(hKey.get(), val.c_str());
            }
            ++report.layers_values_removed;
            report.details.push_back(L"AppCompat Layers: " + val);
        }
    }
}

void AppCompatCleaner::clean_store_values(const Target& target, bool dry_run, AppCompatCleanReport& report) {
    struct KeyInfo {
        HKEY root;
        const wchar_t* path;
    };

    const KeyInfo targets[] = {
        { HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\Compatibility Assistant\\Store" },
        { HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\Compatibility Assistant\\Store" }
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
            if (path_references_target(val_name, target)) {
                matched_vals.push_back(val_name);
            }
        }

        for (const auto& val : matched_vals) {
            if (!dry_run) {
                RegDeleteValueW(hKey.get(), val.c_str());
            }
            ++report.store_values_removed;
            report.details.push_back(L"AppCompat Store: " + val);
        }
    }
}

void AppCompatCleaner::clean_custom_keys(const Target& target, bool dry_run, AppCompatCleanReport& report) {
    const wchar_t* const kCustomPath = L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\Custom";
    UniqueHKey hCustom;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, kCustomPath, 0, KEY_READ | KEY_WRITE, hCustom.put()) != ERROR_SUCCESS) {
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, kCustomPath, 0, KEY_READ, hCustom.put()) != ERROR_SUCCESS) {
            return;
        }
    }

    DWORD subkey_count = 0;
    DWORD max_subkey_len = 0;
    if (RegQueryInfoKeyW(hCustom.get(), nullptr, nullptr, nullptr, &subkey_count,
                         &max_subkey_len, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) {
        return;
    }

    std::vector<wchar_t> name_buf(max_subkey_len + 2, L'\0');
    std::vector<std::wstring> matched_keys;

    for (DWORD i = 0; i < subkey_count; ++i) {
        DWORD len = static_cast<DWORD>(name_buf.size());
        if (RegEnumKeyExW(hCustom.get(), i, name_buf.data(), &len,
                          nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) {
            continue;
        }

        const std::wstring subkey_name(name_buf.data(), len);
        if (!target.name.empty() && string_contains_ignore_case(subkey_name, target.name)) {
            matched_keys.push_back(subkey_name);
        }
    }

    for (const auto& k : matched_keys) {
        if (!dry_run) {
            RegDeleteTreeW(hCustom.get(), k.c_str());
        }
        ++report.custom_keys_removed;
        report.details.push_back(L"AppCompat Custom: " + k);
    }
}

AppCompatCleanReport AppCompatCleaner::clean_app_compat(const Target& target, bool dry_run) {
    AppCompatCleanReport report;
    clean_layers_values(target, dry_run, report);
    clean_store_values(target, dry_run, report);
    clean_custom_keys(target, dry_run, report);
    return report;
}

} // namespace obliterator
