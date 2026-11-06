#include "obliterator/power_cleaner.hpp"

#include "obliterator/handles.hpp"
#include "obliterator/log.hpp"
#include "obliterator/path.hpp"
#include "obliterator/safety.hpp"

#include <algorithm>
#include <cwctype>
#include <vector>

namespace obliterator {

bool PowerCleaner::matches_target(const std::wstring& name, const Target& target) {
    if (name.empty()) {
        return false;
    }

    const std::wstring lower_name = PathHelper::to_lower_unicode(name);

    if (!target.name.empty() && target.name.length() >= 3) {
        const std::wstring t_name = PathHelper::to_lower_unicode(target.name);
        if (lower_name.find(t_name) != std::wstring::npos) {
            return true;
        }
    }

    if (!target.root_path.empty()) {
        const std::wstring norm_root = SafetyValidator::normalize_path(target.root_path);
        const auto last_slash = norm_root.find_last_of(L"\\/");
        if (last_slash != std::wstring::npos && last_slash + 1 < norm_root.length()) {
            const std::wstring folder = norm_root.substr(last_slash + 1);
            if (folder.length() >= 3) {
                const std::wstring lower_folder = PathHelper::to_lower_unicode(folder);
                if (lower_name.find(lower_folder) != std::wstring::npos) {
                    return true;
                }
            }
        }
    }

    return false;
}

PowerCleanReport PowerCleaner::clean_power_overrides(const Target& target, bool dry_run) {
    PowerCleanReport report;

    const wchar_t* const kPowerKeys[] = {
        L"SYSTEM\\CurrentControlSet\\Control\\Power\\PowerRequestOverrides\\PROCESS",
        L"SYSTEM\\CurrentControlSet\\Control\\Power\\User\\PowerRequestOverrides\\Process"
    };

    for (const auto* kpath : kPowerKeys) {
        UniqueHKey hKey;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, kpath, 0, KEY_READ | KEY_WRITE, hKey.put()) != ERROR_SUCCESS) {
            if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, kpath, 0, KEY_READ, hKey.put()) != ERROR_SUCCESS) {
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
            if (matches_target(val_name, target)) {
                matched_vals.push_back(val_name);
            }
        }

        for (const auto& v : matched_vals) {
            if (!dry_run) {
                RegDeleteValueW(hKey.get(), v.c_str());
            }
            ++report.power_overrides_removed;
            report.details.push_back(L"PowerRequestOverride: " + v);
        }
    }

    return report;
}

} // namespace obliterator
