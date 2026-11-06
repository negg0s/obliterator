#include "obliterator/gpu_cleaner.hpp"

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

bool GpuPreferenceCleaner::path_references_target(const std::wstring& path, const Target& target) {
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

GpuCleanReport GpuPreferenceCleaner::clean_gpu_preferences(const Target& target, bool dry_run) {
    GpuCleanReport report;

    struct KeyTarget {
        HKEY root;
        const wchar_t* path;
    };

    const KeyTarget targets[] = {
        { HKEY_CURRENT_USER, L"Software\\Microsoft\\DirectX\\UserGpuPreferences" },
        { HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\DirectX\\UserGpuPreferences" },
        { HKEY_CURRENT_USER, L"Software\\Microsoft\\Direct3D\\MostRecentApplication" }
    };

    for (const auto& kt : targets) {
        UniqueHKey hKey;
        if (RegOpenKeyExW(kt.root, kt.path, 0, KEY_READ | KEY_WRITE, hKey.put()) != ERROR_SUCCESS) {
            if (RegOpenKeyExW(kt.root, kt.path, 0, KEY_READ, hKey.put()) != ERROR_SUCCESS) {
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

        for (const auto& v : matched_vals) {
            if (!dry_run) {
                RegDeleteValueW(hKey.get(), v.c_str());
            }
            ++report.gpu_preferences_removed;
            report.details.push_back(L"GPU preference: " + v);
        }
    }

    return report;
}

} // namespace obliterator
