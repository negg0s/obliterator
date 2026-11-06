#include "obliterator/ifeo_cleaner.hpp"

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

bool IfeoCleaner::matches_target_executable(const std::wstring& filename, const Target& target) {
    if (filename.empty()) {
        return false;
    }

    const std::wstring lower_fn = PathHelper::to_lower_unicode(filename);

    if (!target.name.empty() && target.name.length() >= 3) {
        const std::wstring lower_name = PathHelper::to_lower_unicode(target.name);
        if (lower_fn.find(lower_name) != std::wstring::npos) {
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
                if (lower_fn.find(lower_folder) != std::wstring::npos) {
                    return true;
                }
            }
        }
    }

    return false;
}

bool IfeoCleaner::path_references_target(const std::wstring& path, const Target& target) {
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

IfeoCleanReport IfeoCleaner::clean_ifeo_entries(const Target& target, bool dry_run) {
    IfeoCleanReport report;
    const wchar_t* const kIfeoPath = L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options";

    UniqueHKey hIfeo;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, kIfeoPath, 0, KEY_READ | KEY_WRITE, hIfeo.put()) != ERROR_SUCCESS) {
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, kIfeoPath, 0, KEY_READ, hIfeo.put()) != ERROR_SUCCESS) {
            return report;
        }
    }

    DWORD subkey_count = 0;
    DWORD max_subkey_len = 0;
    if (RegQueryInfoKeyW(hIfeo.get(), nullptr, nullptr, nullptr, &subkey_count,
                         &max_subkey_len, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) {
        return report;
    }

    std::vector<wchar_t> name_buf(max_subkey_len + 2, L'\0');
    std::vector<std::wstring> keys_to_delete;
    std::vector<std::wstring> debuggers_to_delete;

    for (DWORD i = 0; i < subkey_count; ++i) {
        DWORD len = static_cast<DWORD>(name_buf.size());
        if (RegEnumKeyExW(hIfeo.get(), i, name_buf.data(), &len,
                          nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) {
            continue;
        }

        const std::wstring subkey_name(name_buf.data(), len);

        // Check if subkey matches target executable
        if (matches_target_executable(subkey_name, target)) {
            keys_to_delete.push_back(subkey_name);
            continue;
        }

        // Check if subkey has a Debugger value pointing to target
        UniqueHKey hSub;
        if (RegOpenKeyExW(hIfeo.get(), subkey_name.c_str(), 0, KEY_READ, hSub.put()) == ERROR_SUCCESS) {
            const std::wstring dbg_cmd = read_reg_string_value(hSub.get(), nullptr, L"Debugger");
            if (!dbg_cmd.empty() && path_references_target(dbg_cmd, target)) {
                debuggers_to_delete.push_back(subkey_name);
            }
        }
    }

    for (const auto& k : keys_to_delete) {
        if (!dry_run) {
            RegDeleteTreeW(hIfeo.get(), k.c_str());
        }
        ++report.target_keys_removed;
        report.details.push_back(L"IFEO target key: " + k);
    }

    for (const auto& sub_name : debuggers_to_delete) {
        if (!dry_run) {
            UniqueHKey hSub;
            if (RegOpenKeyExW(hIfeo.get(), sub_name.c_str(), 0, KEY_WRITE, hSub.put()) == ERROR_SUCCESS) {
                RegDeleteValueW(hSub.get(), L"Debugger");
            }
        }
        ++report.debugger_hooks_removed;
        report.details.push_back(L"IFEO debugger hook removed from: " + sub_name);
    }

    return report;
}

} // namespace obliterator
