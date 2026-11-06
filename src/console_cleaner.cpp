#include "obliterator/console_cleaner.hpp"

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

bool ConsoleCleaner::matches_target_executable(const std::wstring& filename, const Target& target) {
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

bool ConsoleCleaner::path_references_target(const std::wstring& path, const Target& target) {
    if (path.empty()) {
        return false;
    }

    if (!target.root_path.empty()) {
        // Console keys replace backslashes and colons with underscores
        std::wstring sanitized_root = target.root_path;
        for (wchar_t& c : sanitized_root) {
            if (c == L'\\' || c == L'/') {
                c = L'_';
            }
        }

        if (string_contains_ignore_case(path, sanitized_root)) {
            return true;
        }

        if (PathHelper::contains_path_reference(path, target.root_path)) {
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

ConsoleCleanReport ConsoleCleaner::clean_console_settings(const Target& target, bool dry_run) {
    ConsoleCleanReport report;
    const wchar_t* const kConsolePath = L"Console";

    UniqueHKey hConsole;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, kConsolePath, 0, KEY_READ | KEY_WRITE, hConsole.put()) != ERROR_SUCCESS) {
        if (RegOpenKeyExW(HKEY_CURRENT_USER, kConsolePath, 0, KEY_READ, hConsole.put()) != ERROR_SUCCESS) {
            return report;
        }
    }

    DWORD subkey_count = 0;
    DWORD max_subkey_len = 0;
    if (RegQueryInfoKeyW(hConsole.get(), nullptr, nullptr, nullptr, &subkey_count,
                         &max_subkey_len, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) {
        return report;
    }

    std::vector<wchar_t> name_buf(max_subkey_len + 2, L'\0');
    std::vector<std::wstring> keys_to_delete;

    for (DWORD i = 0; i < subkey_count; ++i) {
        DWORD len = static_cast<DWORD>(name_buf.size());
        if (RegEnumKeyExW(hConsole.get(), i, name_buf.data(), &len, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) {
            continue;
        }

        const std::wstring subkey_name(name_buf.data(), len);
        if (matches_target_executable(subkey_name, target) || path_references_target(subkey_name, target)) {
            keys_to_delete.push_back(subkey_name);
        }
    }

    for (const auto& k : keys_to_delete) {
        if (!dry_run) {
            RegDeleteTreeW(hConsole.get(), k.c_str());
        }
        ++report.console_configs_removed;
        report.details.push_back(L"Console config: " + k);
    }

    return report;
}

} // namespace obliterator
