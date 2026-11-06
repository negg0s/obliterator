#include "obliterator/comdlg_cleaner.hpp"

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

bool ComDlgCleaner::matches_target_executable(const std::wstring& filename, const Target& target) {
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

bool ComDlgCleaner::path_references_target(const std::wstring& path, const Target& target) {
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

ComDlgCleanReport ComDlgCleaner::clean_comdlg_mru(const Target& target, bool dry_run) {
    ComDlgCleanReport report;

    // 1. LastVisitedPidlMRU
    const wchar_t* const kLastVisitedKey =
        L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\LastVisitedPidlMRU";

    UniqueHKey hLastVisited;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, kLastVisitedKey, 0, KEY_READ | KEY_WRITE, hLastVisited.put()) == ERROR_SUCCESS ||
        RegOpenKeyExW(HKEY_CURRENT_USER, kLastVisitedKey, 0, KEY_READ, hLastVisited.put()) == ERROR_SUCCESS) {

        DWORD val_count = 0;
        DWORD max_val_len = 0;
        DWORD max_data_len = 0;
        if (RegQueryInfoKeyW(hLastVisited.get(), nullptr, nullptr, nullptr, nullptr, nullptr,
                             nullptr, &val_count, &max_val_len, &max_data_len, nullptr, nullptr) == ERROR_SUCCESS) {
            std::vector<wchar_t> name_buf(max_val_len + 2, L'\0');
            std::vector<BYTE> data_buf(max_data_len + 4, 0);
            std::vector<std::wstring> vals_to_delete;

            for (DWORD i = 0; i < val_count; ++i) {
                DWORD len = static_cast<DWORD>(name_buf.size());
                DWORD data_len = static_cast<DWORD>(data_buf.size());
                DWORD type = 0;
                if (RegEnumValueW(hLastVisited.get(), i, name_buf.data(), &len, nullptr, &type,
                                  data_buf.data(), &data_len) != ERROR_SUCCESS) {
                    continue;
                }

                const std::wstring val_name(name_buf.data(), len);
                if (val_name == L"MRUListEx") {
                    continue;
                }

                // The first field in LastVisitedPidlMRU binary data is a null-terminated wchar_t executable name
                if (data_len >= sizeof(wchar_t)) {
                    const auto* wchar_data = reinterpret_cast<const wchar_t*>(data_buf.data());
                    const size_t max_chars = data_len / sizeof(wchar_t);
                    size_t null_pos = 0;
                    while (null_pos < max_chars && wchar_data[null_pos] != L'\0') {
                        ++null_pos;
                    }

                    if (null_pos > 0 && null_pos < max_chars) {
                        const std::wstring exe_name(wchar_data, null_pos);
                        if (matches_target_executable(exe_name, target)) {
                            vals_to_delete.push_back(val_name);
                        }
                    }
                }
            }

            for (const auto& v : vals_to_delete) {
                if (!dry_run) {
                    RegDeleteValueW(hLastVisited.get(), v.c_str());
                }
                ++report.last_visited_removed;
                report.details.push_back(L"ComDlg LastVisited: " + v);
            }
        }
    }

    // 2. CIDSizeMRU
    const wchar_t* const kCidSizeKey =
        L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\CIDSizeMRU";

    UniqueHKey hCidSize;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, kCidSizeKey, 0, KEY_READ | KEY_WRITE, hCidSize.put()) == ERROR_SUCCESS ||
        RegOpenKeyExW(HKEY_CURRENT_USER, kCidSizeKey, 0, KEY_READ, hCidSize.put()) == ERROR_SUCCESS) {

        DWORD val_count = 0;
        DWORD max_val_len = 0;
        if (RegQueryInfoKeyW(hCidSize.get(), nullptr, nullptr, nullptr, nullptr, nullptr,
                             nullptr, &val_count, &max_val_len, nullptr, nullptr, nullptr) == ERROR_SUCCESS) {
            std::vector<wchar_t> name_buf(max_val_len + 2, L'\0');
            std::vector<std::wstring> vals_to_delete;

            for (DWORD i = 0; i < val_count; ++i) {
                DWORD len = static_cast<DWORD>(name_buf.size());
                if (RegEnumValueW(hCidSize.get(), i, name_buf.data(), &len, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) {
                    continue;
                }

                const std::wstring val_name(name_buf.data(), len);
                if (matches_target_executable(val_name, target) || path_references_target(val_name, target)) {
                    vals_to_delete.push_back(val_name);
                }
            }

            for (const auto& v : vals_to_delete) {
                if (!dry_run) {
                    RegDeleteValueW(hCidSize.get(), v.c_str());
                }
                ++report.cid_size_removed;
                report.details.push_back(L"ComDlg CIDSize: " + v);
            }
        }
    }

    return report;
}

} // namespace obliterator
