#include "obliterator/user_assist_cleaner.hpp"

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

std::wstring UserAssistCleaner::rot13(const std::wstring& input) {
    std::wstring result = input;
    for (wchar_t& c : result) {
        if (c >= L'A' && c <= L'Z') {
            c = static_cast<wchar_t>(L'A' + (c - L'A' + 13) % 26);
        } else if (c >= L'a' && c <= L'z') {
            c = static_cast<wchar_t>(L'a' + (c - L'a' + 13) % 26);
        }
    }
    return result;
}

bool UserAssistCleaner::path_references_target(const std::wstring& decoded_path, const Target& target) {
    if (decoded_path.empty()) {
        return false;
    }

    if (!target.root_path.empty()) {
        if (PathHelper::contains_path_reference(decoded_path, target.root_path)) {
            return true;
        }
        const std::wstring norm_path = SafetyValidator::normalize_path(decoded_path);
        if (PathHelper::is_same_or_subpath(target.root_path, norm_path)) {
            return true;
        }
    }

    if (!target.name.empty() && target.name.length() >= 3) {
        if (string_contains_ignore_case(decoded_path, target.name)) {
            return true;
        }
    }

    return false;
}

UserAssistCleanReport UserAssistCleaner::clean_user_assist(const Target& target, bool dry_run) {
    UserAssistCleanReport report;
    const wchar_t* const kUserAssistPath = L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist";

    UniqueHKey hUserAssist;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, kUserAssistPath, 0, KEY_READ, hUserAssist.put()) != ERROR_SUCCESS) {
        return report;
    }

    DWORD subkey_count = 0;
    DWORD max_subkey_len = 0;
    if (RegQueryInfoKeyW(hUserAssist.get(), nullptr, nullptr, nullptr, &subkey_count,
                         &max_subkey_len, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) {
        return report;
    }

    std::vector<wchar_t> subkey_name_buf(max_subkey_len + 2, L'\0');

    for (DWORD s = 0; s < subkey_count; ++s) {
        DWORD sk_len = static_cast<DWORD>(subkey_name_buf.size());
        if (RegEnumKeyExW(hUserAssist.get(), s, subkey_name_buf.data(), &sk_len,
                          nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) {
            continue;
        }

        const std::wstring guid_name(subkey_name_buf.data(), sk_len);
        const std::wstring count_path = guid_name + L"\\Count";

        UniqueHKey hCount;
        if (RegOpenKeyExW(hUserAssist.get(), count_path.c_str(), 0, KEY_READ | KEY_WRITE, hCount.put()) != ERROR_SUCCESS) {
            if (RegOpenKeyExW(hUserAssist.get(), count_path.c_str(), 0, KEY_READ, hCount.put()) != ERROR_SUCCESS) {
                continue;
            }
        }

        DWORD val_count = 0;
        DWORD max_val_len = 0;
        if (RegQueryInfoKeyW(hCount.get(), nullptr, nullptr, nullptr, nullptr, nullptr,
                             nullptr, &val_count, &max_val_len, nullptr, nullptr, nullptr) != ERROR_SUCCESS) {
            continue;
        }

        std::vector<wchar_t> val_buf(max_val_len + 2, L'\0');
        std::vector<std::wstring> vals_to_delete;

        for (DWORD v = 0; v < val_count; ++v) {
            DWORD v_len = static_cast<DWORD>(val_buf.size());
            if (RegEnumValueW(hCount.get(), v, val_buf.data(), &v_len,
                              nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) {
                continue;
            }

            const std::wstring raw_val(val_buf.data(), v_len);
            const std::wstring decoded = rot13(raw_val);

            if (path_references_target(decoded, target)) {
                vals_to_delete.push_back(raw_val);
            }
        }

        for (const auto& raw_val : vals_to_delete) {
            if (!dry_run) {
                RegDeleteValueW(hCount.get(), raw_val.c_str());
            }
            ++report.entries_removed;
            report.details.push_back(L"UserAssist: " + rot13(raw_val));
        }
    }

    return report;
}

} // namespace obliterator
