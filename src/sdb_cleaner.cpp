#include "obliterator/sdb_cleaner.hpp"

#include "obliterator/handles.hpp"
#include "obliterator/path.hpp"
#include "obliterator/safety.hpp"

#include <algorithm>
#include <cwctype>
#include <filesystem>
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

bool SdbCleaner::matches_target(const std::wstring& name, const Target& target) {
    if (name.empty()) {
        return false;
    }

    if (!target.name.empty() && target.name.length() >= 3) {
        if (string_contains_ignore_case(name, target.name)) {
            return true;
        }
        if (name.length() >= 4 && string_contains_ignore_case(target.name, name)) {
            return true;
        }
        if (target.name.length() > 6) {
            const std::wstring lower_t = PathHelper::to_lower_unicode(target.name);
            if (lower_t.rfind(L"app") == lower_t.length() - 3) {
                const std::wstring stem = target.name.substr(0, target.name.length() - 3);
                if (string_contains_ignore_case(name, stem)) {
                    return true;
                }
            }
        }
    }

    if (!target.root_path.empty()) {
        const std::wstring norm_root = SafetyValidator::normalize_path(target.root_path);
        const auto last_slash = norm_root.find_last_of(L"\\/");
        if (last_slash != std::wstring::npos && last_slash + 1 < norm_root.length()) {
            const std::wstring folder = norm_root.substr(last_slash + 1);
            if (folder.length() >= 3 && string_contains_ignore_case(name, folder)) {
                return true;
            }
        }
    }

    return false;
}

bool SdbCleaner::path_references_target(const std::wstring& path, const Target& target) {
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

SdbCleanReport SdbCleaner::clean_sdb_shims(const Target& target, bool dry_run) {
    SdbCleanReport report;
    const HKEY kRoots[] = { HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER };

    const wchar_t* const kInstalledSdb =
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\InstalledSDB";
    const wchar_t* const kCustomSdb =
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\Custom";

    std::vector<std::wstring> deleted_guids;

    // 1. InstalledSDB
    for (HKEY root : kRoots) {
        const REGSAM access = dry_run ? KEY_READ : (KEY_READ | KEY_WRITE);
        UniqueHKey hInstalled;
        if (RegOpenKeyExW(root, kInstalledSdb, 0, access, hInstalled.put()) != ERROR_SUCCESS) {
            continue;
        }

        DWORD subkey_count = 0;
        DWORD max_subkey_len = 0;
        if (RegQueryInfoKeyW(hInstalled.get(), nullptr, nullptr, nullptr, &subkey_count,
                             &max_subkey_len, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) {
            continue;
        }

        std::vector<wchar_t> name_buf(max_subkey_len + 2, L'\0');
        struct SdbMatch {
            std::wstring guid;
            std::wstring db_path;
            std::wstring desc;
        };
        std::vector<SdbMatch> to_delete;

        for (DWORD i = 0; i < subkey_count; ++i) {
            DWORD len = static_cast<DWORD>(name_buf.size());
            if (RegEnumKeyExW(hInstalled.get(), i, name_buf.data(), &len, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) {
                continue;
            }

            const std::wstring guid(name_buf.data(), len);
            UniqueHKey hSub;
            if (RegOpenKeyExW(hInstalled.get(), guid.c_str(), 0, KEY_READ, hSub.put()) != ERROR_SUCCESS) {
                continue;
            }

            wchar_t path_buf[MAX_PATH] = { 0 };
            DWORD path_len = sizeof(path_buf);
            DWORD type = 0;
            std::wstring db_path;
            if (RegQueryValueExW(hSub.get(), L"DatabasePath", nullptr, &type,
                                 reinterpret_cast<BYTE*>(path_buf), &path_len) == ERROR_SUCCESS &&
                (type == REG_SZ || type == REG_EXPAND_SZ)) {
                db_path = path_buf;
            }

            wchar_t desc_buf[MAX_PATH] = { 0 };
            DWORD desc_len = sizeof(desc_buf);
            std::wstring desc;
            if (RegQueryValueExW(hSub.get(), L"DatabaseDescription", nullptr, &type,
                                 reinterpret_cast<BYTE*>(desc_buf), &desc_len) == ERROR_SUCCESS &&
                type == REG_SZ) {
                desc = desc_buf;
            }

            bool matched = false;
            if (!desc.empty() && matches_target(desc, target)) {
                matched = true;
            }
            if (!matched && !db_path.empty() && path_references_target(db_path, target)) {
                matched = true;
            }

            if (matched) {
                to_delete.push_back({guid, db_path, desc});
            }
        }

        for (const auto& item : to_delete) {
            if (!dry_run) {
                RegDeleteTreeW(hInstalled.get(), item.guid.c_str());
                if (!item.db_path.empty()) {
                    namespace fs = std::filesystem;
                    std::error_code ec;
                    if (fs::exists(item.db_path, ec)) {
                        fs::remove(item.db_path, ec);
                    }
                }
            }
            ++report.sdb_entries_removed;
            report.details.push_back(L"Installed SDB: " + item.guid + L" (" + item.desc + L")");
            deleted_guids.push_back(item.guid);
        }
    }

    // 2. Custom hooks
    for (HKEY root : kRoots) {
        const REGSAM access = dry_run ? KEY_READ : (KEY_READ | KEY_WRITE);
        UniqueHKey hCustom;
        if (RegOpenKeyExW(root, kCustomSdb, 0, access, hCustom.put()) != ERROR_SUCCESS) {
            continue;
        }

        DWORD subkey_count = 0;
        DWORD max_subkey_len = 0;
        if (RegQueryInfoKeyW(hCustom.get(), nullptr, nullptr, nullptr, &subkey_count,
                             &max_subkey_len, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) {
            continue;
        }

        std::vector<wchar_t> name_buf(max_subkey_len + 2, L'\0');
        std::vector<std::wstring> to_delete;

        for (DWORD i = 0; i < subkey_count; ++i) {
            DWORD len = static_cast<DWORD>(name_buf.size());
            if (RegEnumKeyExW(hCustom.get(), i, name_buf.data(), &len, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) {
                continue;
            }

            const std::wstring subkey_name(name_buf.data(), len);
            bool matched = matches_target(subkey_name, target);

            if (!matched && !deleted_guids.empty()) {
                UniqueHKey hSub;
                if (RegOpenKeyExW(hCustom.get(), subkey_name.c_str(), 0, KEY_READ, hSub.put()) == ERROR_SUCCESS) {
                    DWORD val_count = 0;
                    DWORD max_val_len = 0;
                    if (RegQueryInfoKeyW(hSub.get(), nullptr, nullptr, nullptr, nullptr, nullptr,
                                         nullptr, &val_count, &max_val_len, nullptr, nullptr, nullptr) == ERROR_SUCCESS) {
                        std::vector<wchar_t> val_buf(max_val_len + 2, L'\0');
                        for (DWORD j = 0; j < val_count; ++j) {
                            DWORD vlen = static_cast<DWORD>(val_buf.size());
                            if (RegEnumValueW(hSub.get(), j, val_buf.data(), &vlen, nullptr, nullptr, nullptr, nullptr) == ERROR_SUCCESS) {
                                const std::wstring vname(val_buf.data(), vlen);
                                for (const auto& dg : deleted_guids) {
                                    if (string_contains_ignore_case(vname, dg)) {
                                        matched = true;
                                        break;
                                    }
                                }
                            }
                            if (matched) break;
                        }
                    }
                }
            }

            if (matched) {
                to_delete.push_back(subkey_name);
            }
        }

        for (const auto& item : to_delete) {
            if (!dry_run) {
                RegDeleteTreeW(hCustom.get(), item.c_str());
            }
            ++report.custom_hooks_removed;
            report.details.push_back(L"Custom SDB Hook: " + item);
        }
    }

    return report;
}

} // namespace obliterator
