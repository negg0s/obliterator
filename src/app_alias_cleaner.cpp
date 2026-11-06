#include "obliterator/app_alias_cleaner.hpp"

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

bool AppAliasCleaner::matches_target(const std::wstring& name, const Target& target) {
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

bool AppAliasCleaner::path_references_target(const std::wstring& path, const Target& target) {
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

AppAliasCleanReport AppAliasCleaner::clean_app_aliases(const Target& target, bool dry_run) {
    AppAliasCleanReport report;
    const HKEY kRoots[] = { HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE };
    const wchar_t* const kAliasRegistryPath = L"Software\\Microsoft\\Windows\\CurrentVersion\\AppExecutionAlias";

    // 1. Registry cleanup
    for (HKEY root : kRoots) {
        const REGSAM access = dry_run ? KEY_READ : (KEY_READ | KEY_WRITE);
        UniqueHKey hAliases;
        if (RegOpenKeyExW(root, kAliasRegistryPath, 0, access, hAliases.put()) != ERROR_SUCCESS) {
            continue;
        }

        DWORD subkey_count = 0;
        DWORD max_subkey_len = 0;
        if (RegQueryInfoKeyW(hAliases.get(), nullptr, nullptr, nullptr, &subkey_count,
                             &max_subkey_len, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) {
            continue;
        }

        std::vector<wchar_t> name_buf(max_subkey_len + 2, L'\0');
        std::vector<std::wstring> to_delete;

        for (DWORD i = 0; i < subkey_count; ++i) {
            DWORD len = static_cast<DWORD>(name_buf.size());
            if (RegEnumKeyExW(hAliases.get(), i, name_buf.data(), &len, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) {
                continue;
            }

            const std::wstring subkey_name(name_buf.data(), len);
            UniqueHKey hSub;
            if (RegOpenKeyExW(hAliases.get(), subkey_name.c_str(), 0, KEY_READ, hSub.put()) != ERROR_SUCCESS) {
                continue;
            }

            bool matched = matches_target(subkey_name, target);

            if (!matched) {
                wchar_t pfn_buf[MAX_PATH] = { 0 };
                DWORD pfn_len = sizeof(pfn_buf);
                DWORD type = 0;
                if (RegQueryValueExW(hSub.get(), L"PackageFamilyName", nullptr, &type,
                                     reinterpret_cast<BYTE*>(pfn_buf), &pfn_len) == ERROR_SUCCESS &&
                    type == REG_SZ) {
                    if (matches_target(pfn_buf, target)) {
                        matched = true;
                    }
                }
            }

            if (!matched) {
                wchar_t aumid_buf[MAX_PATH] = { 0 };
                DWORD aumid_len = sizeof(aumid_buf);
                DWORD type = 0;
                if (RegQueryValueExW(hSub.get(), L"AppUserModelId", nullptr, &type,
                                     reinterpret_cast<BYTE*>(aumid_buf), &aumid_len) == ERROR_SUCCESS &&
                    type == REG_SZ) {
                    if (matches_target(aumid_buf, target)) {
                        matched = true;
                    }
                }
            }

            if (!matched) {
                wchar_t exe_buf[MAX_PATH] = { 0 };
                DWORD exe_len = sizeof(exe_buf);
                DWORD type = 0;
                if (RegQueryValueExW(hSub.get(), L"Executable", nullptr, &type,
                                     reinterpret_cast<BYTE*>(exe_buf), &exe_len) == ERROR_SUCCESS &&
                    (type == REG_SZ || type == REG_EXPAND_SZ)) {
                    if (path_references_target(exe_buf, target)) {
                        matched = true;
                    }
                }
            }

            if (matched) {
                to_delete.push_back(subkey_name);
            }
        }

        for (const auto& item : to_delete) {
            if (!dry_run) {
                RegDeleteTreeW(hAliases.get(), item.c_str());
            }
            ++report.registry_aliases_removed;
            report.details.push_back(L"AppExecutionAlias Registry: " + item);
        }
    }

    // 2. Filesystem cleanup (%LOCALAPPDATA%\Microsoft\WindowsApps)
    namespace fs = std::filesystem;
    wchar_t local_app_data[MAX_PATH] = { 0 };
    if (GetEnvironmentVariableW(L"LOCALAPPDATA", local_app_data, MAX_PATH) > 0) {
        std::error_code ec;
        const fs::path apps_dir = fs::path(local_app_data) / L"Microsoft" / L"WindowsApps";
        if (fs::exists(apps_dir, ec) && fs::is_directory(apps_dir, ec)) {
            for (const auto& entry : fs::directory_iterator(apps_dir, ec)) {
                if (ec) {
                    break;
                }

                if (entry.is_regular_file(ec) || entry.is_symlink(ec)) {
                    const std::wstring fn = entry.path().filename().wstring();
                    const std::wstring stem = entry.path().stem().wstring();
                    if (matches_target(fn, target) || matches_target(stem, target)) {
                        if (!dry_run) {
                            fs::remove(entry.path(), ec);
                        }
                        ++report.file_aliases_removed;
                        report.details.push_back(L"AppExecutionAlias File: " + fn);
                    }
                }
            }
        }
    }

    return report;
}

} // namespace obliterator
