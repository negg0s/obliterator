#include "obliterator/defender_cleaner.hpp"

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

bool DefenderCleaner::matches_target_executable(const std::wstring& filename, const Target& target) {
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

bool DefenderCleaner::path_references_target(const std::wstring& path, const Target& target) {
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

DefenderCleanReport DefenderCleaner::clean_defender_exclusions(const Target& target, bool dry_run) {
    DefenderCleanReport report;
    const HKEY kRoots[] = { HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER };

    // 1. Path exclusions
    const wchar_t* const kPathsKey = L"SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths";
    for (HKEY root : kRoots) {
        const REGSAM access = dry_run ? KEY_READ : (KEY_READ | KEY_WRITE);
        UniqueHKey hPaths;
        if (RegOpenKeyExW(root, kPathsKey, 0, access, hPaths.put()) == ERROR_SUCCESS) {
            DWORD val_count = 0;
            DWORD max_val_len = 0;
            if (RegQueryInfoKeyW(hPaths.get(), nullptr, nullptr, nullptr, nullptr, nullptr,
                                 nullptr, &val_count, &max_val_len, nullptr, nullptr, nullptr) == ERROR_SUCCESS) {
                std::vector<wchar_t> name_buf(max_val_len + 2, L'\0');
                std::vector<std::wstring> to_delete;

                for (DWORD i = 0; i < val_count; ++i) {
                    DWORD len = static_cast<DWORD>(name_buf.size());
                    if (RegEnumValueW(hPaths.get(), i, name_buf.data(), &len, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) {
                        continue;
                    }
                    const std::wstring val_name(name_buf.data(), len);
                    if (path_references_target(val_name, target)) {
                        to_delete.push_back(val_name);
                    }
                }

                for (const auto& v : to_delete) {
                    if (!dry_run) {
                        RegDeleteValueW(hPaths.get(), v.c_str());
                    }
                    ++report.path_exclusions_removed;
                    report.details.push_back(L"Defender Path Exclusion: " + v);
                }
            }
        }
    }

    // 2. Process exclusions
    const wchar_t* const kProcessesKey = L"SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Processes";
    for (HKEY root : kRoots) {
        const REGSAM access = dry_run ? KEY_READ : (KEY_READ | KEY_WRITE);
        UniqueHKey hProcesses;
        if (RegOpenKeyExW(root, kProcessesKey, 0, access, hProcesses.put()) == ERROR_SUCCESS) {
            DWORD val_count = 0;
            DWORD max_val_len = 0;
            if (RegQueryInfoKeyW(hProcesses.get(), nullptr, nullptr, nullptr, nullptr, nullptr,
                                 nullptr, &val_count, &max_val_len, nullptr, nullptr, nullptr) == ERROR_SUCCESS) {
                std::vector<wchar_t> name_buf(max_val_len + 2, L'\0');
                std::vector<std::wstring> to_delete;

                for (DWORD i = 0; i < val_count; ++i) {
                    DWORD len = static_cast<DWORD>(name_buf.size());
                    if (RegEnumValueW(hProcesses.get(), i, name_buf.data(), &len, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) {
                        continue;
                    }
                    const std::wstring val_name(name_buf.data(), len);
                    if (matches_target_executable(val_name, target) || path_references_target(val_name, target)) {
                        to_delete.push_back(val_name);
                    }
                }

                for (const auto& v : to_delete) {
                    if (!dry_run) {
                        RegDeleteValueW(hProcesses.get(), v.c_str());
                    }
                    ++report.process_exclusions_removed;
                    report.details.push_back(L"Defender Process Exclusion: " + v);
                }
            }
        }
    }

    // 3. Controlled Folder Access allowed applications
    const wchar_t* const kCfaKey =
        L"SOFTWARE\\Microsoft\\Windows Defender\\Windows Defender Exploit Guard\\Controlled Folder Access\\AllowedApplications";
    for (HKEY root : kRoots) {
        const REGSAM access = dry_run ? KEY_READ : (KEY_READ | KEY_WRITE);
        UniqueHKey hCfa;
        if (RegOpenKeyExW(root, kCfaKey, 0, access, hCfa.put()) == ERROR_SUCCESS) {
            DWORD val_count = 0;
            DWORD max_val_len = 0;
            if (RegQueryInfoKeyW(hCfa.get(), nullptr, nullptr, nullptr, nullptr, nullptr,
                                 nullptr, &val_count, &max_val_len, nullptr, nullptr, nullptr) == ERROR_SUCCESS) {
                std::vector<wchar_t> name_buf(max_val_len + 2, L'\0');
                std::vector<std::wstring> to_delete;

                for (DWORD i = 0; i < val_count; ++i) {
                    DWORD len = static_cast<DWORD>(name_buf.size());
                    if (RegEnumValueW(hCfa.get(), i, name_buf.data(), &len, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) {
                        continue;
                    }
                    const std::wstring val_name(name_buf.data(), len);
                    if (path_references_target(val_name, target) || matches_target_executable(val_name, target)) {
                        to_delete.push_back(val_name);
                    }
                }

                for (const auto& v : to_delete) {
                    if (!dry_run) {
                        RegDeleteValueW(hCfa.get(), v.c_str());
                    }
                    ++report.cfa_allowed_removed;
                    report.details.push_back(L"Controlled Folder Access Allowed App: " + v);
                }
            }
        }
    }

    return report;
}

} // namespace obliterator
