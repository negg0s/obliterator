#include "obliterator/wer_cleaner.hpp"

#include "obliterator/handles.hpp"
#include "obliterator/log.hpp"
#include "obliterator/path.hpp"
#include "obliterator/safety.hpp"

#include <algorithm>
#include <cwctype>
#include <filesystem>
#include <vector>

namespace obliterator {

namespace fs = std::filesystem;

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

bool WerCleaner::matches_target_executable(const std::wstring& filename, const Target& target) {
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
            const std::wstring folder_name = norm_root.substr(last_slash + 1);
            if (folder_name.length() >= 3) {
                const std::wstring lower_folder = PathHelper::to_lower_unicode(folder_name);
                if (lower_fn.find(lower_folder) != std::wstring::npos) {
                    return true;
                }
            }
        }
    }

    return false;
}

void WerCleaner::clean_local_dumps_registry(const Target& target, bool dry_run, WerCleanReport& report) {
    struct RootInfo {
        HKEY root;
        const wchar_t* path;
    };

    const RootInfo roots[] = {
        { HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\Windows Error Reporting\\LocalDumps" },
        { HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\Windows Error Reporting\\LocalDumps" }
    };

    for (const auto& r : roots) {
        UniqueHKey hDumps;
        if (RegOpenKeyExW(r.root, r.path, 0, KEY_READ | KEY_WRITE, hDumps.put()) != ERROR_SUCCESS) {
            if (RegOpenKeyExW(r.root, r.path, 0, KEY_READ, hDumps.put()) != ERROR_SUCCESS) {
                continue;
            }
        }

        DWORD subkey_count = 0;
        DWORD max_subkey_len = 0;
        if (RegQueryInfoKeyW(hDumps.get(), nullptr, nullptr, nullptr, &subkey_count,
                             &max_subkey_len, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) {
            continue;
        }

        std::vector<wchar_t> name_buf(max_subkey_len + 2, L'\0');
        std::vector<std::wstring> matched_keys;

        for (DWORD i = 0; i < subkey_count; ++i) {
            DWORD len = static_cast<DWORD>(name_buf.size());
            if (RegEnumKeyExW(hDumps.get(), i, name_buf.data(), &len,
                              nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) {
                continue;
            }

            const std::wstring subkey_name(name_buf.data(), len);
            UniqueHKey hSub;
            if (RegOpenKeyExW(hDumps.get(), subkey_name.c_str(), 0, KEY_READ, hSub.put()) != ERROR_SUCCESS) {
                continue;
            }

            const std::wstring dump_folder = read_reg_string_value(hSub.get(), nullptr, L"DumpFolder");

            bool matched = false;
            if (matches_target_executable(subkey_name, target)) {
                matched = true;
            } else if (!target.root_path.empty() && PathHelper::contains_path_reference(dump_folder, target.root_path)) {
                matched = true;
            }

            if (matched) {
                matched_keys.push_back(subkey_name);
            }
        }

        for (const auto& k : matched_keys) {
            if (!dry_run) {
                RegDeleteTreeW(hDumps.get(), k.c_str());
            }
            ++report.local_dumps_keys_removed;
            report.details.push_back(L"LocalDumps key: " + k);
        }
    }
}

void WerCleaner::clean_crash_dumps_files(const Target& target, bool dry_run, WerCleanReport& report) {
    wchar_t local_app_data[MAX_PATH] = {0};
    if (GetEnvironmentVariableW(L"LOCALAPPDATA", local_app_data, MAX_PATH) == 0) {
        return;
    }

    const fs::path crash_dumps_dir = fs::path(local_app_data) / L"CrashDumps";
    std::error_code ec;
    if (!fs::exists(crash_dumps_dir, ec) || !fs::is_directory(crash_dumps_dir, ec)) {
        return;
    }

    for (const auto& entry : fs::directory_iterator(crash_dumps_dir, ec)) {
        if (!entry.is_regular_file(ec)) {
            continue;
        }

        const auto filename = entry.path().filename().wstring();
        const auto ext = entry.path().extension().wstring();
        const std::wstring lower_ext = PathHelper::to_lower_unicode(ext);

        if (lower_ext == L".dmp" && matches_target_executable(filename, target)) {
            const auto fsize = entry.file_size(ec);
            if (!ec) {
                report.bytes_reclaimed += fsize;
            }

            if (!dry_run) {
                fs::remove(entry.path(), ec);
            }
            ++report.crash_dumps_deleted;
            report.details.push_back(L"Crash dump: " + filename);
        }
    }
}

void WerCleaner::clean_report_archive(const Target& target, bool dry_run, WerCleanReport& report) {
    std::vector<fs::path> search_paths;

    wchar_t prog_data[MAX_PATH] = {0};
    if (GetEnvironmentVariableW(L"ProgramData", prog_data, MAX_PATH) > 0) {
        search_paths.push_back(fs::path(prog_data) / L"Microsoft\\Windows\\WER\\ReportArchive");
        search_paths.push_back(fs::path(prog_data) / L"Microsoft\\Windows\\WER\\ReportQueue");
    }

    wchar_t local_app_data[MAX_PATH] = {0};
    if (GetEnvironmentVariableW(L"LOCALAPPDATA", local_app_data, MAX_PATH) > 0) {
        search_paths.push_back(fs::path(local_app_data) / L"Microsoft\\Windows\\WER\\ReportArchive");
        search_paths.push_back(fs::path(local_app_data) / L"Microsoft\\Windows\\WER\\ReportQueue");
    }

    for (const auto& dir : search_paths) {
        std::error_code ec;
        if (!fs::exists(dir, ec) || !fs::is_directory(dir, ec)) {
            continue;
        }

        for (const auto& entry : fs::directory_iterator(dir, ec)) {
            if (!entry.is_directory(ec)) {
                continue;
            }

            const auto folder_name = entry.path().filename().wstring();
            if (matches_target_executable(folder_name, target)) {
                // Calculate folder size
                for (const auto& sub_entry : fs::recursive_directory_iterator(entry.path(), ec)) {
                    if (sub_entry.is_regular_file(ec)) {
                        const auto sz = sub_entry.file_size(ec);
                        if (!ec) {
                            report.bytes_reclaimed += sz;
                        }
                    }
                }

                if (!dry_run) {
                    fs::remove_all(entry.path(), ec);
                }
                ++report.wer_reports_deleted;
                report.details.push_back(L"WER report folder: " + folder_name);
            }
        }
    }
}

WerCleanReport WerCleaner::clean_wer_artifacts(const Target& target, bool dry_run) {
    WerCleanReport report;
    clean_local_dumps_registry(target, dry_run, report);
    clean_crash_dumps_files(target, dry_run, report);
    clean_report_archive(target, dry_run, report);
    return report;
}

} // namespace obliterator
