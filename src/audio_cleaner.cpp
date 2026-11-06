#include "obliterator/audio_cleaner.hpp"

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

bool AudioCleaner::matches_target_executable(const std::wstring& filename, const Target& target) {
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

bool AudioCleaner::path_references_target(const std::wstring& path, const Target& target) {
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

AudioCleanReport AudioCleaner::clean_audio_sessions(const Target& target, bool dry_run) {
    AudioCleanReport report;

    // 1. Clean WASAPI PolicyConfig PropertyStore entries
    const wchar_t* const kPropertyStorePath =
        L"Software\\Microsoft\\Internet Explorer\\LowRegistry\\Audio\\PolicyConfig\\PropertyStore";

    UniqueHKey hPropStore;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, kPropertyStorePath, 0, KEY_READ | KEY_WRITE, hPropStore.put()) == ERROR_SUCCESS ||
        RegOpenKeyExW(HKEY_CURRENT_USER, kPropertyStorePath, 0, KEY_READ, hPropStore.put()) == ERROR_SUCCESS) {

        DWORD subkey_count = 0;
        DWORD max_subkey_len = 0;
        if (RegQueryInfoKeyW(hPropStore.get(), nullptr, nullptr, nullptr, &subkey_count,
                             &max_subkey_len, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr) == ERROR_SUCCESS) {
            std::vector<wchar_t> name_buf(max_subkey_len + 2, L'\0');
            std::vector<std::wstring> matched_subkeys;

            for (DWORD i = 0; i < subkey_count; ++i) {
                DWORD len = static_cast<DWORD>(name_buf.size());
                if (RegEnumKeyExW(hPropStore.get(), i, name_buf.data(), &len,
                                  nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) {
                    continue;
                }

                const std::wstring subkey_name(name_buf.data(), len);
                UniqueHKey hSession;
                if (RegOpenKeyExW(hPropStore.get(), subkey_name.c_str(), 0, KEY_READ, hSession.put()) != ERROR_SUCCESS) {
                    continue;
                }

                DWORD val_count = 0;
                DWORD max_val_len = 0;
                if (RegQueryInfoKeyW(hSession.get(), nullptr, nullptr, nullptr, nullptr, nullptr,
                                     nullptr, &val_count, &max_val_len, nullptr, nullptr, nullptr) != ERROR_SUCCESS) {
                    continue;
                }

                std::vector<wchar_t> val_name_buf(max_val_len + 2, L'\0');
                bool matched = false;

                for (DWORD v = 0; v < val_count && !matched; ++v) {
                    DWORD v_len = static_cast<DWORD>(val_name_buf.size());
                    if (RegEnumValueW(hSession.get(), v, val_name_buf.data(), &v_len,
                                      nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) {
                        continue;
                    }

                    const std::wstring val_name(val_name_buf.data(), v_len);
                    const std::wstring val_data = read_reg_string_value(hSession.get(), nullptr, val_name.c_str());
                    if (path_references_target(val_data, target) || matches_target_executable(val_data, target)) {
                        matched = true;
                    }
                }

                if (matched) {
                    matched_subkeys.push_back(subkey_name);
                }
            }

            for (const auto& k : matched_subkeys) {
                if (!dry_run) {
                    RegDeleteTreeW(hPropStore.get(), k.c_str());
                }
                ++report.audio_sessions_removed;
                report.details.push_back(L"Audio PropertyStore: " + k);
            }
        }
    }

    // 2. Clean AppVolume entries
    const wchar_t* const kAppVolumePath =
        L"Software\\Microsoft\\Multimedia\\Audio\\VolumeControl\\AppVolume";

    UniqueHKey hAppVol;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, kAppVolumePath, 0, KEY_READ | KEY_WRITE, hAppVol.put()) == ERROR_SUCCESS ||
        RegOpenKeyExW(HKEY_CURRENT_USER, kAppVolumePath, 0, KEY_READ, hAppVol.put()) == ERROR_SUCCESS) {

        DWORD subkey_count = 0;
        DWORD max_subkey_len = 0;
        if (RegQueryInfoKeyW(hAppVol.get(), nullptr, nullptr, nullptr, &subkey_count,
                             &max_subkey_len, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr) == ERROR_SUCCESS) {
            std::vector<wchar_t> name_buf(max_subkey_len + 2, L'\0');
            std::vector<std::wstring> matched_subkeys;

            for (DWORD i = 0; i < subkey_count; ++i) {
                DWORD len = static_cast<DWORD>(name_buf.size());
                if (RegEnumKeyExW(hAppVol.get(), i, name_buf.data(), &len,
                                  nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) {
                    continue;
                }

                const std::wstring subkey_name(name_buf.data(), len);
                if (matches_target_executable(subkey_name, target)) {
                    matched_subkeys.push_back(subkey_name);
                }
            }

            for (const auto& k : matched_subkeys) {
                if (!dry_run) {
                    RegDeleteTreeW(hAppVol.get(), k.c_str());
                }
                ++report.audio_sessions_removed;
                report.details.push_back(L"Audio AppVolume: " + k);
            }
        }
    }

    return report;
}

} // namespace obliterator
