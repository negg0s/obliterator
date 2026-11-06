#include "obliterator/dcom_cleaner.hpp"

#include "obliterator/handles.hpp"
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

bool DcomCleaner::matches_target_executable(const std::wstring& filename, const Target& target) {
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

bool DcomCleaner::path_references_target(const std::wstring& path, const Target& target) {
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

bool DcomCleaner::string_matches_target(const std::wstring& str, const Target& target) {
    if (str.empty()) {
        return false;
    }

    if (!target.name.empty() && target.name.length() >= 3) {
        if (string_contains_ignore_case(str, target.name)) {
            return true;
        }
        if (str.length() >= 4 && string_contains_ignore_case(target.name, str)) {
            return true;
        }
    }

    if (!target.root_path.empty()) {
        const std::wstring norm_root = SafetyValidator::normalize_path(target.root_path);
        const auto last_slash = norm_root.find_last_of(L"\\/");
        if (last_slash != std::wstring::npos && last_slash + 1 < norm_root.length()) {
            const std::wstring folder = norm_root.substr(last_slash + 1);
            if (folder.length() >= 3 && string_contains_ignore_case(str, folder)) {
                return true;
            }
        }
    }

    return false;
}

DcomCleanReport DcomCleaner::clean_dcom_appids(const Target& target, bool dry_run) {
    DcomCleanReport report;
    const HKEY kRoots[] = { HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE };
    const wchar_t* const kAppIdPath = L"Software\\Classes\\AppID";

    for (HKEY root : kRoots) {
        const REGSAM access = dry_run ? KEY_READ : (KEY_READ | KEY_WRITE);
        UniqueHKey hAppId;
        if (RegOpenKeyExW(root, kAppIdPath, 0, access, hAppId.put()) != ERROR_SUCCESS) {
            continue;
        }

        DWORD subkey_count = 0;
        DWORD max_subkey_len = 0;
        if (RegQueryInfoKeyW(hAppId.get(), nullptr, nullptr, nullptr, &subkey_count,
                             &max_subkey_len, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) {
            continue;
        }

        std::vector<wchar_t> name_buf(max_subkey_len + 2, L'\0');
        struct AppIdDeleteTarget {
            std::wstring subkey_name;
            std::wstring linked_guid;
        };
        std::vector<AppIdDeleteTarget> to_delete;

        for (DWORD i = 0; i < subkey_count; ++i) {
            DWORD len = static_cast<DWORD>(name_buf.size());
            if (RegEnumKeyExW(hAppId.get(), i, name_buf.data(), &len, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) {
                continue;
            }

            const std::wstring subkey_name(name_buf.data(), len);
            UniqueHKey hSub;
            if (RegOpenKeyExW(hAppId.get(), subkey_name.c_str(), 0, KEY_READ, hSub.put()) != ERROR_SUCCESS) {
                continue;
            }

            // Case A: Named after an executable (e.g. app.exe)
            if (subkey_name.length() > 4 &&
                (subkey_name.rfind(L".exe") == subkey_name.length() - 4 ||
                 subkey_name.rfind(L".EXE") == subkey_name.length() - 4)) {
                if (matches_target_executable(subkey_name, target)) {
                    wchar_t appid_guid_buf[MAX_PATH] = { 0 };
                    DWORD appid_guid_len = sizeof(appid_guid_buf);
                    DWORD type = 0;
                    std::wstring linked_guid;
                    if (RegQueryValueExW(hSub.get(), L"AppID", nullptr, &type,
                                         reinterpret_cast<BYTE*>(appid_guid_buf), &appid_guid_len) == ERROR_SUCCESS &&
                        type == REG_SZ) {
                        linked_guid = appid_guid_buf;
                    }
                    to_delete.push_back({subkey_name, linked_guid});
                }
                continue;
            }

            // Case B: GUID AppID subkey (e.g. {xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx})
            if (subkey_name.length() >= 36 && subkey_name.front() == L'{') {
                bool matched = false;

                // Check default friendly name
                wchar_t desc_buf[MAX_PATH] = { 0 };
                DWORD desc_len = sizeof(desc_buf);
                DWORD type = 0;
                if (RegQueryValueExW(hSub.get(), nullptr, nullptr, &type,
                                     reinterpret_cast<BYTE*>(desc_buf), &desc_len) == ERROR_SUCCESS &&
                    type == REG_SZ) {
                    if (string_matches_target(desc_buf, target)) {
                        matched = true;
                    }
                }

                // Check LocalService
                if (!matched) {
                    wchar_t svc_buf[MAX_PATH] = { 0 };
                    DWORD svc_len = sizeof(svc_buf);
                    if (RegQueryValueExW(hSub.get(), L"LocalService", nullptr, &type,
                                         reinterpret_cast<BYTE*>(svc_buf), &svc_len) == ERROR_SUCCESS &&
                        type == REG_SZ) {
                        if (string_matches_target(svc_buf, target)) {
                            matched = true;
                        }
                    }
                }

                // Check DllSurrogate
                if (!matched) {
                    wchar_t surr_buf[MAX_PATH] = { 0 };
                    DWORD surr_len = sizeof(surr_buf);
                    if (RegQueryValueExW(hSub.get(), L"DllSurrogate", nullptr, &type,
                                         reinterpret_cast<BYTE*>(surr_buf), &surr_len) == ERROR_SUCCESS &&
                        type == REG_SZ) {
                        if (path_references_target(surr_buf, target)) {
                            matched = true;
                        }
                    }
                }

                if (matched) {
                    to_delete.push_back({subkey_name, L""});
                }
            }
        }

        for (const auto& item : to_delete) {
            if (!dry_run) {
                RegDeleteTreeW(hAppId.get(), item.subkey_name.c_str());
                if (!item.linked_guid.empty()) {
                    RegDeleteTreeW(hAppId.get(), item.linked_guid.c_str());
                }
            }
            ++report.appids_removed;
            report.details.push_back(L"DCOM AppID: " + item.subkey_name);
        }
    }

    return report;
}

} // namespace obliterator
