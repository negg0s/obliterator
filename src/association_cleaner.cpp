#include "obliterator/association_cleaner.hpp"

#include "obliterator/handles.hpp"
#include "obliterator/log.hpp"
#include "obliterator/path.hpp"
#include "obliterator/safety.hpp"

#include <shlobj.h>
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
    if (RegQueryValueExW(target_hkey, value_name, nullptr, nullptr, nullptr, &bytes) == ERROR_SUCCESS && bytes > 0) {
        std::vector<wchar_t> buf((bytes / sizeof(wchar_t)) + 2, L'\0');
        if (RegQueryValueExW(target_hkey, value_name, nullptr, nullptr,
                             reinterpret_cast<LPBYTE>(buf.data()), &bytes) == ERROR_SUCCESS) {
            result = buf.data();
        }
    }
    return result;
}

bool AssociationCleaner::is_protected_protocol(const std::wstring& protocol) {
    static const wchar_t* const kProtectedProtocols[] = {
        L"http", L"https", L"ftp", L"file", L"mailto", L"news", L"nntp",
        L"tel", L"sms", L"ldap", L"ms-settings", L"ms-windows-store",
        L"ms-screenclip", L"calculator", L"windowsdefender", L"microsoft-edge",
        L"ms-gamingoverlay", L"ms-gamebar", L"ms-clock", L"about", L"res"
    };

    const std::wstring lower = PathHelper::to_lower_unicode(protocol);
    for (const auto* prot : kProtectedProtocols) {
        if (lower == prot) {
            return true;
        }
    }
    return false;
}

bool AssociationCleaner::path_references_target(const std::wstring& text, const Target& target) {
    if (text.empty()) {
        return false;
    }

    if (!target.root_path.empty()) {
        if (PathHelper::contains_path_reference(text, target.root_path)) {
            return true;
        }
        const std::wstring norm_text = SafetyValidator::normalize_path(text);
        if (PathHelper::is_same_or_subpath(target.root_path, norm_text)) {
            return true;
        }
    }

    if (!target.name.empty() && target.name.length() >= 3) {
        if (string_contains_ignore_case(text, target.name)) {
            return true;
        }
    }

    return false;
}

void AssociationCleaner::clean_url_protocols(const Target& target, bool dry_run, AssociationCleanReport& report) {
    struct RootInfo {
        HKEY root;
        const wchar_t* path;
    };

    const RootInfo roots[] = {
        { HKEY_CURRENT_USER, L"Software\\Classes" },
        { HKEY_LOCAL_MACHINE, L"SOFTWARE\\Classes" }
    };

    for (const auto& r : roots) {
        UniqueHKey hClasses;
        if (RegOpenKeyExW(r.root, r.path, 0, KEY_READ | KEY_WRITE, hClasses.put()) != ERROR_SUCCESS) {
            if (RegOpenKeyExW(r.root, r.path, 0, KEY_READ, hClasses.put()) != ERROR_SUCCESS) {
                continue;
            }
        }

        DWORD subkey_count = 0;
        DWORD max_subkey_len = 0;
        if (RegQueryInfoKeyW(hClasses.get(), nullptr, nullptr, nullptr, &subkey_count,
                             &max_subkey_len, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) {
            continue;
        }

        std::vector<wchar_t> name_buf(max_subkey_len + 2, L'\0');
        std::vector<std::wstring> matched_protocols;

        for (DWORD i = 0; i < subkey_count; ++i) {
            DWORD len = static_cast<DWORD>(name_buf.size());
            if (RegEnumKeyExW(hClasses.get(), i, name_buf.data(), &len,
                              nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) {
                continue;
            }

            const std::wstring subkey_name(name_buf.data(), len);
            if (is_protected_protocol(subkey_name)) {
                continue;
            }

            UniqueHKey hProto;
            if (RegOpenKeyExW(hClasses.get(), subkey_name.c_str(), 0, KEY_READ, hProto.put()) != ERROR_SUCCESS) {
                continue;
            }

            // A protocol key must contain a value named "URL Protocol"
            DWORD type = 0;
            if (RegQueryValueExW(hProto.get(), L"URL Protocol", nullptr, &type, nullptr, nullptr) != ERROR_SUCCESS) {
                continue;
            }

            // Check shell\open\command
            const std::wstring cmd = read_reg_string_value(hProto.get(), L"shell\\open\\command", nullptr);
            bool matched = false;

            if (path_references_target(cmd, target)) {
                matched = true;
            } else if (!target.name.empty() && string_contains_ignore_case(subkey_name, target.name)) {
                matched = true;
            }

            if (matched) {
                matched_protocols.push_back(subkey_name);
            }
        }

        for (const auto& proto : matched_protocols) {
            if (!dry_run) {
                RegDeleteTreeW(hClasses.get(), proto.c_str());
            }
            ++report.protocols_removed;
            report.details.push_back(L"URL Protocol: " + proto);
        }
    }
}

void AssociationCleaner::clean_app_paths(const Target& target, bool dry_run, AssociationCleanReport& report) {
    struct AppPathRoot {
        HKEY root;
        const wchar_t* subkey;
    };

    const AppPathRoot roots[] = {
        { HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths" },
        { HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\App Paths" }
    };

    for (const auto& r : roots) {
        UniqueHKey hAppPaths;
        if (RegOpenKeyExW(r.root, r.subkey, 0, KEY_READ | KEY_WRITE, hAppPaths.put()) != ERROR_SUCCESS) {
            if (RegOpenKeyExW(r.root, r.subkey, 0, KEY_READ, hAppPaths.put()) != ERROR_SUCCESS) {
                continue;
            }
        }

        DWORD subkey_count = 0;
        DWORD max_subkey_len = 0;
        if (RegQueryInfoKeyW(hAppPaths.get(), nullptr, nullptr, nullptr, &subkey_count,
                             &max_subkey_len, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) {
            continue;
        }

        std::vector<wchar_t> name_buf(max_subkey_len + 2, L'\0');
        std::vector<std::wstring> matched_keys;

        for (DWORD i = 0; i < subkey_count; ++i) {
            DWORD len = static_cast<DWORD>(name_buf.size());
            if (RegEnumKeyExW(hAppPaths.get(), i, name_buf.data(), &len,
                              nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) {
                continue;
            }

            const std::wstring app_key(name_buf.data(), len);
            UniqueHKey hSub;
            if (RegOpenKeyExW(hAppPaths.get(), app_key.c_str(), 0, KEY_READ, hSub.put()) != ERROR_SUCCESS) {
                continue;
            }

            const std::wstring default_val = read_reg_string_value(hSub.get(), nullptr, nullptr);
            const std::wstring path_val = read_reg_string_value(hSub.get(), nullptr, L"Path");

            bool matched = false;
            if (path_references_target(default_val, target) || path_references_target(path_val, target)) {
                matched = true;
            } else if (!target.name.empty() && string_contains_ignore_case(app_key, target.name)) {
                matched = true;
            }

            if (matched) {
                matched_keys.push_back(app_key);
            }
        }

        for (const auto& k : matched_keys) {
            if (!dry_run) {
                RegDeleteTreeW(hAppPaths.get(), k.c_str());
            }
            ++report.app_paths_removed;
            report.details.push_back(L"App Path: " + k);
        }
    }
}

void AssociationCleaner::clean_explorer_file_exts(const Target& target, bool dry_run, AssociationCleanReport& report) {
    const wchar_t* const kFileExtsPath = L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\FileExts";
    UniqueHKey hFileExts;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, kFileExtsPath, 0, KEY_READ, hFileExts.put()) != ERROR_SUCCESS) {
        return;
    }

    DWORD ext_count = 0;
    DWORD max_ext_len = 0;
    if (RegQueryInfoKeyW(hFileExts.get(), nullptr, nullptr, nullptr, &ext_count,
                         &max_ext_len, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) {
        return;
    }

    std::vector<wchar_t> ext_buf(max_ext_len + 2, L'\0');

    for (DWORD i = 0; i < ext_count; ++i) {
        DWORD len = static_cast<DWORD>(ext_buf.size());
        if (RegEnumKeyExW(hFileExts.get(), i, ext_buf.data(), &len,
                          nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) {
            continue;
        }

        const std::wstring ext_name(ext_buf.data(), len);
        const std::wstring open_with_path = ext_name + L"\\OpenWithList";

        UniqueHKey hOpenWith;
        if (RegOpenKeyExW(hFileExts.get(), open_with_path.c_str(), 0, KEY_READ | KEY_WRITE, hOpenWith.put()) == ERROR_SUCCESS) {
            DWORD val_count = 0;
            DWORD max_val_len = 0;
            if (RegQueryInfoKeyW(hOpenWith.get(), nullptr, nullptr, nullptr, nullptr,
                                 nullptr, nullptr, &val_count, &max_val_len, nullptr, nullptr, nullptr) == ERROR_SUCCESS) {
                std::vector<wchar_t> val_name_buf(max_val_len + 2, L'\0');
                std::vector<std::wstring> vals_to_delete;

                for (DWORD v = 0; v < val_count; ++v) {
                    DWORD val_len = static_cast<DWORD>(val_name_buf.size());
                    if (RegEnumValueW(hOpenWith.get(), v, val_name_buf.data(), &val_len,
                                      nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) {
                        continue;
                    }

                    const std::wstring val_name(val_name_buf.data(), val_len);
                    if (val_name == L"MRUList") {
                        continue;
                    }

                    const std::wstring val_data = read_reg_string_value(hOpenWith.get(), nullptr, val_name.c_str());
                    if (!val_data.empty() && path_references_target(val_data, target)) {
                        vals_to_delete.push_back(val_name);
                    }
                }

                for (const auto& vd : vals_to_delete) {
                    if (!dry_run) {
                        RegDeleteValueW(hOpenWith.get(), vd.c_str());
                    }
                    ++report.file_exts_cleaned;
                    report.details.push_back(L"FileExts " + ext_name + L": " + vd);
                }
            }
        }
    }
}

AssociationCleanReport AssociationCleaner::clean_associations(const Target& target, bool dry_run) {
    AssociationCleanReport report;
    clean_url_protocols(target, dry_run, report);
    clean_app_paths(target, dry_run, report);
    clean_explorer_file_exts(target, dry_run, report);

    if (!dry_run && (report.protocols_removed > 0 || report.app_paths_removed > 0 || report.file_exts_cleaned > 0)) {
        SHChangeNotify(SHCNE_ASSOCCHANGED, SHCNF_IDLIST, nullptr, nullptr);
    }

    return report;
}

} // namespace obliterator
