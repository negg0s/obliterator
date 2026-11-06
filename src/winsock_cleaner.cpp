#include "obliterator/winsock_cleaner.hpp"

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

bool WinsockCleaner::is_protected_provider(const std::wstring& lib_path, const std::wstring& display_name) {
    static const wchar_t* const kProtectedLibs[] = {
        L"mswsock.dll",
        L"winrnr.dll",
        L"pnrpnsp.dll",
        L"napinsp.dll",
        L"wshbth.dll",
        L"nlansp.dll"
    };

    for (const auto* lib : kProtectedLibs) {
        if (string_contains_ignore_case(lib_path, lib)) {
            return true;
        }
    }

    static const wchar_t* const kProtectedNames[] = {
        L"Network Location Awareness",
        L"NLA",
        L"DNS API",
        L"Bluetooth",
        L"Peer Name Resolution",
        L"PNRP"
    };

    for (const auto* name : kProtectedNames) {
        if (string_contains_ignore_case(display_name, name)) {
            return true;
        }
    }

    return false;
}

bool WinsockCleaner::matches_target(const std::wstring& name, const Target& target) {
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

bool WinsockCleaner::path_references_target(const std::wstring& path, const Target& target) {
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

WinsockCleanReport WinsockCleaner::clean_winsock_providers(const Target& target, bool dry_run) {
    WinsockCleanReport report;
    const HKEY kRoots[] = { HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER };
    const wchar_t* const kCatalogPaths[] = {
        L"SYSTEM\\CurrentControlSet\\Services\\WinSock2\\Parameters\\NameSpace_Catalog5\\Catalog_Entries",
        L"SYSTEM\\CurrentControlSet\\Services\\WinSock2\\Parameters\\NameSpace_Catalog5\\Catalog_Entries64"
    };

    for (HKEY root : kRoots) {
        for (const auto* cat_path : kCatalogPaths) {
            const REGSAM access = dry_run ? KEY_READ : (KEY_READ | KEY_WRITE);
            UniqueHKey hCatalog;
            if (RegOpenKeyExW(root, cat_path, 0, access, hCatalog.put()) != ERROR_SUCCESS) {
                continue;
            }

            DWORD subkey_count = 0;
            DWORD max_subkey_len = 0;
            if (RegQueryInfoKeyW(hCatalog.get(), nullptr, nullptr, nullptr, &subkey_count,
                                 &max_subkey_len, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) {
                continue;
            }

            std::vector<wchar_t> name_buf(max_subkey_len + 2, L'\0');
            struct ProviderMatch {
                std::wstring subkey_name;
                std::wstring display_name;
            };
            std::vector<ProviderMatch> to_delete;

            for (DWORD i = 0; i < subkey_count; ++i) {
                DWORD len = static_cast<DWORD>(name_buf.size());
                if (RegEnumKeyExW(hCatalog.get(), i, name_buf.data(), &len, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) {
                    continue;
                }

                const std::wstring subkey_name(name_buf.data(), len);
                UniqueHKey hSub;
                if (RegOpenKeyExW(hCatalog.get(), subkey_name.c_str(), 0, KEY_READ, hSub.put()) != ERROR_SUCCESS) {
                    continue;
                }

                wchar_t lib_buf[MAX_PATH] = { 0 };
                DWORD lib_len = sizeof(lib_buf);
                DWORD type = 0;
                std::wstring lib_path;
                if (RegQueryValueExW(hSub.get(), L"LibraryPath", nullptr, &type,
                                     reinterpret_cast<BYTE*>(lib_buf), &lib_len) == ERROR_SUCCESS &&
                    (type == REG_SZ || type == REG_EXPAND_SZ)) {
                    lib_path = lib_buf;
                }

                wchar_t disp_buf[MAX_PATH] = { 0 };
                DWORD disp_len = sizeof(disp_buf);
                std::wstring disp_name;
                if (RegQueryValueExW(hSub.get(), L"DisplayString", nullptr, &type,
                                     reinterpret_cast<BYTE*>(disp_buf), &disp_len) == ERROR_SUCCESS &&
                    type == REG_SZ) {
                    disp_name = disp_buf;
                }

                if (is_protected_provider(lib_path, disp_name)) {
                    continue;
                }

                bool matched = false;
                if (!disp_name.empty() && matches_target(disp_name, target)) {
                    matched = true;
                }
                if (!matched && !lib_path.empty() && path_references_target(lib_path, target)) {
                    matched = true;
                }

                if (matched) {
                    to_delete.push_back({subkey_name, disp_name});
                }
            }

            for (const auto& item : to_delete) {
                if (!dry_run) {
                    RegDeleteTreeW(hCatalog.get(), item.subkey_name.c_str());
                }
                ++report.catalog_entries_removed;
                report.details.push_back(L"WinSock Namespace Provider: " + (item.display_name.empty() ? item.subkey_name : item.display_name));
            }
        }
    }

    return report;
}

} // namespace obliterator
