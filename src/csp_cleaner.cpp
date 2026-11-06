#include "obliterator/csp_cleaner.hpp"

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

bool CspCleaner::is_protected_provider(const std::wstring& name) {
    static const wchar_t* const kProtected[] = {
        L"Microsoft Base Cryptographic Provider v1.0",
        L"Microsoft Enhanced Cryptographic Provider v1.0",
        L"Microsoft Strong Cryptographic Provider",
        L"Microsoft Enhanced RSA and AES Cryptographic Provider",
        L"Microsoft Base Smart Card Crypto Provider",
        L"Microsoft Base DSS Cryptographic Provider",
        L"Microsoft Base DSS and Diffie-Hellman Cryptographic Provider",
        L"Microsoft Enhanced DSS and Diffie-Hellman Cryptographic Provider",
        L"Microsoft DH SChannel Cryptographic Provider",
        L"Microsoft RSA SChannel Cryptographic Provider",
        L"Microsoft Software Key Storage Provider"
    };

    for (const auto* p : kProtected) {
        if (_wcsicmp(name.c_str(), p) == 0) {
            return true;
        }
    }
    return false;
}

bool CspCleaner::matches_target(const std::wstring& name, const Target& target) {
    if (name.empty()) {
        return false;
    }

    if (!target.name.empty() && target.name.length() >= 3) {
        if (string_contains_ignore_case(name, target.name)) {
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

bool CspCleaner::path_references_target(const std::wstring& path, const Target& target) {
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

CspCleanReport CspCleaner::clean_csps(const Target& target, bool dry_run) {
    CspCleanReport report;
    const HKEY kRoots[] = { HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER };
    const wchar_t* const kProviderPaths[] = {
        L"SOFTWARE\\Microsoft\\Cryptography\\Defaults\\Provider",
        L"SOFTWARE\\WOW6432Node\\Microsoft\\Cryptography\\Defaults\\Provider"
    };

    std::vector<std::wstring> all_deleted_providers;

    // 1. Providers
    for (HKEY root : kRoots) {
        for (const auto* prov_path : kProviderPaths) {
            const REGSAM access = dry_run ? KEY_READ : (KEY_READ | KEY_WRITE);
            UniqueHKey hProviders;
            if (RegOpenKeyExW(root, prov_path, 0, access, hProviders.put()) != ERROR_SUCCESS) {
                continue;
            }

            DWORD subkey_count = 0;
            DWORD max_subkey_len = 0;
            if (RegQueryInfoKeyW(hProviders.get(), nullptr, nullptr, nullptr, &subkey_count,
                                 &max_subkey_len, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) {
                continue;
            }

            std::vector<wchar_t> name_buf(max_subkey_len + 2, L'\0');
            std::vector<std::wstring> to_delete;

            for (DWORD i = 0; i < subkey_count; ++i) {
                DWORD len = static_cast<DWORD>(name_buf.size());
                if (RegEnumKeyExW(hProviders.get(), i, name_buf.data(), &len, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) {
                    continue;
                }

                const std::wstring prov_name(name_buf.data(), len);
                if (is_protected_provider(prov_name)) {
                    continue;
                }

                bool matches = matches_target(prov_name, target);
                if (!matches) {
                    UniqueHKey hSub;
                    if (RegOpenKeyExW(hProviders.get(), prov_name.c_str(), 0, KEY_READ, hSub.put()) == ERROR_SUCCESS) {
                        wchar_t img_buf[MAX_PATH] = { 0 };
                        DWORD img_len = sizeof(img_buf);
                        DWORD type = 0;
                        if (RegQueryValueExW(hSub.get(), L"Image Path", nullptr, &type,
                                             reinterpret_cast<BYTE*>(img_buf), &img_len) == ERROR_SUCCESS &&
                            (type == REG_SZ || type == REG_EXPAND_SZ)) {
                            matches = path_references_target(img_buf, target);
                        }
                    }
                }

                if (matches) {
                    to_delete.push_back(prov_name);
                }
            }

            for (const auto& p : to_delete) {
                if (!dry_run) {
                    RegDeleteTreeW(hProviders.get(), p.c_str());
                }
                ++report.providers_removed;
                report.details.push_back(L"CSP: " + p);
                all_deleted_providers.push_back(p);
            }
        }
    }

    // 2. Provider Types
    const wchar_t* const kTypePaths[] = {
        L"SOFTWARE\\Microsoft\\Cryptography\\Defaults\\Provider Types",
        L"SOFTWARE\\WOW6432Node\\Microsoft\\Cryptography\\Defaults\\Provider Types"
    };

    for (HKEY root : kRoots) {
        for (const auto* type_path : kTypePaths) {
            const REGSAM access = dry_run ? KEY_READ : (KEY_READ | KEY_WRITE);
            UniqueHKey hTypes;
            if (RegOpenKeyExW(root, type_path, 0, access, hTypes.put()) != ERROR_SUCCESS) {
                continue;
            }

            DWORD subkey_count = 0;
            DWORD max_subkey_len = 0;
            if (RegQueryInfoKeyW(hTypes.get(), nullptr, nullptr, nullptr, &subkey_count,
                                 &max_subkey_len, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) {
                continue;
            }

            std::vector<wchar_t> name_buf(max_subkey_len + 2, L'\0');

            for (DWORD i = 0; i < subkey_count; ++i) {
                DWORD len = static_cast<DWORD>(name_buf.size());
                if (RegEnumKeyExW(hTypes.get(), i, name_buf.data(), &len, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) {
                    continue;
                }

                const std::wstring subkey_name(name_buf.data(), len);
                UniqueHKey hSubType;
                if (RegOpenKeyExW(hTypes.get(), subkey_name.c_str(), 0, access, hSubType.put()) != ERROR_SUCCESS) {
                    continue;
                }

                wchar_t prov_name_buf[MAX_PATH] = { 0 };
                DWORD prov_name_len = sizeof(prov_name_buf);
                DWORD type = 0;
                if (RegQueryValueExW(hSubType.get(), L"Name", nullptr, &type,
                                     reinterpret_cast<BYTE*>(prov_name_buf), &prov_name_len) == ERROR_SUCCESS &&
                    type == REG_SZ) {
                    const std::wstring active_prov(prov_name_buf);
                    bool matched = false;
                    for (const auto& dp : all_deleted_providers) {
                        if (_wcsicmp(active_prov.c_str(), dp.c_str()) == 0) {
                            matched = true;
                            break;
                        }
                    }
                    if (!matched && matches_target(active_prov, target)) {
                        matched = true;
                    }

                    if (matched) {
                        if (!dry_run) {
                            RegDeleteValueW(hSubType.get(), L"Name");
                        }
                        ++report.provider_types_cleaned;
                        report.details.push_back(L"Provider Type reference cleaned: " + subkey_name + L" -> " + active_prov);
                    }
                }
            }
        }
    }

    return report;
}

} // namespace obliterator
