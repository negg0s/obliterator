#include "obliterator/credential_provider_cleaner.hpp"

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

bool CredentialProviderCleaner::is_protected_provider_guid(const std::wstring& guid_str) {
    static const wchar_t* const kProtectedGuids[] = {
        L"{60b78e88-ead8-445c-9cfd-0b87f74ea6cd}", // PasswordProvider
        L"{25C52724-CE35-4576-BAB0-843C15BD8663}", // SmartcardCredentialProvider
        L"{cb8274f4-d130-4e18-8f5b-800cbd582521}", // SmartcardPinProvider
        L"{F8A0B187-F13E-4869-80B3-244479250E9E}", // PinProvider
        L"{8AF66243-6567-4868-B465-6ED21A4B6007}", // FaceProvider
        L"{bec09223-82aa-4186-a054-126384b73c23}", // FingerprintProvider
        L"{27FBDB57-B613-4AF2-9D7E-49FAA49FB6D2}", // TrustedSignalCredentialProvider
        L"{d68ddaee-c335-483a-9e66-63e836ec2d48}", // GenericProvider
        L"{C885F0FB-5D44-4EA6-AE26-726487E14925}"  // NPPSLogonProvider
    };

    for (const auto* p : kProtectedGuids) {
        if (_wcsicmp(guid_str.c_str(), p) == 0) {
            return true;
        }
    }

    return false;
}

bool CredentialProviderCleaner::matches_target(const std::wstring& name, const Target& target) {
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

bool CredentialProviderCleaner::inspect_clsid_server(HKEY root, const std::wstring& clsid_str, const Target& target) {
    if (clsid_str.empty()) {
        return false;
    }

    const std::wstring clsid_key = L"Software\\Classes\\CLSID\\" + clsid_str + L"\\InprocServer32";
    UniqueHKey hInproc;
    if (RegOpenKeyExW(root, clsid_key.c_str(), 0, KEY_READ, hInproc.put()) != ERROR_SUCCESS) {
        return false;
    }

    wchar_t path_buf[MAX_PATH] = { 0 };
    DWORD path_len = sizeof(path_buf);
    DWORD type = 0;
    if (RegQueryValueExW(hInproc.get(), nullptr, nullptr, &type,
                         reinterpret_cast<BYTE*>(path_buf), &path_len) == ERROR_SUCCESS &&
        (type == REG_SZ || type == REG_EXPAND_SZ)) {
        const std::wstring dll_path(path_buf);

        if (!target.root_path.empty()) {
            if (PathHelper::contains_path_reference(dll_path, target.root_path)) {
                return true;
            }
            const std::wstring norm_path = SafetyValidator::normalize_path(dll_path);
            if (PathHelper::is_same_or_subpath(target.root_path, norm_path)) {
                return true;
            }
        }

        if (!target.name.empty() && target.name.length() >= 3) {
            if (string_contains_ignore_case(dll_path, target.name)) {
                return true;
            }
        }
    }

    return false;
}

CredentialProviderCleanReport CredentialProviderCleaner::clean_credential_providers(const Target& target, bool dry_run) {
    CredentialProviderCleanReport report;
    const HKEY kRoots[] = { HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER };

    enum class CatType { Provider, Filter, Plap };
    struct CategoryDef {
        const wchar_t* path;
        CatType type;
    };

    const CategoryDef kCategories[] = {
        { L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Authentication\\Credential Providers", CatType::Provider },
        { L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Authentication\\Credential Provider Filters", CatType::Filter },
        { L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Authentication\\PLAP Providers", CatType::Plap }
    };

    for (HKEY root : kRoots) {
        for (const auto& cat : kCategories) {
            const REGSAM access = dry_run ? KEY_READ : (KEY_READ | KEY_WRITE);
            UniqueHKey hCat;
            if (RegOpenKeyExW(root, cat.path, 0, access, hCat.put()) != ERROR_SUCCESS) {
                continue;
            }

            DWORD subkey_count = 0;
            DWORD max_subkey_len = 0;
            if (RegQueryInfoKeyW(hCat.get(), nullptr, nullptr, nullptr, &subkey_count,
                                 &max_subkey_len, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) {
                continue;
            }

            std::vector<wchar_t> name_buf(max_subkey_len + 2, L'\0');
            struct ProviderMatch {
                std::wstring guid;
                std::wstring desc;
            };
            std::vector<ProviderMatch> to_delete;

            for (DWORD i = 0; i < subkey_count; ++i) {
                DWORD len = static_cast<DWORD>(name_buf.size());
                if (RegEnumKeyExW(hCat.get(), i, name_buf.data(), &len, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) {
                    continue;
                }

                const std::wstring guid_str(name_buf.data(), len);
                if (is_protected_provider_guid(guid_str)) {
                    continue;
                }

                UniqueHKey hSub;
                if (RegOpenKeyExW(hCat.get(), guid_str.c_str(), 0, KEY_READ, hSub.put()) != ERROR_SUCCESS) {
                    continue;
                }

                wchar_t desc_buf[MAX_PATH] = { 0 };
                DWORD desc_len = sizeof(desc_buf);
                DWORD type = 0;
                std::wstring friendly_name;
                if (RegQueryValueExW(hSub.get(), nullptr, nullptr, &type,
                                     reinterpret_cast<BYTE*>(desc_buf), &desc_len) == ERROR_SUCCESS &&
                    type == REG_SZ) {
                    friendly_name = desc_buf;
                }

                bool matched = false;
                if (!friendly_name.empty() && matches_target(friendly_name, target)) {
                    matched = true;
                }
                if (!matched) {
                    matched = inspect_clsid_server(root, guid_str, target);
                }

                if (matched) {
                    to_delete.push_back({guid_str, friendly_name});
                }
            }

            for (const auto& item : to_delete) {
                if (!dry_run) {
                    RegDeleteTreeW(hCat.get(), item.guid.c_str());
                    const std::wstring full_clsid_key = L"Software\\Classes\\CLSID\\" + item.guid;
                    RegDeleteTreeW(root, full_clsid_key.c_str());
                }

                if (cat.type == CatType::Provider) {
                    ++report.providers_removed;
                    report.details.push_back(L"Credential Provider: " + item.guid + L" (" + item.desc + L")");
                } else if (cat.type == CatType::Filter) {
                    ++report.filters_removed;
                    report.details.push_back(L"Credential Provider Filter: " + item.guid + L" (" + item.desc + L")");
                } else {
                    ++report.plap_providers_removed;
                    report.details.push_back(L"PLAP Provider: " + item.guid + L" (" + item.desc + L")");
                }
            }
        }
    }

    return report;
}

} // namespace obliterator
