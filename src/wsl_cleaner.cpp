#include "obliterator/wsl_cleaner.hpp"

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

bool WslCleaner::matches_target(const std::wstring& name, const Target& target) {
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

bool WslCleaner::path_references_target(const std::wstring& path, const Target& target) {
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

WslCleanReport WslCleaner::clean_wsl_distros(const Target& target, bool dry_run) {
    WslCleanReport report;
    const HKEY kRoots[] = { HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE };
    const wchar_t* const kLxssPath = L"Software\\Microsoft\\Windows\\CurrentVersion\\Lxss";

    for (HKEY root : kRoots) {
        const REGSAM access = dry_run ? KEY_READ : (KEY_READ | KEY_WRITE);
        UniqueHKey hLxss;
        if (RegOpenKeyExW(root, kLxssPath, 0, access, hLxss.put()) != ERROR_SUCCESS) {
            continue;
        }

        wchar_t def_distro_buf[MAX_PATH] = { 0 };
        DWORD def_distro_len = sizeof(def_distro_buf);
        DWORD type = 0;
        std::wstring default_distro;
        if (RegQueryValueExW(hLxss.get(), L"DefaultDistribution", nullptr, &type,
                             reinterpret_cast<BYTE*>(def_distro_buf), &def_distro_len) == ERROR_SUCCESS &&
            type == REG_SZ) {
            default_distro = def_distro_buf;
        }

        DWORD subkey_count = 0;
        DWORD max_subkey_len = 0;
        if (RegQueryInfoKeyW(hLxss.get(), nullptr, nullptr, nullptr, &subkey_count,
                             &max_subkey_len, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) {
            continue;
        }

        std::vector<wchar_t> name_buf(max_subkey_len + 2, L'\0');
        struct DistroDeleteTarget {
            std::wstring guid;
            std::wstring name;
        };
        std::vector<DistroDeleteTarget> to_delete;

        for (DWORD i = 0; i < subkey_count; ++i) {
            DWORD len = static_cast<DWORD>(name_buf.size());
            if (RegEnumKeyExW(hLxss.get(), i, name_buf.data(), &len, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) {
                continue;
            }

            const std::wstring guid(name_buf.data(), len);
            UniqueHKey hSub;
            if (RegOpenKeyExW(hLxss.get(), guid.c_str(), 0, KEY_READ, hSub.put()) != ERROR_SUCCESS) {
                continue;
            }

            wchar_t dname_buf[MAX_PATH] = { 0 };
            DWORD dname_len = sizeof(dname_buf);
            std::wstring distro_name;
            if (RegQueryValueExW(hSub.get(), L"DistributionName", nullptr, &type,
                                 reinterpret_cast<BYTE*>(dname_buf), &dname_len) == ERROR_SUCCESS &&
                type == REG_SZ) {
                distro_name = dname_buf;
            }

            wchar_t base_buf[MAX_PATH] = { 0 };
            DWORD base_len = sizeof(base_buf);
            std::wstring base_path;
            if (RegQueryValueExW(hSub.get(), L"BasePath", nullptr, &type,
                                 reinterpret_cast<BYTE*>(base_buf), &base_len) == ERROR_SUCCESS &&
                (type == REG_SZ || type == REG_EXPAND_SZ)) {
                base_path = base_buf;
            }

            bool matched = false;
            if (!distro_name.empty() && matches_target(distro_name, target)) {
                matched = true;
            }
            if (!matched && !base_path.empty() && path_references_target(base_path, target)) {
                matched = true;
            }

            if (matched) {
                to_delete.push_back({guid, distro_name});
            }
        }

        for (const auto& item : to_delete) {
            if (!dry_run) {
                RegDeleteTreeW(hLxss.get(), item.guid.c_str());
                if (!default_distro.empty() && _wcsicmp(default_distro.c_str(), item.guid.c_str()) == 0) {
                    RegDeleteValueW(hLxss.get(), L"DefaultDistribution");
                }
            }
            ++report.distros_removed;
            report.details.push_back(L"WSL Distro: " + (item.name.empty() ? item.guid : item.name));
        }
    }

    return report;
}

} // namespace obliterator
