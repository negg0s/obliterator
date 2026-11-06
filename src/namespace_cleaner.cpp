#include "obliterator/namespace_cleaner.hpp"

#include "obliterator/handles.hpp"
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

bool NamespaceCleaner::matches_target(const std::wstring& name, const Target& target) {
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

bool NamespaceCleaner::path_references_target(const std::wstring& path, const Target& target) {
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

bool NamespaceCleaner::inspect_clsid_server(HKEY root, const std::wstring& clsid_str, const Target& target) {
    if (clsid_str.empty()) {
        return false;
    }

    const std::wstring clsid_key = L"Software\\Classes\\CLSID\\" + clsid_str + L"\\InprocServer32";
    UniqueHKey hInproc;
    if (RegOpenKeyExW(root, clsid_key.c_str(), 0, KEY_READ, hInproc.put()) == ERROR_SUCCESS) {
        wchar_t path_buf[MAX_PATH] = { 0 };
        DWORD path_len = sizeof(path_buf);
        DWORD type = 0;
        if (RegQueryValueExW(hInproc.get(), nullptr, nullptr, &type,
                             reinterpret_cast<BYTE*>(path_buf), &path_len) == ERROR_SUCCESS &&
            (type == REG_SZ || type == REG_EXPAND_SZ)) {
            if (path_references_target(path_buf, target)) {
                return true;
            }
        }
    }

    // Also check DefaultIcon or Instance
    const std::wstring icon_key = L"Software\\Classes\\CLSID\\" + clsid_str + L"\\DefaultIcon";
    UniqueHKey hIcon;
    if (RegOpenKeyExW(root, icon_key.c_str(), 0, KEY_READ, hIcon.put()) == ERROR_SUCCESS) {
        wchar_t path_buf[MAX_PATH] = { 0 };
        DWORD path_len = sizeof(path_buf);
        DWORD type = 0;
        if (RegQueryValueExW(hIcon.get(), nullptr, nullptr, &type,
                             reinterpret_cast<BYTE*>(path_buf), &path_len) == ERROR_SUCCESS &&
            (type == REG_SZ || type == REG_EXPAND_SZ)) {
            if (path_references_target(path_buf, target)) {
                return true;
            }
        }
    }

    return false;
}

void NamespaceCleaner::notify_shell() {
    SHChangeNotify(SHCNE_ASSOCCHANGED, SHCNF_IDLIST, nullptr, nullptr);
    SHChangeNotify(SHCNE_UPDATEDIR, SHCNF_IDLIST, nullptr, nullptr);
}

NamespaceCleanReport NamespaceCleaner::clean_namespace_extensions(const Target& target, bool dry_run) {
    NamespaceCleanReport report;
    const HKEY kRoots[] = { HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE };

    struct TargetCategory {
        const wchar_t* path;
        bool is_desktop;
    };

    const TargetCategory kCategories[] = {
        { L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\MyComputer\\NameSpace", false },
        { L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Desktop\\NameSpace", true }
    };

    bool did_delete = false;

    for (HKEY root : kRoots) {
        for (const auto& cat : kCategories) {
            const REGSAM access = dry_run ? KEY_READ : (KEY_READ | KEY_WRITE);
            UniqueHKey hNamespace;
            if (RegOpenKeyExW(root, cat.path, 0, access, hNamespace.put()) != ERROR_SUCCESS) {
                continue;
            }

            DWORD subkey_count = 0;
            DWORD max_subkey_len = 0;
            if (RegQueryInfoKeyW(hNamespace.get(), nullptr, nullptr, nullptr, &subkey_count,
                                 &max_subkey_len, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) {
                continue;
            }

            std::vector<wchar_t> name_buf(max_subkey_len + 2, L'\0');
            std::vector<std::wstring> to_delete;

            for (DWORD i = 0; i < subkey_count; ++i) {
                DWORD len = static_cast<DWORD>(name_buf.size());
                if (RegEnumKeyExW(hNamespace.get(), i, name_buf.data(), &len, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) {
                    continue;
                }

                const std::wstring guid_name(name_buf.data(), len);
                UniqueHKey hSub;
                if (RegOpenKeyExW(hNamespace.get(), guid_name.c_str(), 0, KEY_READ, hSub.put()) != ERROR_SUCCESS) {
                    continue;
                }

                bool matched = false;

                // Check default friendly name (e.g. "Dropbox" or "Google Drive")
                wchar_t desc_buf[MAX_PATH] = { 0 };
                DWORD desc_len = sizeof(desc_buf);
                DWORD type = 0;
                if (RegQueryValueExW(hSub.get(), nullptr, nullptr, &type,
                                     reinterpret_cast<BYTE*>(desc_buf), &desc_len) == ERROR_SUCCESS &&
                    type == REG_SZ) {
                    if (matches_target(desc_buf, target)) {
                        matched = true;
                    }
                }

                // Check associated CLSID inproc server or icon
                if (!matched && guid_name.length() >= 36 && guid_name.front() == L'{') {
                    if (inspect_clsid_server(root, guid_name, target)) {
                        matched = true;
                    }
                }

                if (matched) {
                    to_delete.push_back(guid_name);
                }
            }

            for (const auto& g : to_delete) {
                if (!dry_run) {
                    RegDeleteTreeW(hNamespace.get(), g.c_str());
                    const std::wstring full_clsid_key = L"Software\\Classes\\CLSID\\" + g;
                    RegDeleteTreeW(root, full_clsid_key.c_str());
                }
                if (cat.is_desktop) {
                    ++report.desktop_entries_removed;
                } else {
                    ++report.mycomputer_entries_removed;
                }
                report.details.push_back(std::wstring(cat.is_desktop ? L"Desktop NameSpace: " : L"MyComputer NameSpace: ") + g);
                did_delete = true;
            }
        }
    }

    if (did_delete && !dry_run) {
        notify_shell();
    }

    return report;
}

} // namespace obliterator
