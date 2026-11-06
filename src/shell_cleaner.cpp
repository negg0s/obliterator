#include "obliterator/shell_cleaner.hpp"

#include "obliterator/handles.hpp"
#include "obliterator/log.hpp"
#include "obliterator/path.hpp"
#include "obliterator/safety.hpp"

#include <shlobj.h>
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

static void scan_clsid_branch(
    HKEY root_key,
    DWORD sam_view,
    const std::wstring& target_root_path,
    std::wstring_view target_name,
    std::vector<ShellExtensionInfo>& out_extensions
) {
    const std::wstring clsid_path = L"SOFTWARE\\Classes\\CLSID";
    UniqueHKey hClsid;
    if (RegOpenKeyExW(root_key, clsid_path.c_str(), 0, KEY_READ | sam_view, hClsid.put()) != ERROR_SUCCESS) {
        return;
    }

    DWORD subkey_count = 0;
    DWORD max_subkey_len = 0;
    if (RegQueryInfoKeyW(hClsid.get(), nullptr, nullptr, nullptr, &subkey_count,
                         &max_subkey_len, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) {
        return;
    }

    std::vector<wchar_t> key_name_buf(max_subkey_len + 2, L'\0');

    for (DWORD idx = 0; idx < subkey_count; ++idx) {
        DWORD name_len = static_cast<DWORD>(key_name_buf.size());
        if (RegEnumKeyExW(hClsid.get(), idx, key_name_buf.data(), &name_len,
                          nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) {
            continue;
        }

        const std::wstring guid(key_name_buf.data(), name_len);
        UniqueHKey hSub;
        if (RegOpenKeyExW(hClsid.get(), guid.c_str(), 0, KEY_READ | sam_view, hSub.put()) != ERROR_SUCCESS) {
            continue;
        }

        const std::wstring inproc_dll = read_reg_string_value(hSub.get(), L"InprocServer32", nullptr);
        if (inproc_dll.empty()) {
            continue;
        }

        const std::wstring norm_dll = SafetyValidator::normalize_path(inproc_dll);
        bool matches = false;

        if (!target_root_path.empty() && PathHelper::is_same_or_subpath(target_root_path, norm_dll)) {
            matches = true;
        } else if (!target_name.empty() && string_contains_ignore_case(norm_dll, target_name)) {
            matches = true;
        }

        if (matches) {
            const std::wstring desc = read_reg_string_value(hSub.get(), nullptr, nullptr);
            ShellExtensionInfo info;
            info.clsid = guid;
            info.name = desc.empty() ? guid : desc;
            info.handler_key_path = clsid_path + L"\\" + guid;
            info.module_path = inproc_dll;
            info.root_key = root_key;
            info.sam_view = sam_view;
            out_extensions.push_back(std::move(info));
        }
    }
}

std::vector<ShellExtensionInfo> ShellCleaner::find_target_shell_extensions(
    const std::wstring& target_root_path,
    std::wstring_view target_name
) {
    std::vector<ShellExtensionInfo> extensions;
    if (target_root_path.empty() && target_name.empty()) {
        return extensions;
    }

    const DWORD views[] = {KEY_WOW64_64KEY, KEY_WOW64_32KEY};
    for (DWORD view : views) {
        scan_clsid_branch(HKEY_LOCAL_MACHINE, view, target_root_path, target_name, extensions);
        scan_clsid_branch(HKEY_CURRENT_USER, view, target_root_path, target_name, extensions);
    }

    return extensions;
}

static size_t delete_matched_handler_subkeys(
    HKEY root,
    const std::wstring& branch_path,
    DWORD sam_view,
    const std::vector<std::wstring>& target_guids,
    std::wstring_view target_name
) {
    UniqueHKey hParent;
    if (RegOpenKeyExW(root, branch_path.c_str(), 0, KEY_READ | KEY_WRITE | sam_view, hParent.put()) != ERROR_SUCCESS) {
        return 0;
    }

    DWORD subkey_count = 0;
    DWORD max_subkey_len = 0;
    if (RegQueryInfoKeyW(hParent.get(), nullptr, nullptr, nullptr, &subkey_count,
                         &max_subkey_len, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) {
        return 0;
    }

    std::vector<wchar_t> name_buf(max_subkey_len + 2, L'\0');
    std::vector<std::wstring> to_delete;

    for (DWORD idx = 0; idx < subkey_count; ++idx) {
        DWORD len = static_cast<DWORD>(name_buf.size());
        if (RegEnumKeyExW(hParent.get(), idx, name_buf.data(), &len, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) {
            continue;
        }

        std::wstring subkey_name(name_buf.data(), len);
        bool match = false;

        // Check if subkey name itself is one of the target GUIDs
        for (const auto& g : target_guids) {
            if (_wcsicmp(subkey_name.c_str(), g.c_str()) == 0) {
                match = true;
                break;
            }
        }

        // Check default value of the handler
        if (!match) {
            std::wstring def_val = read_reg_string_value(hParent.get(), subkey_name.c_str(), nullptr);
            for (const auto& g : target_guids) {
                if (_wcsicmp(def_val.c_str(), g.c_str()) == 0) {
                    match = true;
                    break;
                }
            }
        }

        // Check subkey name contains target name
        if (!match && !target_name.empty() && string_contains_ignore_case(subkey_name, target_name)) {
            match = true;
        }

        if (match) {
            to_delete.push_back(std::move(subkey_name));
        }
    }

    size_t deleted = 0;
    for (const auto& sub : to_delete) {
        if (RegDeleteTreeW(hParent.get(), sub.c_str()) == ERROR_SUCCESS) {
            deleted++;
            Logger::debug(L"Deleted shell handler key: " + branch_path + L"\\" + sub);
        }
    }
    return deleted;
}

ShellCleanReport ShellCleaner::clean_shell_extensions(
    const std::wstring& target_root_path,
    std::wstring_view target_name
) {
    ShellCleanReport report;
    auto extensions = find_target_shell_extensions(target_root_path, target_name);

    std::vector<std::wstring> target_guids;
    target_guids.reserve(extensions.size());

    // 1. Delete CLSID registry trees
    for (const auto& ext : extensions) {
        target_guids.push_back(ext.clsid);
        UniqueHKey hParent;
        if (RegOpenKeyExW(ext.root_key, L"SOFTWARE\\Classes\\CLSID", 0,
                          KEY_WRITE | ext.sam_view, hParent.put()) == ERROR_SUCCESS) {
            if (RegDeleteTreeW(hParent.get(), ext.clsid.c_str()) == ERROR_SUCCESS) {
                report.clsids_deleted++;
                Logger::debug(L"Deleted COM CLSID: " + ext.clsid + L" (" + ext.module_path + L")");
            }
        }
    }

    const wchar_t* context_menu_roots[] = {
        L"SOFTWARE\\Classes\\*\\shellex\\ContextMenuHandlers",
        L"SOFTWARE\\Classes\\Directory\\shellex\\ContextMenuHandlers",
        L"SOFTWARE\\Classes\\Directory\\Background\\shellex\\ContextMenuHandlers",
        L"SOFTWARE\\Classes\\Folder\\shellex\\ContextMenuHandlers",
        L"SOFTWARE\\Classes\\Drive\\shellex\\ContextMenuHandlers"
    };

    const DWORD views[] = {KEY_WOW64_64KEY, KEY_WOW64_32KEY};

    // 2. Clean context menu handlers
    for (const auto* cm_path : context_menu_roots) {
        for (DWORD view : views) {
            report.context_menu_handlers_deleted += delete_matched_handler_subkeys(
                HKEY_LOCAL_MACHINE, cm_path, view, target_guids, target_name
            );
            report.context_menu_handlers_deleted += delete_matched_handler_subkeys(
                HKEY_CURRENT_USER, cm_path, view, target_guids, target_name
            );
        }
    }

    // 3. Clean ShellIconOverlayIdentifiers
    const wchar_t* overlay_path = L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ShellIconOverlayIdentifiers";
    for (DWORD view : views) {
        report.icon_overlays_deleted += delete_matched_handler_subkeys(
            HKEY_LOCAL_MACHINE, overlay_path, view, target_guids, target_name
        );
    }

    // 4. Clean Shell Extensions\Approved values
    const wchar_t* approved_path = L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Shell Extensions\\Approved";
    for (DWORD view : views) {
        UniqueHKey hApproved;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, approved_path, 0, KEY_READ | KEY_WRITE | view, hApproved.put()) == ERROR_SUCCESS) {
            for (const auto& g : target_guids) {
                if (RegDeleteValueW(hApproved.get(), g.c_str()) == ERROR_SUCCESS) {
                    report.approved_entries_deleted++;
                }
            }
        }
    }

    // Notify shell to flush memory cache
    notify_shell_cache_refresh();

    return report;
}

void ShellCleaner::notify_shell_cache_refresh() {
    SHChangeNotify(SHCNE_ASSOCCHANGED, SHCNF_IDLIST, nullptr, nullptr);
}

} // namespace obliterator
