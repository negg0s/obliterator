#include "obliterator/aedebug_cleaner.hpp"

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

bool AeDebugCleaner::path_references_target(const std::wstring& path, const Target& target) {
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

AeDebugCleanReport AeDebugCleaner::clean_aedebug(const Target& target, bool dry_run) {
    AeDebugCleanReport report;
    const HKEY kRoots[] = { HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER };
    const wchar_t* const kAeDebugPaths[] = {
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AeDebug",
        L"SOFTWARE\\WOW6432Node\\Microsoft\\Windows NT\\CurrentVersion\\AeDebug"
    };

    const wchar_t* const kDefaultWer = L"\"%SystemRoot%\\system32\\werfault.exe\" -u -p %ld -e %ld";
    const wchar_t* const kDefaultAuto = L"1";

    for (HKEY root : kRoots) {
        for (const auto* dbg_path : kAeDebugPaths) {
            const REGSAM access = dry_run ? KEY_READ : (KEY_READ | KEY_WRITE);
            UniqueHKey hKey;
            if (RegOpenKeyExW(root, dbg_path, 0, access, hKey.put()) != ERROR_SUCCESS) {
                continue;
            }

            wchar_t dbg_buf[1024] = { 0 };
            DWORD dbg_len = sizeof(dbg_buf);
            DWORD type = 0;
            if (RegQueryValueExW(hKey.get(), L"Debugger", nullptr, &type,
                                 reinterpret_cast<BYTE*>(dbg_buf), &dbg_len) == ERROR_SUCCESS &&
                type == REG_SZ) {
                const std::wstring current_dbg(dbg_buf);
                if (path_references_target(current_dbg, target)) {
                    if (!dry_run) {
                        RegSetValueExW(hKey.get(), L"Debugger", 0, REG_SZ,
                                       reinterpret_cast<const BYTE*>(kDefaultWer),
                                       static_cast<DWORD>((wcslen(kDefaultWer) + 1) * sizeof(wchar_t)));
                        RegSetValueExW(hKey.get(), L"Auto", 0, REG_SZ,
                                       reinterpret_cast<const BYTE*>(kDefaultAuto),
                                       static_cast<DWORD>((wcslen(kDefaultAuto) + 1) * sizeof(wchar_t)));
                    }
                    ++report.aedebug_hooks_reset;
                    report.details.push_back(L"Reset AeDebug post-mortem handler: " + current_dbg);
                }
            }
        }
    }

    return report;
}

} // namespace obliterator
