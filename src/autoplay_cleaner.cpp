#include "obliterator/autoplay_cleaner.hpp"

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

bool AutoPlayCleaner::is_protected_handler(const std::wstring& handler_name) {
    if (handler_name.rfind(L"MS", 0) == 0 || handler_name.rfind(L"Windows", 0) == 0) {
        return true;
    }

    static const wchar_t* const kProtected[] = {
        L"ShowPicturesOnArrival",
        L"PlayMusicFilesOnArrival",
        L"PlayVideoFilesOnArrival",
        L"OpenFolderOnArrival",
        L"TakeNoAction"
    };

    for (const auto* p : kProtected) {
        if (_wcsicmp(handler_name.c_str(), p) == 0) {
            return true;
        }
    }

    return false;
}

bool AutoPlayCleaner::matches_target(const std::wstring& name, const Target& target) {
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

bool AutoPlayCleaner::path_references_target(const std::wstring& path, const Target& target) {
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

AutoPlayCleanReport AutoPlayCleaner::clean_autoplay_handlers(const Target& target, bool dry_run) {
    AutoPlayCleanReport report;
    const HKEY kRoots[] = { HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER };

    const wchar_t* const kHandlersPath =
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\AutoplayHandlers\\Handlers";
    const wchar_t* const kEventHandlersPath =
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\AutoplayHandlers\\EventHandlers";

    for (HKEY root : kRoots) {
        const REGSAM access = dry_run ? KEY_READ : (KEY_READ | KEY_WRITE);
        UniqueHKey hHandlers;
        if (RegOpenKeyExW(root, kHandlersPath, 0, access, hHandlers.put()) != ERROR_SUCCESS) {
            continue;
        }

        DWORD subkey_count = 0;
        DWORD max_subkey_len = 0;
        if (RegQueryInfoKeyW(hHandlers.get(), nullptr, nullptr, nullptr, &subkey_count,
                             &max_subkey_len, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) {
            continue;
        }

        std::vector<wchar_t> name_buf(max_subkey_len + 2, L'\0');
        std::vector<std::wstring> handlers_to_delete;

        for (DWORD i = 0; i < subkey_count; ++i) {
            DWORD len = static_cast<DWORD>(name_buf.size());
            if (RegEnumKeyExW(hHandlers.get(), i, name_buf.data(), &len, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) {
                continue;
            }

            const std::wstring handler_name(name_buf.data(), len);
            if (is_protected_handler(handler_name)) {
                continue;
            }

            UniqueHKey hSub;
            if (RegOpenKeyExW(hHandlers.get(), handler_name.c_str(), 0, KEY_READ, hSub.put()) != ERROR_SUCCESS) {
                continue;
            }

            bool matched = matches_target(handler_name, target);

            if (!matched) {
                wchar_t prov_buf[MAX_PATH] = { 0 };
                DWORD prov_len = sizeof(prov_buf);
                DWORD type = 0;
                if (RegQueryValueExW(hSub.get(), L"Provider", nullptr, &type,
                                     reinterpret_cast<BYTE*>(prov_buf), &prov_len) == ERROR_SUCCESS &&
                    type == REG_SZ) {
                    if (matches_target(prov_buf, target)) {
                        matched = true;
                    }
                }
            }

            if (!matched) {
                wchar_t icon_buf[MAX_PATH] = { 0 };
                DWORD icon_len = sizeof(icon_buf);
                DWORD type = 0;
                if (RegQueryValueExW(hSub.get(), L"DefaultIcon", nullptr, &type,
                                     reinterpret_cast<BYTE*>(icon_buf), &icon_len) == ERROR_SUCCESS &&
                    (type == REG_SZ || type == REG_EXPAND_SZ)) {
                    if (path_references_target(icon_buf, target)) {
                        matched = true;
                    }
                }
            }

            if (!matched) {
                wchar_t progid_buf[MAX_PATH] = { 0 };
                DWORD progid_len = sizeof(progid_buf);
                DWORD type = 0;
                if (RegQueryValueExW(hSub.get(), L"InvokeProgID", nullptr, &type,
                                     reinterpret_cast<BYTE*>(progid_buf), &progid_len) == ERROR_SUCCESS &&
                    type == REG_SZ) {
                    if (matches_target(progid_buf, target)) {
                        matched = true;
                    }
                }
            }

            if (matched) {
                handlers_to_delete.push_back(handler_name);
            }
        }

        for (const auto& h : handlers_to_delete) {
            if (!dry_run) {
                RegDeleteTreeW(hHandlers.get(), h.c_str());
            }
            ++report.autoplay_handlers_removed;
            report.details.push_back(L"AutoPlay Handler: " + h);
        }

        // Clean event bindings
        if (!handlers_to_delete.empty()) {
            UniqueHKey hEvents;
            if (RegOpenKeyExW(root, kEventHandlersPath, 0, access, hEvents.put()) == ERROR_SUCCESS) {
                DWORD ev_count = 0;
                DWORD max_ev_len = 0;
                if (RegQueryInfoKeyW(hEvents.get(), nullptr, nullptr, nullptr, &ev_count,
                                     &max_ev_len, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr) == ERROR_SUCCESS) {
                    std::vector<wchar_t> ev_buf(max_ev_len + 2, L'\0');
                    for (DWORD i = 0; i < ev_count; ++i) {
                        DWORD elen = static_cast<DWORD>(ev_buf.size());
                        if (RegEnumKeyExW(hEvents.get(), i, ev_buf.data(), &elen, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) {
                            continue;
                        }

                        const std::wstring event_name(ev_buf.data(), elen);
                        UniqueHKey hEvSub;
                        if (RegOpenKeyExW(hEvents.get(), event_name.c_str(), 0, access, hEvSub.put()) != ERROR_SUCCESS) {
                            continue;
                        }

                        for (const auto& h : handlers_to_delete) {
                            if (RegQueryValueExW(hEvSub.get(), h.c_str(), nullptr, nullptr, nullptr, nullptr) == ERROR_SUCCESS) {
                                if (!dry_run) {
                                    RegDeleteValueW(hEvSub.get(), h.c_str());
                                }
                                ++report.event_bindings_removed;
                                report.details.push_back(L"AutoPlay Event Binding: " + event_name + L" -> " + h);
                            }
                        }
                    }
                }
            }
        }
    }

    return report;
}

} // namespace obliterator
