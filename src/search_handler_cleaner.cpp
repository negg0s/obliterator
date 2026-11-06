#include "obliterator/search_handler_cleaner.hpp"

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

bool SearchHandlerCleaner::is_protected_protocol(const std::wstring& protocol) {
    static const wchar_t* const kProtected[] = {
        L"file",
        L"mapi",
        L"csc",
        L"iehistory",
        L"onenote",
        L"imapi"
    };

    for (const auto* p : kProtected) {
        if (_wcsicmp(protocol.c_str(), p) == 0) {
            return true;
        }
    }

    return false;
}

bool SearchHandlerCleaner::matches_target(const std::wstring& name, const Target& target) {
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

bool SearchHandlerCleaner::inspect_clsid_server(HKEY root, const std::wstring& clsid_str, const Target& target) {
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
        const std::wstring lib_path(path_buf);
        if (!target.root_path.empty()) {
            if (PathHelper::contains_path_reference(lib_path, target.root_path)) {
                return true;
            }
            const std::wstring norm_path = SafetyValidator::normalize_path(lib_path);
            if (PathHelper::is_same_or_subpath(target.root_path, norm_path)) {
                return true;
            }
        }
        if (!target.name.empty() && target.name.length() >= 3) {
            if (string_contains_ignore_case(lib_path, target.name)) {
                return true;
            }
        }
    }

    return false;
}

SearchHandlerCleanReport SearchHandlerCleaner::clean_search_handlers(const Target& target, bool dry_run) {
    SearchHandlerCleanReport report;
    const HKEY kRoots[] = { HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER };
    const wchar_t* const kSearchHandlersPath = L"SOFTWARE\\Microsoft\\Windows Search\\ProtocolHandlers";

    for (HKEY root : kRoots) {
        const REGSAM access = dry_run ? KEY_READ : (KEY_READ | KEY_WRITE);
        UniqueHKey hHandlers;
        if (RegOpenKeyExW(root, kSearchHandlersPath, 0, access, hHandlers.put()) != ERROR_SUCCESS) {
            continue;
        }

        DWORD val_count = 0;
        DWORD max_val_len = 0;
        DWORD max_data_len = 0;
        if (RegQueryInfoKeyW(hHandlers.get(), nullptr, nullptr, nullptr, nullptr, nullptr,
                             nullptr, &val_count, &max_val_len, &max_data_len, nullptr, nullptr) != ERROR_SUCCESS) {
            continue;
        }

        std::vector<wchar_t> name_buf(max_val_len + 2, L'\0');
        std::vector<wchar_t> data_buf((max_data_len / sizeof(wchar_t)) + 2, L'\0');

        struct HandlerDeleteTarget {
            std::wstring protocol_name;
            std::wstring clsid;
        };
        std::vector<HandlerDeleteTarget> to_delete;

        for (DWORD i = 0; i < val_count; ++i) {
            DWORD len = static_cast<DWORD>(name_buf.size());
            DWORD dlen = static_cast<DWORD>(data_buf.size() * sizeof(wchar_t));
            DWORD type = 0;

            if (RegEnumValueW(hHandlers.get(), i, name_buf.data(), &len, nullptr, &type,
                              reinterpret_cast<BYTE*>(data_buf.data()), &dlen) != ERROR_SUCCESS) {
                continue;
            }

            const std::wstring proto_name(name_buf.data(), len);
            if (is_protected_protocol(proto_name)) {
                continue;
            }

            std::wstring clsid_str;
            if (type == REG_SZ && dlen >= sizeof(wchar_t)) {
                clsid_str = data_buf.data();
            }

            bool matched = matches_target(proto_name, target);
            if (!matched && !clsid_str.empty()) {
                matched = inspect_clsid_server(root, clsid_str, target);
            }

            if (matched) {
                to_delete.push_back({proto_name, clsid_str});
            }
        }

        for (const auto& item : to_delete) {
            if (!dry_run) {
                RegDeleteValueW(hHandlers.get(), item.protocol_name.c_str());
                if (!item.clsid.empty()) {
                    const std::wstring full_clsid_key = L"Software\\Classes\\CLSID\\" + item.clsid;
                    RegDeleteTreeW(root, full_clsid_key.c_str());
                }
            }
            ++report.protocol_handlers_removed;
            report.details.push_back(L"Search Protocol Handler: " + item.protocol_name);
        }
    }

    return report;
}

} // namespace obliterator
