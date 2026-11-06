#include "obliterator/event_log_cleaner.hpp"

#include "obliterator/handles.hpp"
#include "obliterator/log.hpp"
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
    DWORD type = 0;
    if (RegQueryValueExW(target_hkey, value_name, nullptr, &type, nullptr, &bytes) == ERROR_SUCCESS && bytes > 0) {
        std::vector<wchar_t> buf((bytes / sizeof(wchar_t)) + 2, L'\0');
        if (RegQueryValueExW(target_hkey, value_name, nullptr, &type,
                             reinterpret_cast<LPBYTE>(buf.data()), &bytes) == ERROR_SUCCESS) {
            if (type == REG_EXPAND_SZ) {
                wchar_t exp_buf[MAX_PATH * 2] = {0};
                if (ExpandEnvironmentStringsW(buf.data(), exp_buf, MAX_PATH * 2) > 0) {
                    result = exp_buf;
                } else {
                    result = buf.data();
                }
            } else {
                result = buf.data();
            }
        }
    }
    return result;
}

bool EventLogCleaner::is_protected_event_source(const std::wstring& source) {
    static const wchar_t* const kProtectedSources[] = {
        L"application error", L"application hang", L"windows error reporting",
        L"msiinstaller", L"esent", L"desktop window manager", L"service control manager",
        L"kernel-general", L"eventlog", L"plugplaymanager", L"security-spp", L"vss",
        L"winlogon", L"user profile service", L"group policy", L"ntfs", L"disk",
        L"volmgr", L"tcpip", L"dhcp-client", L"dnsapi", L"sidebyside", L".net runtime"
    };

    const std::wstring lower = PathHelper::to_lower_unicode(source);
    if (lower.starts_with(L"microsoft-windows-") || lower.starts_with(L"microsoft.windows.")) {
        return true;
    }

    for (const auto* s : kProtectedSources) {
        if (lower == s) {
            return true;
        }
    }
    return false;
}

bool EventLogCleaner::path_references_target(const std::wstring& path, const Target& target) {
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

void EventLogCleaner::clean_classic_sources(const Target& target, bool dry_run, EventLogCleanReport& report) {
    const wchar_t* const kChannels[] = {
        L"SYSTEM\\CurrentControlSet\\Services\\EventLog\\Application",
        L"SYSTEM\\CurrentControlSet\\Services\\EventLog\\System"
    };

    for (const auto* channel_path : kChannels) {
        UniqueHKey hChannel;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, channel_path, 0, KEY_READ | KEY_WRITE, hChannel.put()) != ERROR_SUCCESS) {
            if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, channel_path, 0, KEY_READ, hChannel.put()) != ERROR_SUCCESS) {
                continue;
            }
        }

        DWORD subkey_count = 0;
        DWORD max_subkey_len = 0;
        if (RegQueryInfoKeyW(hChannel.get(), nullptr, nullptr, nullptr, &subkey_count,
                             &max_subkey_len, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) {
            continue;
        }

        std::vector<wchar_t> name_buf(max_subkey_len + 2, L'\0');
        std::vector<std::wstring> matched_sources;

        for (DWORD i = 0; i < subkey_count; ++i) {
            DWORD len = static_cast<DWORD>(name_buf.size());
            if (RegEnumKeyExW(hChannel.get(), i, name_buf.data(), &len,
                              nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) {
                continue;
            }

            const std::wstring src_name(name_buf.data(), len);
            if (is_protected_event_source(src_name)) {
                continue;
            }

            UniqueHKey hSrc;
            if (RegOpenKeyExW(hChannel.get(), src_name.c_str(), 0, KEY_READ, hSrc.put()) != ERROR_SUCCESS) {
                continue;
            }

            const std::wstring event_msg_file = read_reg_string_value(hSrc.get(), nullptr, L"EventMessageFile");
            const std::wstring cat_msg_file = read_reg_string_value(hSrc.get(), nullptr, L"CategoryMessageFile");

            bool matched = false;
            if (path_references_target(event_msg_file, target) || path_references_target(cat_msg_file, target)) {
                matched = true;
            } else if (!target.name.empty() && string_contains_ignore_case(src_name, target.name)) {
                matched = true;
            }

            if (matched) {
                matched_sources.push_back(src_name);
            }
        }

        for (const auto& src : matched_sources) {
            if (!dry_run) {
                RegDeleteTreeW(hChannel.get(), src.c_str());
            }
            ++report.event_sources_removed;
            report.details.push_back(std::wstring(channel_path) + L"\\" + src);
        }
    }
}

void EventLogCleaner::clean_etw_publishers(const Target& target, bool dry_run, EventLogCleanReport& report) {
    const wchar_t* const kPublishersPath = L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WINEVT\\Publishers";
    UniqueHKey hPubs;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, kPublishersPath, 0, KEY_READ | KEY_WRITE, hPubs.put()) != ERROR_SUCCESS) {
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, kPublishersPath, 0, KEY_READ, hPubs.put()) != ERROR_SUCCESS) {
            return;
        }
    }

    DWORD subkey_count = 0;
    DWORD max_subkey_len = 0;
    if (RegQueryInfoKeyW(hPubs.get(), nullptr, nullptr, nullptr, &subkey_count,
                         &max_subkey_len, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) {
        return;
    }

    std::vector<wchar_t> name_buf(max_subkey_len + 2, L'\0');
    std::vector<std::wstring> matched_publishers;

    for (DWORD i = 0; i < subkey_count; ++i) {
        DWORD len = static_cast<DWORD>(name_buf.size());
        if (RegEnumKeyExW(hPubs.get(), i, name_buf.data(), &len,
                          nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) {
            continue;
        }

        const std::wstring guid_str(name_buf.data(), len);
        UniqueHKey hGuid;
        if (RegOpenKeyExW(hPubs.get(), guid_str.c_str(), 0, KEY_READ, hGuid.put()) != ERROR_SUCCESS) {
            continue;
        }

        const std::wstring res_file = read_reg_string_value(hGuid.get(), nullptr, L"ResourceFileName");
        const std::wstring msg_file = read_reg_string_value(hGuid.get(), nullptr, L"MessageFileName");

        bool matched = false;
        if (path_references_target(res_file, target) || path_references_target(msg_file, target)) {
            matched = true;
        }

        if (matched) {
            matched_publishers.push_back(guid_str);
        }
    }

    for (const auto& guid : matched_publishers) {
        if (!dry_run) {
            RegDeleteTreeW(hPubs.get(), guid.c_str());
        }
        ++report.etw_publishers_removed;
        report.details.push_back(L"ETW Publisher: " + guid);
    }
}

EventLogCleanReport EventLogCleaner::clean_event_log_sources(const Target& target, bool dry_run) {
    EventLogCleanReport report;
    clean_classic_sources(target, dry_run, report);
    clean_etw_publishers(target, dry_run, report);
    return report;
}

} // namespace obliterator
