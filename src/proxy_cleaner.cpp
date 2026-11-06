#include "obliterator/proxy_cleaner.hpp"

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

bool ProxyCleaner::path_references_target(const std::wstring& path, const Target& target) {
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

bool ProxyCleaner::matches_proxy_target(const Target& target) {
    static const wchar_t* const kProxyKeywords[] = {
        L"proxy", L"fiddler", L"charles", L"burp", L"vpn",
        L"shadowsocks", L"v2ray", L"clash", L"privoxy", L"mitmproxy", L"tor"
    };

    const std::wstring lower_name = PathHelper::to_lower_unicode(target.name);
    for (const auto* kw : kProxyKeywords) {
        if (lower_name.find(kw) != std::wstring::npos) {
            return true;
        }
    }

    const std::wstring lower_root = PathHelper::to_lower_unicode(target.root_path);
    for (const auto* kw : kProxyKeywords) {
        if (lower_root.find(kw) != std::wstring::npos) {
            return true;
        }
    }

    return false;
}

void ProxyCleaner::notify_wininet() {
    HMODULE hWinInet = LoadLibraryExW(L"wininet.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (!hWinInet) {
        return;
    }

    using InternetSetOptionW_fn = BOOL(WINAPI*)(HANDLE, DWORD, LPVOID, DWORD);
    auto pfnInternetSetOptionW = reinterpret_cast<InternetSetOptionW_fn>(
        reinterpret_cast<void*>(GetProcAddress(hWinInet, "InternetSetOptionW")));

    if (pfnInternetSetOptionW) {
        constexpr DWORD kSettingsChanged = 39; // INTERNET_OPTION_SETTINGS_CHANGED
        constexpr DWORD kRefresh = 37;         // INTERNET_OPTION_REFRESH
        pfnInternetSetOptionW(nullptr, kSettingsChanged, nullptr, 0);
        pfnInternetSetOptionW(nullptr, kRefresh, nullptr, 0);
    }

    FreeLibrary(hWinInet);
}

ProxyCleanReport ProxyCleaner::clean_proxy_settings(const Target& target, bool dry_run) {
    ProxyCleanReport report;
    const wchar_t* const kInternetSettings = L"Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings";
    const HKEY kRoots[] = { HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE };

    bool did_reset = false;
    const bool is_proxy_app = matches_proxy_target(target);

    for (HKEY root : kRoots) {
        const REGSAM access = dry_run ? KEY_READ : (KEY_READ | KEY_WRITE);
        UniqueHKey hKey;
        if (RegOpenKeyExW(root, kInternetSettings, 0, access, hKey.put()) != ERROR_SUCCESS) {
            continue;
        }

        // 1. Check AutoConfigURL
        wchar_t auto_url_buf[1024] = { 0 };
        DWORD auto_url_len = sizeof(auto_url_buf);
        DWORD type = 0;
        bool auto_url_matches = false;

        if (RegQueryValueExW(hKey.get(), L"AutoConfigURL", nullptr, &type,
                             reinterpret_cast<BYTE*>(auto_url_buf), &auto_url_len) == ERROR_SUCCESS &&
            type == REG_SZ) {
            const std::wstring auto_url(auto_url_buf);
            if (path_references_target(auto_url, target) ||
                (is_proxy_app && (string_contains_ignore_case(auto_url, L"127.0.0.1") ||
                                  string_contains_ignore_case(auto_url, L"localhost")))) {
                auto_url_matches = true;
                if (!dry_run) {
                    RegDeleteValueW(hKey.get(), L"AutoConfigURL");
                }
                ++report.proxy_settings_reset;
                report.details.push_back(L"Reset AutoConfigURL: " + auto_url);
                did_reset = true;
            }
        }

        // 2. Check ProxyEnable & ProxyServer
        DWORD proxy_enable = 0;
        DWORD enable_len = sizeof(proxy_enable);
        if (RegQueryValueExW(hKey.get(), L"ProxyEnable", nullptr, &type,
                             reinterpret_cast<BYTE*>(&proxy_enable), &enable_len) == ERROR_SUCCESS &&
            type == REG_DWORD && proxy_enable != 0) {

            wchar_t server_buf[1024] = { 0 };
            DWORD server_len = sizeof(server_buf);
            std::wstring proxy_server;
            if (RegQueryValueExW(hKey.get(), L"ProxyServer", nullptr, &type,
                                 reinterpret_cast<BYTE*>(server_buf), &server_len) == ERROR_SUCCESS &&
                type == REG_SZ) {
                proxy_server = server_buf;
            }

            bool should_disable = false;
            if (auto_url_matches) {
                should_disable = true;
            } else if (!proxy_server.empty() && path_references_target(proxy_server, target)) {
                should_disable = true;
            } else if (is_proxy_app && (string_contains_ignore_case(proxy_server, L"127.0.0.1") ||
                                       string_contains_ignore_case(proxy_server, L"localhost"))) {
                should_disable = true;
            }

            if (should_disable) {
                if (!dry_run) {
                    DWORD zero = 0;
                    RegSetValueExW(hKey.get(), L"ProxyEnable", 0, REG_DWORD,
                                   reinterpret_cast<const BYTE*>(&zero), sizeof(zero));
                    if (!proxy_server.empty()) {
                        RegDeleteValueW(hKey.get(), L"ProxyServer");
                    }
                }
                ++report.proxy_settings_reset;
                report.details.push_back(L"Disabled ProxyEnable and cleared ProxyServer: " + proxy_server);
                did_reset = true;
            }
        }
    }

    if (did_reset && !dry_run) {
        notify_wininet();
    }

    return report;
}

} // namespace obliterator
