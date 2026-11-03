#include "obliterator/diagnose.hpp"
#include "obliterator/error.hpp"
#include "obliterator/handles.hpp"
#include "obliterator/privileges.hpp"

#include <windows.h>
#include <tlhelp32.h>
#include <sddl.h>

#include <algorithm>
#include <cwctype>
#include <fstream>
#include <sstream>
#include <vector>

namespace obliterator {

static std::wstring query_reg_string(HKEY root, const wchar_t* subkey, const wchar_t* value_name) {
    UniqueHKey key;
    if (RegOpenKeyExW(root, subkey, 0, KEY_READ, key.put()) != ERROR_SUCCESS) {
        return {};
    }
    DWORD type = 0;
    DWORD bytes = 0;
    if (RegQueryValueExW(key.get(), value_name, nullptr, &type, nullptr, &bytes) != ERROR_SUCCESS) {
        return {};
    }
    std::wstring result(bytes / sizeof(wchar_t), L'\0');
    if (RegQueryValueExW(key.get(), value_name, nullptr, &type,
                         reinterpret_cast<LPBYTE>(result.data()), &bytes) != ERROR_SUCCESS) {
        return {};
    }
    while (!result.empty() && result.back() == L'\0') {
        result.pop_back();
    }
    return result;
}

static DWORD query_reg_dword(HKEY root, const wchar_t* subkey, const wchar_t* value_name, DWORD default_val = 0) {
    UniqueHKey key;
    if (RegOpenKeyExW(root, subkey, 0, KEY_READ, key.put()) != ERROR_SUCCESS) {
        return default_val;
    }
    DWORD type = 0;
    DWORD val = 0;
    DWORD bytes = sizeof(DWORD);
    if (RegQueryValueExW(key.get(), value_name, nullptr, &type,
                         reinterpret_cast<LPBYTE>(&val), &bytes) == ERROR_SUCCESS && type == REG_DWORD) {
        return val;
    }
    return default_val;
}

std::wstring SystemDiagnostics::sanitize_pii(const std::wstring& input) {
    std::wstring result = input;

    // Get current username
    wchar_t user_buf[256]{};
    DWORD user_len = 256;
    if (GetUserNameW(user_buf, &user_len) && user_len > 1) {
        std::wstring username = user_buf;
        size_t pos = 0;
        while ((pos = result.find(username, pos)) != std::wstring::npos) {
            result.replace(pos, username.length(), L"<user>");
            pos += 6;
        }
    }

    // Sanitize user profiles in C:\Users\<name>
    size_t users_pos = 0;
    while ((users_pos = result.find(L"\\Users\\", users_pos)) != std::wstring::npos) {
        size_t name_start = users_pos + 7;
        size_t next_slash = result.find(L'\\', name_start);
        size_t end_pos = (next_slash != std::wstring::npos) ? next_slash : result.size();
        std::wstring raw_user = result.substr(name_start, end_pos - name_start);
        if (raw_user != L"<user>" && raw_user != L"Public" && raw_user != L"Default" && raw_user != L"All Users") {
            result.replace(name_start, raw_user.length(), L"<user>");
        }
        users_pos = name_start + 6;
    }

    // Sanitize user SIDs (e.g. S-1-5-21-...)
    size_t sid_pos = 0;
    while ((sid_pos = result.find(L"S-1-5-21-", sid_pos)) != std::wstring::npos) {
        size_t sid_end = sid_pos + 9;
        while (sid_end < result.size() && (std::iswdigit(result[sid_end]) || result[sid_end] == L'-')) {
            sid_end++;
        }
        result.replace(sid_pos, sid_end - sid_pos, L"<user-sid>");
        sid_pos += 10;
    }

    return result;
}

Result<std::wstring> SystemDiagnostics::collect_report() {
    std::wostringstream oss;

    oss << L"================================================================================\n";
    oss << L" Obliterator Diagnostic Report\n";
    oss << L" Generated for bug reporting and stubborn uninstall investigation.\n";
    oss << L" Personal identifiers (usernames, domain SIDs) are sanitized to <user>.\n";
    oss << L"================================================================================\n\n";

    // 1. Operating System Details
    const wchar_t* cv_key = L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion";
    std::wstring prod_name = query_reg_string(HKEY_LOCAL_MACHINE, cv_key, L"ProductName");
    std::wstring display_ver = query_reg_string(HKEY_LOCAL_MACHINE, cv_key, L"DisplayVersion");
    std::wstring current_build = query_reg_string(HKEY_LOCAL_MACHINE, cv_key, L"CurrentBuild");
    DWORD ubr = query_reg_dword(HKEY_LOCAL_MACHINE, cv_key, L"UBR", 0);
    std::wstring install_type = query_reg_string(HKEY_LOCAL_MACHINE, cv_key, L"InstallationType");

    oss << L"[Operating System]\n";
    oss << L"Product Name:        " << (prod_name.empty() ? L"(Windows)" : prod_name) << L"\n";
    oss << L"Display Version:     " << (display_ver.empty() ? L"(Unknown)" : display_ver) << L"\n";
    oss << L"Build Number:        " << (current_build.empty() ? L"0" : current_build);
    if (ubr > 0) {
        oss << L"." << ubr;
    }
    oss << L"\n";
    oss << L"Installation Type:   " << (install_type.empty() ? L"Client" : install_type) << L"\n";
    oss << L"\n";

    // 2. Token Elevation and Process Privileges
    oss << L"[Process Privileges and Elevation]\n";
    HANDLE hTokenRaw = INVALID_HANDLE_VALUE;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hTokenRaw)) {
        UniqueHandle hToken(hTokenRaw);
        TOKEN_ELEVATION elevation{};
        DWORD ret_len = 0;
        if (GetTokenInformation(hToken.get(), TokenElevation, &elevation, sizeof(elevation), &ret_len)) {
            oss << L"Elevated Token:      " << (elevation.TokenIsElevated ? L"Yes (Administrator)" : L"No (Standard User)") << L"\n";
        }

        // Check specific key privileges
        auto check_priv = [&](const wchar_t* priv_name) -> const wchar_t* {
            LUID luid{};
            if (!LookupPrivilegeValueW(nullptr, priv_name, &luid)) {
                return L"Unavailable";
            }
            PRIVILEGE_SET ps{};
            ps.PrivilegeCount = 1;
            ps.Control = PRIVILEGE_SET_ALL_NECESSARY;
            ps.Privilege[0].Luid = luid;
            ps.Privilege[0].Attributes = SE_PRIVILEGE_ENABLED;
            BOOL has_priv = FALSE;
            if (PrivilegeCheck(hToken.get(), &ps, &has_priv) && has_priv) {
                return L"Enabled";
            }
            return L"Disabled / Not Held";
        };

        oss << L"SeDebugPrivilege:         " << check_priv(SE_DEBUG_NAME) << L"\n";
        oss << L"SeBackupPrivilege:        " << check_priv(SE_BACKUP_NAME) << L"\n";
        oss << L"SeRestorePrivilege:       " << check_priv(SE_RESTORE_NAME) << L"\n";
        oss << L"SeTakeOwnershipPrivilege: " << check_priv(SE_TAKE_OWNERSHIP_NAME) << L"\n";
        oss << L"SeLoadDriverPrivilege:    " << check_priv(SE_LOAD_DRIVER_NAME) << L"\n";
    } else {
        oss << L"Unable to inspect process token (Error: " << GetLastError() << L")\n";
    }
    oss << L"\n";

    // 3. Security and Real-Time Protection State
    oss << L"[Real-Time Protection and Security Services]\n";
    const wchar_t* rtp_key = L"SOFTWARE\\Microsoft\\Windows Defender\\Real-Time Protection";
    DWORD rtp_disabled = query_reg_dword(HKEY_LOCAL_MACHINE, rtp_key, L"DisableRealtimeMonitoring", 0);
    oss << L"Defender Real-Time Monitor: " << (rtp_disabled == 1 ? L"Disabled" : L"Active / Enabled") << L"\n";

    const wchar_t* tamper_key = L"SOFTWARE\\Microsoft\\Windows Defender\\Features";
    DWORD tamper = query_reg_dword(HKEY_LOCAL_MACHINE, tamper_key, L"TamperProtection", 0);
    oss << L"Tamper Protection:          " << (tamper != 0 ? L"Active (5)" : L"Disabled / Not Configured") << L"\n";

    // Enumerate registered AMSI providers count
    UniqueHKey amsi_key;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\AMSI\\Providers", 0, KEY_READ, amsi_key.put()) == ERROR_SUCCESS) {
        DWORD num_subkeys = 0;
        if (RegQueryInfoKeyW(amsi_key.get(), nullptr, nullptr, nullptr, &num_subkeys, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr) == ERROR_SUCCESS) {
            oss << L"Registered AMSI Providers:  " << num_subkeys << L"\n";
        }
    }
    oss << L"\n";

    // 4. Protected Processes and Critical Security Daemons
    oss << L"[Running Security & Protected Processes]\n";
    UniqueHandle snap(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
    if (snap.is_valid()) {
        PROCESSENTRY32W pe{};
        pe.dwSize = sizeof(pe);
        if (Process32FirstW(snap.get(), &pe)) {
            size_t count = 0;
            do {
                std::wstring exe_name = pe.szExeFile;
                std::wstring lower_exe = exe_name;
                std::transform(lower_exe.begin(), lower_exe.end(), lower_exe.begin(), ::towlower);

                bool is_security = (lower_exe == L"msmpeng.exe" || lower_exe == L"nissrv.exe" ||
                                    lower_exe == L"securityhealthservice.exe" || lower_exe == L"smartscreen.exe" ||
                                    lower_exe == L"csfalconservice.exe" || lower_exe == L"edpa.exe" ||
                                    lower_exe == L"vgc.exe" || lower_exe == L"easyanticheat.exe" ||
                                    lower_exe == L"beservice.exe");

                // Check process access limit
                UniqueHandle hProc(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe.th32ProcessID));
                bool access_denied = (!hProc.is_valid());

                if (is_security || (pe.th32ProcessID > 4 && access_denied)) {
                    oss << L"  PID " << pe.th32ProcessID << L": " << exe_name;
                    if (is_security) {
                        oss << L" [Security Component]";
                    }
                    if (access_denied) {
                        oss << L" [Access Denied / Protected]";
                    }
                    oss << L"\n";
                    count++;
                }
            } while (Process32NextW(snap.get(), &pe));
            if (count == 0) {
                oss << L"  (No protected security processes identified)\n";
            }
        }
    }
    oss << L"\n";

    oss << L"[Troubleshooting Guidance]\n";
    oss << L"If an application or service resists deletion:\n";
    oss << L"1. Ensure obliterator is running in an elevated administrative command prompt.\n";
    oss << L"2. Run: obliterator <target> --dry-run --json > plan.json\n";
    oss << L"3. If protected kernel drivers or anti-cheat services lock files, check Safe Mode:\n";
    oss << L"   obliterator <target> --safe-mode-plan\n";
    oss << L"================================================================================\n";

    std::wstring report = sanitize_pii(oss.str());
    return report;
}

Result<void> SystemDiagnostics::write_report_to_file(const std::wstring& file_path) {
    auto report_res = collect_report();
    if (!report_res) {
        return report_res.error();
    }

    const std::wstring& report_text = report_res.value();
    std::ofstream out(file_path, std::ios::out | std::ios::binary);
    if (!out.is_open()) {
        return Win32Error::from_code(ERROR_CANNOT_MAKE);
    }

    // Convert wide string to UTF-8
    int utf8_size = WideCharToMultiByte(CP_UTF8, 0, report_text.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (utf8_size > 0) {
        std::string utf8_buf(utf8_size, '\0');
        WideCharToMultiByte(CP_UTF8, 0, report_text.c_str(), -1, utf8_buf.data(), utf8_size, nullptr, nullptr);
        if (!utf8_buf.empty() && utf8_buf.back() == '\0') {
            utf8_buf.pop_back();
        }
        out.write(utf8_buf.data(), utf8_buf.size());
    }

    out.close();
    return Result<void>::success();
}

} // namespace obliterator
