#include "obliterator/uninstaller.hpp"
#include "obliterator/handles.hpp"
#include "obliterator/log.hpp"
#include "obliterator/path.hpp"
#include "obliterator/safety.hpp"
#include "obliterator/wiper.hpp"

#include <algorithm>
#include <cwctype>
#include <filesystem>
#include <string_view>
#include <vector>

namespace obliterator {

static std::wstring to_lower(std::wstring_view sv) {
    std::wstring s(sv);
    std::transform(s.begin(), s.end(), s.begin(), [](wchar_t c) {
        return static_cast<wchar_t>(std::towlower(c));
    });
    return s;
}

static std::wstring_view trim_sv(std::wstring_view sv) {
    while (!sv.empty() && (sv.front() == L' ' || sv.front() == L'\t' || sv.front() == L'\r' || sv.front() == L'\n')) {
        sv.remove_prefix(1);
    }
    while (!sv.empty() && (sv.back() == L' ' || sv.back() == L'\t' || sv.back() == L'\r' || sv.back() == L'\n')) {
        sv.remove_suffix(1);
    }
    return sv;
}

ParsedUninstallCommand NativeUninstaller::parse_command(std::wstring_view cmd) {
    ParsedUninstallCommand result;
    cmd = trim_sv(cmd);
    result.raw_command = std::wstring(cmd);
    if (cmd.empty()) {
        return result;
    }

    if (cmd.front() == L'\"') {
        size_t end_quote = cmd.find(L'\"', 1);
        if (end_quote != std::wstring_view::npos) {
            result.executable_path = std::wstring(cmd.substr(1, end_quote - 1));
            result.arguments = std::wstring(trim_sv(cmd.substr(end_quote + 1)));
            result.is_valid = true;
            return result;
        }
        result.executable_path = std::wstring(cmd.substr(1));
        result.is_valid = true;
        return result;
    }

    std::wstring lower_cmd = to_lower(cmd);

    // Check for msiexec invocations without quotes
    if (lower_cmd.starts_with(L"msiexec.exe") || lower_cmd.starts_with(L"msiexec ")) {
        size_t space_pos = cmd.find(L' ');
        if (space_pos != std::wstring_view::npos) {
            result.executable_path = std::wstring(cmd.substr(0, space_pos));
            result.arguments = std::wstring(trim_sv(cmd.substr(space_pos + 1)));
        } else {
            result.executable_path = std::wstring(cmd);
        }
        result.is_valid = true;
        return result;
    }

    // Check for rundll32 invocations without quotes
    if (lower_cmd.starts_with(L"rundll32.exe") || lower_cmd.starts_with(L"rundll32 ")) {
        size_t space_pos = cmd.find(L' ');
        if (space_pos != std::wstring_view::npos) {
            result.executable_path = std::wstring(cmd.substr(0, space_pos));
            result.arguments = std::wstring(trim_sv(cmd.substr(space_pos + 1)));
        } else {
            result.executable_path = std::wstring(cmd);
        }
        result.is_valid = true;
        return result;
    }

    // Find .exe boundary
    size_t search_pos = 0;
    while (true) {
        size_t exe_pos = lower_cmd.find(L".exe", search_pos);
        if (exe_pos == std::wstring_view::npos) {
            break;
        }
        size_t after_exe = exe_pos + 4;
        if (after_exe == cmd.size() || cmd[after_exe] == L' ' || cmd[after_exe] == L'\t' || cmd[after_exe] == L'\"') {
            result.executable_path = std::wstring(cmd.substr(0, after_exe));
            result.arguments = std::wstring(trim_sv(cmd.substr(after_exe)));
            result.is_valid = true;
            return result;
        }
        search_pos = after_exe;
    }

    size_t first_space = cmd.find(L' ');
    if (first_space != std::wstring_view::npos) {
        result.executable_path = std::wstring(cmd.substr(0, first_space));
        result.arguments = std::wstring(trim_sv(cmd.substr(first_space + 1)));
    } else {
        result.executable_path = std::wstring(cmd);
    }
    result.is_valid = true;
    return result;
}

std::wstring NativeUninstaller::extract_product_code(std::wstring_view cmd) {
    size_t open_brace = cmd.find(L'{');
    while (open_brace != std::wstring_view::npos) {
        size_t close_brace = cmd.find(L'}', open_brace);
        if (close_brace != std::wstring_view::npos && (close_brace - open_brace) == 37) {
            // Validate standard GUID format: {8-4-4-4-12}
            std::wstring_view candidate = cmd.substr(open_brace, 38);
            if (candidate[9] == L'-' && candidate[14] == L'-' &&
                candidate[19] == L'-' && candidate[24] == L'-') {
                bool valid = true;
                for (size_t i = 1; i < 37; ++i) {
                    if (i == 9 || i == 14 || i == 19 || i == 24) continue;
                    wchar_t c = candidate[i];
                    if (!std::iswxdigit(c)) {
                        valid = false;
                        break;
                    }
                }
                if (valid) {
                    std::wstring guid(candidate);
                    std::transform(guid.begin(), guid.end(), guid.begin(), [](wchar_t c) {
                        return static_cast<wchar_t>(std::towupper(c));
                    });
                    return guid;
                }
            }
        }
        open_brace = cmd.find(L'{', open_brace + 1);
    }
    return {};
}

UninstallerType NativeUninstaller::detect_pe_signature(const std::wstring& exe_path) {
    if (exe_path.empty()) {
        return UninstallerType::None;
    }

    std::wstring ext_path = FileWiper::ensure_extended_path(exe_path);
    UniqueHandle hFile(CreateFileW(
        ext_path.c_str(),
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr
    ));

    if (!hFile) {
        return UninstallerType::None;
    }

    constexpr size_t kScanSize = 1024 * 1024; // 1 MB
    std::vector<char> buffer(kScanSize);
    DWORD bytes_read = 0;
    if (!ReadFile(hFile.get(), buffer.data(), static_cast<DWORD>(buffer.size()), &bytes_read, nullptr) || bytes_read == 0) {
        return UninstallerType::None;
    }
    buffer.resize(bytes_read);

    std::string_view content(buffer.data(), buffer.size());

    // Inno Setup signature markers
    if (content.find("Inno Setup Setup Data") != std::string_view::npos ||
        content.find("Inno Setup: Setup Version") != std::string_view::npos ||
        content.find("Inno Setup Messages") != std::string_view::npos) {
        return UninstallerType::InnoSetup;
    }

    // NSIS signature markers
    if (content.find("Nullsoft.NSIS.exehead") != std::string_view::npos ||
        content.find("NullsoftInst") != std::string_view::npos) {
        return UninstallerType::Nsis;
    }

    // InstallShield signature markers
    if (content.find("InstallShield") != std::string_view::npos ||
        content.find("_isdel.exe") != std::string_view::npos ||
        content.find("ISSetup.dll") != std::string_view::npos) {
        return UninstallerType::InstallShield;
    }

    return UninstallerType::None;
}

NativeUninstallerInfo NativeUninstaller::detect_from_strings(
    const std::wstring& uninstall_str,
    const std::wstring& quiet_uninstall_str,
    const std::wstring& install_loc,
    const std::wstring& display_name
) {
    (void)install_loc;
    NativeUninstallerInfo info;
    info.raw_uninstall_string = uninstall_str;
    info.raw_quiet_string = quiet_uninstall_str;
    info.display_name = display_name;

    // 1. Check for MSI (Windows Installer)
    std::wstring product_code = extract_product_code(quiet_uninstall_str);
    if (product_code.empty()) {
        product_code = extract_product_code(uninstall_str);
    }

    std::wstring lower_uninst = to_lower(uninstall_str);
    std::wstring lower_quiet = to_lower(quiet_uninstall_str);

    if (!product_code.empty() && (lower_uninst.find(L"msiexec") != std::wstring::npos ||
                                  lower_quiet.find(L"msiexec") != std::wstring::npos ||
                                  uninstall_str.starts_with(L"{"))) {
        info.type = UninstallerType::Msi;
        info.product_code = product_code;
        info.quiet_command = L"msiexec.exe /x " + product_code + L" /qn /norestart";
        return info;
    }

    // Determine target command to inspect
    std::wstring candidate_cmd = !quiet_uninstall_str.empty() ? quiet_uninstall_str : uninstall_str;
    if (candidate_cmd.empty()) {
        info.type = UninstallerType::None;
        return info;
    }

    ParsedUninstallCommand parsed = parse_command(candidate_cmd);
    std::wstring exe_name = to_lower(std::filesystem::path(parsed.executable_path).filename().wstring());

    // 2. Check for Inno Setup (unins000.exe, unins001.exe, etc.)
    bool is_inno_pattern = false;
    if (exe_name.starts_with(L"unins") && exe_name.ends_with(L".exe") && exe_name.size() > 9) {
        std::wstring_view mid = std::wstring_view(exe_name).substr(5, exe_name.size() - 9);
        is_inno_pattern = !mid.empty() && std::all_of(mid.begin(), mid.end(), [](wchar_t c) {
            return c >= L'0' && c <= L'9';
        });
    }
    if (is_inno_pattern || lower_uninst.find(L"inno setup") != std::wstring::npos) {
        info.type = UninstallerType::InnoSetup;
        info.quiet_command = L"\"" + parsed.executable_path + L"\" /VERYSILENT /SUPPRESSMSGBOXES /NORESTART";
        return info;
    }

    // 3. Check for NSIS
    if (exe_name == L"uninst.exe" || exe_name == L"uninstall.exe" || exe_name == L"uninstaller.exe" ||
        lower_uninst.find(L"nsis") != std::wstring::npos) {
        UninstallerType pe_type = detect_pe_signature(parsed.executable_path);
        if (pe_type == UninstallerType::InnoSetup) {
            info.type = UninstallerType::InnoSetup;
            info.quiet_command = L"\"" + parsed.executable_path + L"\" /VERYSILENT /SUPPRESSMSGBOXES /NORESTART";
            return info;
        }
        if (pe_type == UninstallerType::Nsis ||
            exe_name == L"uninst.exe" ||
            lower_uninst.find(L"nsis") != std::wstring::npos ||
            lower_uninst.find(L"_?=") != std::wstring::npos ||
            lower_uninst.find(L"/s") != std::wstring::npos) {
            info.type = UninstallerType::Nsis;
            info.quiet_command = L"\"" + parsed.executable_path + L"\" /S";
            return info;
        }
    }

    // 4. Check for InstallShield
    if (exe_name == L"setup.exe" || exe_name == L"_isdel.exe" || exe_name == L"isuninst.exe" ||
        lower_uninst.find(L"installshield") != std::wstring::npos) {
        info.type = UninstallerType::InstallShield;
        if (parsed.arguments.find(L"/v") != std::wstring::npos) {
            info.quiet_command = L"\"" + parsed.executable_path + L"\" /s /v\"/qn /norestart\"";
        } else {
            info.quiet_command = L"\"" + parsed.executable_path + L"\" /s";
        }
        return info;
    }

    // 5. Inspect PE signature directly on disk if executable exists
    UninstallerType pe_type = detect_pe_signature(parsed.executable_path);
    if (pe_type == UninstallerType::InnoSetup) {
        info.type = UninstallerType::InnoSetup;
        info.quiet_command = L"\"" + parsed.executable_path + L"\" /VERYSILENT /SUPPRESSMSGBOXES /NORESTART";
        return info;
    }
    if (pe_type == UninstallerType::Nsis) {
        info.type = UninstallerType::Nsis;
        info.quiet_command = L"\"" + parsed.executable_path + L"\" /S";
        return info;
    }
    if (pe_type == UninstallerType::InstallShield) {
        info.type = UninstallerType::InstallShield;
        info.quiet_command = L"\"" + parsed.executable_path + L"\" /s /v\"/qn /norestart\"";
        return info;
    }

    // 6. Check if vendor provided a QuietUninstallString
    if (!quiet_uninstall_str.empty()) {
        ParsedUninstallCommand quiet_parsed = parse_command(quiet_uninstall_str);
        std::wstring lower_args = to_lower(quiet_parsed.arguments);
        if (lower_args.find(L"/verysilent") != std::wstring::npos ||
            lower_args.find(L"/silent") != std::wstring::npos ||
            lower_args.find(L"/s") != std::wstring::npos ||
            lower_args.find(L"/qn") != std::wstring::npos ||
            lower_args.find(L"/quiet") != std::wstring::npos) {
            info.type = UninstallerType::InnoSetup;
            info.quiet_command = quiet_uninstall_str;
            return info;
        }
    }

    info.type = UninstallerType::Unknown;
    return info;
}

NativeUninstallerInfo NativeUninstaller::detect(const Target& target) {
    if (target.is_uwp) {
        NativeUninstallerInfo info;
        info.type = UninstallerType::Uwp;
        info.package_full_name = target.uwp_package_full_name;
        info.package_family_name = target.uwp_package_family_name;
        info.display_name = target.name;
        return info;
    }

    std::wstring uninst_str = target.uninstall_string;
    std::wstring quiet_str = target.quiet_uninstall_string;
    std::wstring install_loc = target.root_path;

    // If strings not populated directly in Target, query from registry entries
    if (uninst_str.empty() && quiet_str.empty()) {
        for (const auto& reg : target.registry_entries) {
            UniqueHKey key;
            if (RegOpenKeyExW(reg.root_key, reg.subkey_path.c_str(), 0, KEY_READ | reg.sam_view, key.put()) == ERROR_SUCCESS) {
                auto query_str = [&](const wchar_t* val_name) -> std::wstring {
                    DWORD bytes = 0;
                    DWORD type = 0;
                    if (RegQueryValueExW(key.get(), val_name, nullptr, &type, nullptr, &bytes) == ERROR_SUCCESS && bytes > 0) {
                        std::wstring val(bytes / sizeof(wchar_t), L'\0');
                        if (RegQueryValueExW(key.get(), val_name, nullptr, &type,
                                            reinterpret_cast<LPBYTE>(val.data()), &bytes) == ERROR_SUCCESS) {
                            while (!val.empty() && val.back() == L'\0') {
                                val.pop_back();
                            }
                            return val;
                        }
                    }
                    return {};
                };

                if (uninst_str.empty()) {
                    uninst_str = query_str(L"UninstallString");
                }
                if (quiet_str.empty()) {
                    quiet_str = query_str(L"QuietUninstallString");
                }
                if (!uninst_str.empty() || !quiet_str.empty()) {
                    break;
                }
            }
        }
    }

    return detect_from_strings(uninst_str, quiet_str, install_loc, target.name);
}

Result<void> NativeUninstaller::execute_with_timeout(
    const NativeUninstallerInfo& info,
    uint32_t timeout_seconds
) {
    if (info.type == UninstallerType::None || info.type == UninstallerType::Unknown) {
        return Win32Error::from_code(ERROR_NOT_SUPPORTED);
    }

    if (info.quiet_command.empty()) {
        return Win32Error::from_code(ERROR_INVALID_PARAMETER);
    }

    Logger::info(L"Launching native uninstaller (" + std::wstring(type_name(info.type)) +
                 L"): " + info.quiet_command);

    UniqueHandle hJob(CreateJobObjectW(nullptr, nullptr));
    if (!hJob) {
        return Win32Error::last();
    }

    JOBOBJECT_EXTENDED_LIMIT_INFORMATION jeli{};
    jeli.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    SetInformationJobObject(
        hJob.get(),
        JobObjectExtendedLimitInformation,
        &jeli,
        sizeof(jeli)
    );

    STARTUPINFOW si{};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;

    PROCESS_INFORMATION pi{};
    std::wstring cmd_writable = info.quiet_command;

    BOOL ok = CreateProcessW(
        nullptr,
        cmd_writable.data(),
        nullptr,
        nullptr,
        FALSE,
        CREATE_SUSPENDED | CREATE_NEW_PROCESS_GROUP | CREATE_NO_WINDOW,
        nullptr,
        nullptr,
        &si,
        &pi
    );

    if (!ok) {
        DWORD err = GetLastError();
        Logger::error(L"Failed to launch native uninstaller: " + std::to_wstring(err));
        return Win32Error::from_code(err);
    }

    UniqueHandle hProcess(pi.hProcess);
    UniqueHandle hThread(pi.hThread);

    AssignProcessToJobObject(hJob.get(), hProcess.get());
    ResumeThread(hThread.get());

    const DWORD timeout_ms = (timeout_seconds == 0) ? INFINITE : (timeout_seconds * 1000);
    DWORD wait_res = WaitForSingleObject(hProcess.get(), timeout_ms);

    if (wait_res == WAIT_TIMEOUT) {
        Logger::warn(L"Native uninstaller timed out after " + std::to_wstring(timeout_seconds) +
                    L" seconds; terminating uninstaller process tree...");
        TerminateJobObject(hJob.get(), 1);
        TerminateProcess(hProcess.get(), 1);
        WaitForSingleObject(hProcess.get(), 5000);
        return Win32Error::from_code(ERROR_TIMEOUT);
    }

    DWORD exit_code = 0;
    GetExitCodeProcess(hProcess.get(), &exit_code);
    Logger::info(L"Native uninstaller completed with exit code: " + std::to_wstring(exit_code));

    if (exit_code == 3010 || exit_code == 1641) {
        Logger::info(L"Native uninstaller reported reboot required (code " +
                     std::to_wstring(exit_code) + L")");
    }

    return Result<void>::success();
}

const wchar_t* NativeUninstaller::type_name(UninstallerType type) {
    switch (type) {
        case UninstallerType::Msi: return L"MSI";
        case UninstallerType::InnoSetup: return L"Inno Setup";
        case UninstallerType::Nsis: return L"NSIS";
        case UninstallerType::InstallShield: return L"InstallShield";
        case UninstallerType::Uwp: return L"UWP / Microsoft Store";
        case UninstallerType::Unknown: return L"Unknown";
        case UninstallerType::None: default: return L"None";
    }
}

} // namespace obliterator
