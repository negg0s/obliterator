#include "obliterator/ui.hpp"
#include "obliterator/handles.hpp"
#include "obliterator/registry_cleaner.hpp"
#include "obliterator/target.hpp"
#include "obliterator/uwp.hpp"
#include "obliterator/wiper.hpp"

#include <conio.h>

#include <algorithm>
#include <cwctype>
#include <filesystem>
#include <iostream>
#include <vector>

namespace obliterator {

static std::wstring query_ui_reg_string(HKEY key, const wchar_t* val_name) {
    DWORD type = 0;
    DWORD bytes = 0;
    LSTATUS st = RegQueryValueExW(key, val_name, nullptr, &type, nullptr, &bytes);
    if (st != ERROR_SUCCESS || bytes == 0 || (type != REG_SZ && type != REG_EXPAND_SZ)) {
        return {};
    }

    std::wstring buf(bytes / sizeof(wchar_t), L'\0');
    st = RegQueryValueExW(key, val_name, nullptr, &type,
                          reinterpret_cast<LPBYTE>(buf.data()), &bytes);
    if (st != ERROR_SUCCESS) {
        return {};
    }

    while (!buf.empty() && buf.back() == L'\0') {
        buf.pop_back();
    }
    return buf;
}

static DWORD query_ui_reg_dword(HKEY key, const wchar_t* val_name) {
    DWORD type = 0;
    DWORD val = 0;
    DWORD bytes = sizeof(DWORD);
    LSTATUS st = RegQueryValueExW(key, val_name, nullptr, &type,
                                  reinterpret_cast<LPBYTE>(&val), &bytes);
    if (st == ERROR_SUCCESS && type == REG_DWORD) {
        return val;
    }
    return 0;
}

static std::wstring format_date_str(std::wstring raw) {
    if (raw.size() == 8) {
        bool all_digits = true;
        for (wchar_t c : raw) {
            if (!std::iswdigit(c)) {
                all_digits = false;
                break;
            }
        }
        if (all_digits) {
            return raw.substr(0, 4) + L"-" + raw.substr(4, 2) + L"-" + raw.substr(6, 2);
        }
    }
    if (!raw.empty()) {
        return raw;
    }
    return L"----";
}

std::vector<InstalledAppInfo> UserInterface::enumerate_installed_apps() {
    std::vector<InstalledAppInfo> apps;

    struct Scope {
        HKEY root;
        const wchar_t* subkey;
        REGSAM sam;
    };

    const Scope scopes[] = {
        {HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall", KEY_WOW64_64KEY},
        {HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall", KEY_WOW64_32KEY},
        {HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall", 0}
    };

    for (const auto& s : scopes) {
        UniqueHKey root_key;
        if (RegOpenKeyExW(s.root, s.subkey, 0, KEY_READ | s.sam, root_key.put()) != ERROR_SUCCESS) {
            continue;
        }

        DWORD idx = 0;
        wchar_t sub_name[256];
        DWORD sub_len = 256;

        while (true) {
            sub_len = 256;
            LSTATUS st = RegEnumKeyExW(root_key.get(), idx, sub_name, &sub_len,
                                       nullptr, nullptr, nullptr, nullptr);
            if (st == ERROR_NO_MORE_ITEMS) {
                break;
            }
            idx++;
            if (st != ERROR_SUCCESS) {
                continue;
            }

            UniqueHKey app_key;
            st = RegOpenKeyExW(root_key.get(), sub_name, 0, KEY_READ | s.sam, app_key.put());
            if (st != ERROR_SUCCESS) {
                continue;
            }

            if (query_ui_reg_dword(app_key.get(), L"SystemComponent") == 1) {
                continue;
            }

            const std::wstring display_name = query_ui_reg_string(app_key.get(), L"DisplayName");
            if (display_name.empty()) {
                continue;
            }

            const std::wstring publisher = query_ui_reg_string(app_key.get(), L"Publisher");
            const std::wstring install_loc = query_ui_reg_string(app_key.get(), L"InstallLocation");
            const std::wstring display_icon = query_ui_reg_string(app_key.get(), L"DisplayIcon");
            const std::wstring uninstall_str = query_ui_reg_string(app_key.get(), L"UninstallString");
            const DWORD is_win_installer = query_ui_reg_dword(app_key.get(), L"WindowsInstaller");

            const std::wstring deduced_root =
                TargetResolver::deduce_install_folder(install_loc, display_icon, uninstall_str);

            AppType app_type = AppType::Win32;
            std::wstring uninstall_lower = uninstall_str;
            std::transform(uninstall_lower.begin(), uninstall_lower.end(), uninstall_lower.begin(), ::towlower);
            if (is_win_installer == 1 || uninstall_lower.find(L"msiexec") != std::wstring::npos) {
                app_type = AppType::Msi;
            } else if (uninstall_str.empty() && !deduced_root.empty()) {
                app_type = AppType::Portable;
            }

            const DWORD est_size_kb = query_ui_reg_dword(app_key.get(), L"EstimatedSize");
            uint64_t size_bytes = static_cast<uint64_t>(est_size_kb) * 1024ULL;

            std::wstring raw_date = query_ui_reg_string(app_key.get(), L"InstallDate");
            std::wstring install_date = format_date_str(raw_date);

            if (install_date == L"----" && !deduced_root.empty()) {
                WIN32_FILE_ATTRIBUTE_DATA fad{};
                if (GetFileAttributesExW(deduced_root.c_str(), GetFileExInfoStandard, &fad)) {
                    SYSTEMTIME st_time{};
                    if (FileTimeToSystemTime(&fad.ftCreationTime, &st_time)) {
                        wchar_t buf[32];
                        swprintf_s(buf, L"%04u-%02u-%02u", st_time.wYear, st_time.wMonth, st_time.wDay);
                        install_date = buf;
                    }
                }
            }

            bool duplicate = false;
            for (auto& existing : apps) {
                if (_wcsicmp(existing.name.c_str(), display_name.c_str()) == 0) {
                    if (existing.size_bytes == 0 && size_bytes > 0) {
                        existing.size_bytes = size_bytes;
                    }
                    if (existing.root_path.empty() && !deduced_root.empty()) {
                        existing.root_path = deduced_root;
                    }
                    if (existing.publisher.empty() && !publisher.empty()) {
                        existing.publisher = publisher;
                    }
                    duplicate = true;
                    break;
                }
                if (!deduced_root.empty() &&
                    !existing.root_path.empty() &&
                    _wcsicmp(existing.root_path.c_str(), deduced_root.c_str()) == 0) {
                    duplicate = true;
                    break;
                }
            }

            if (!duplicate) {
                apps.push_back({
                    display_name,
                    publisher,
                    install_loc,
                    install_date,
                    size_bytes,
                    deduced_root,
                    app_type,
                    uninstall_str,
                    false,
                    L"",
                    L""
                });
            }
        }
    }

    const auto uwp_apps = UwpManager::enumerate_packages();
    for (const auto& uwp : uwp_apps) {
        apps.push_back({
            L"[UWP] " + uwp.display_name,
            L"Microsoft Store",
            uwp.install_location,
            uwp.install_date,
            uwp.size_bytes,
            uwp.install_location,
            AppType::Store,
            L"",
            true,
            uwp.full_name,
            uwp.family_name
        });
    }

    std::sort(apps.begin(), apps.end(), [](const InstalledAppInfo& a, const InstalledAppInfo& b) {
        if (a.size_bytes != b.size_bytes) {
            return a.size_bytes > b.size_bytes;
        }
        return a.name < b.name;
    });

    return apps;
}

std::optional<InstalledAppInfo> UserInterface::select_app_interactive(
    const std::vector<InstalledAppInfo>& apps) {
    if (apps.empty()) {
        std::wcout << L"No installed applications found in registry.\n";
        return std::nullopt;
    }

    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD orig_mode = 0;
    GetConsoleMode(hOut, &orig_mode);
    SetConsoleMode(hOut, orig_mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);

    // Hide console cursor
    std::wcout << L"\x1b[?25l";

    size_t selected = 0;
    const size_t total = apps.size();
    const size_t page_size = 15;

    auto render = [&]() {
        std::wcout << L"\x1b[2J\x1b[H";
        std::wcout << L"================================================================================\n";
        std::wcout << L" Obliterator - Installed Applications (sorted by size)\n";
        std::wcout << L" Use Up/Down arrows to navigate, Enter to select, Esc to cancel.\n";
        std::wcout << L"================================================================================\n";
        std::wcout << L"   #   Application Name                          Size         Installed\n";
        std::wcout << L"--------------------------------------------------------------------------------\n";

        size_t start = (selected / page_size) * page_size;
        size_t end = std::min(start + page_size, total);

        for (size_t i = start; i < end; ++i) {
            const auto& app = apps[i];
            std::wstring trunc_name = app.name;
            if (trunc_name.size() > 38) {
                trunc_name = trunc_name.substr(0, 35) + L"...";
            }

            std::wstring size_str = (app.size_bytes > 0)
                                    ? FileWiper::format_bytes(app.size_bytes)
                                    : L"----";

            wchar_t line_buf[256];
            swprintf_s(line_buf, L" %3zu   %-38s  %10s   %10s",
                       i + 1, trunc_name.c_str(), size_str.c_str(), app.install_date.c_str());

            if (i == selected) {
                std::wcout << L"\x1b[7m>" << line_buf << L" \x1b[0m\n";
            } else {
                std::wcout << L" " << line_buf << L"\n";
            }
        }

        std::wcout << L"--------------------------------------------------------------------------------\n";
        std::wcout << L" Item " << (selected + 1) << L" of " << total;
        if (!apps[selected].root_path.empty()) {
            std::wcout << L" | Path: " << apps[selected].root_path;
        }
        std::wcout << L"\n";
        std::wcout.flush();
    };

    while (true) {
        render();

        int ch = _getch();
        if (ch == 0 || ch == 224) {
            int code = _getch();
            if (code == 72) {
                if (selected > 0) selected--;
                else selected = total - 1;
            } else if (code == 80) {
                if (selected + 1 < total) selected++;
                else selected = 0;
            } else if (code == 73) {
                if (selected >= page_size) selected -= page_size;
                else selected = 0;
            } else if (code == 81) {
                if (selected + page_size < total) selected += page_size;
                else selected = total - 1;
            } else if (code == 71) {
                selected = 0;
            } else if (code == 79) {
                selected = total - 1;
            }
        } else if (ch == 13) {
            break;
        } else if (ch == 27 || ch == 'q' || ch == 'Q') {
            std::wcout << L"\x1b[?25h\n";
            SetConsoleMode(hOut, orig_mode);
            return std::nullopt;
        }
    }

    std::wcout << L"\x1b[?25h\x1b[2J\x1b[H";
    SetConsoleMode(hOut, orig_mode);

    const auto& chosen = apps[selected];
    std::wcout << L"Selected: " << chosen.name << L"\n";
    if (!chosen.root_path.empty()) {
        std::wcout << L"Location: " << chosen.root_path << L"\n";
    }

    if (!prompt_confirmation(chosen.name)) {
        std::wcout << L"Cancelled by user.\n";
        return std::nullopt;
    }

    return chosen;
}

bool UserInterface::prompt_confirmation(const std::wstring& app_name) {
    std::wcout << L"Are you sure you want to completely obliterate \"" << app_name << L"\"? [y/N]: ";
    std::wcout.flush();

    std::wstring line;
    if (std::getline(std::wcin, line)) {
        if (!line.empty() && (line[0] == L'y' || line[0] == L'Y')) {
            return true;
        }
    }
    return false;
}

Result<void> UserInterface::install_context_menu() {
    wchar_t exe_path[MAX_PATH]{};
    DWORD len = GetModuleFileNameW(nullptr, exe_path, MAX_PATH);
    if (len == 0 || len >= MAX_PATH) {
        return Win32Error::last();
    }

    const wchar_t* targets[] = {
        L"Software\\Classes\\Directory\\shell\\Obliterator",
        L"Software\\Classes\\Directory\\Background\\shell\\Obliterator"
    };

    const std::wstring cmd_str = L"\"" + std::wstring(exe_path) + L"\" \"%V\"";

    for (const auto* target_sub : targets) {
        UniqueHKey key;
        LSTATUS st = RegCreateKeyExW(HKEY_CURRENT_USER, target_sub, 0, nullptr,
                                     0, KEY_WRITE, nullptr, key.put(), nullptr);
        if (st != ERROR_SUCCESS) {
            return Win32Error::from_code(st);
        }

        const std::wstring label = L"Force Obliterate";
        RegSetValueExW(key.get(), nullptr, 0, REG_SZ,
                       reinterpret_cast<const BYTE*>(label.c_str()),
                       static_cast<DWORD>((label.size() + 1) * sizeof(wchar_t)));
        RegSetValueExW(key.get(), L"Icon", 0, REG_SZ,
                       reinterpret_cast<const BYTE*>(exe_path),
                       static_cast<DWORD>((wcslen(exe_path) + 1) * sizeof(wchar_t)));

        UniqueHKey cmd_key;
        st = RegCreateKeyExW(key.get(), L"command", 0, nullptr,
                             0, KEY_WRITE, nullptr, cmd_key.put(), nullptr);
        if (st != ERROR_SUCCESS) {
            return Win32Error::from_code(st);
        }

        RegSetValueExW(cmd_key.get(), nullptr, 0, REG_SZ,
                       reinterpret_cast<const BYTE*>(cmd_str.c_str()),
                       static_cast<DWORD>((cmd_str.size() + 1) * sizeof(wchar_t)));
    }

    return Result<void>::success();
}

Result<void> UserInterface::uninstall_context_menu() {
    RegistryCleaner::delete_key_tree(HKEY_CURRENT_USER, L"Software\\Classes\\Directory\\shell\\Obliterator");
    RegistryCleaner::delete_key_tree(HKEY_CURRENT_USER, L"Software\\Classes\\Directory\\Background\\shell\\Obliterator");
    return Result<void>::success();
}

} // namespace obliterator
