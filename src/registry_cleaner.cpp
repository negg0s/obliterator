#include "obliterator/registry_cleaner.hpp"
#include "obliterator/log.hpp"
#include "obliterator/path.hpp"
#include "obliterator/safety.hpp"

#include <algorithm>
#include <cwctype>
#include <filesystem>
#include <fstream>
#include <vector>

namespace obliterator {

static bool s_backup_enabled = true;
static std::wstring s_custom_backup_directory;
static std::wstring s_active_backup_directory;

static std::wstring to_lower(std::wstring_view input) {
    std::wstring result(input);
    std::transform(result.begin(), result.end(), result.begin(), [](wchar_t c) {
        return static_cast<wchar_t>(std::towlower(c));
    });
    return result;
}

static std::wstring sanitize_filename(std::wstring_view input) {
    std::wstring result;
    result.reserve(input.size());
    for (wchar_t c : input) {
        if (c == L'\\' || c == L'/' || c == L':' || c == L'*' ||
            c == L'?' || c == L'\"' || c == L'<' || c == L'>' || c == L'|') {
            result.push_back(L'_');
        } else {
            result.push_back(c);
        }
    }
    return result;
}

static const wchar_t* root_key_name(HKEY root) {
    if (root == HKEY_LOCAL_MACHINE) {
        return L"HKEY_LOCAL_MACHINE";
    }
    if (root == HKEY_CURRENT_USER) {
        return L"HKEY_CURRENT_USER";
    }
    if (root == HKEY_CLASSES_ROOT) {
        return L"HKEY_CLASSES_ROOT";
    }
    if (root == HKEY_USERS) {
        return L"HKEY_USERS";
    }
    return L"HKEY_UNKNOWN";
}

static const wchar_t* root_key_prefix_short(HKEY root) {
    if (root == HKEY_LOCAL_MACHINE) {
        return L"HKLM";
    }
    if (root == HKEY_CURRENT_USER) {
        return L"HKCU";
    }
    if (root == HKEY_CLASSES_ROOT) {
        return L"HKCR";
    }
    if (root == HKEY_USERS) {
        return L"HKU";
    }
    return L"HK";
}

static std::wstring query_reg_string(HKEY key, const wchar_t* val_name) {
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

static void serialize_key_recursive(HKEY hKey, const std::wstring& full_key_path,
                                    std::vector<wchar_t>& out) {
    auto append_str = [&](std::wstring_view s) {
        out.insert(out.end(), s.begin(), s.end());
    };

    append_str(L"\r\n[");
    append_str(full_key_path);
    append_str(L"]\r\n");

    DWORD val_index = 0;
    wchar_t val_name[256];
    DWORD val_name_len = 256;
    DWORD val_type = 0;
    DWORD val_bytes = 0;

    while (true) {
        val_name_len = 256;
        val_bytes = 0;
        LSTATUS st = RegEnumValueW(hKey, val_index, val_name, &val_name_len,
                                   nullptr, &val_type, nullptr, &val_bytes);
        if (st == ERROR_NO_MORE_ITEMS) {
            break;
        }
        if (st != ERROR_SUCCESS) {
            val_index++;
            continue;
        }

        std::vector<BYTE> data(val_bytes);
        val_name_len = 256;
        st = RegEnumValueW(hKey, val_index, val_name, &val_name_len,
                           nullptr, &val_type, data.data(), &val_bytes);
        val_index++;
        if (st != ERROR_SUCCESS) {
            continue;
        }

        if (val_name_len == 0) {
            append_str(L"@=");
        } else {
            append_str(L"\"");
            for (DWORD i = 0; i < val_name_len; ++i) {
                if (val_name[i] == L'\\' || val_name[i] == L'\"') {
                    out.push_back(L'\\');
                }
                out.push_back(val_name[i]);
            }
            append_str(L"\"=");
        }

        if (val_type == REG_SZ || val_type == REG_EXPAND_SZ) {
            const wchar_t* wdata = reinterpret_cast<const wchar_t*>(data.data());
            size_t wlen = val_bytes / sizeof(wchar_t);
            while (wlen > 0 && wdata[wlen - 1] == L'\0') {
                wlen--;
            }
            append_str(L"\"");
            for (size_t i = 0; i < wlen; ++i) {
                if (wdata[i] == L'\\' || wdata[i] == L'\"') {
                    out.push_back(L'\\');
                }
                out.push_back(wdata[i]);
            }
            append_str(L"\"\r\n");
        } else if (val_type == REG_DWORD && val_bytes >= sizeof(DWORD)) {
            DWORD dw = *reinterpret_cast<const DWORD*>(data.data());
            wchar_t hex_buf[32];
            swprintf_s(hex_buf, L"dword:%08x\r\n", dw);
            append_str(hex_buf);
        } else {
            wchar_t hex_prefix[32];
            if (val_type == REG_BINARY) {
                swprintf_s(hex_prefix, L"hex:");
            } else {
                swprintf_s(hex_prefix, L"hex(%x):", val_type);
            }
            append_str(hex_prefix);
            for (DWORD i = 0; i < val_bytes; ++i) {
                wchar_t byte_buf[8];
                swprintf_s(byte_buf, (i + 1 == val_bytes) ? L"%02x\r\n" : L"%02x,", data[i]);
                append_str(byte_buf);
            }
            if (val_bytes == 0) {
                append_str(L"\r\n");
            }
        }
    }

    DWORD sub_index = 0;
    wchar_t sub_name[256];
    DWORD sub_name_len = 256;

    while (true) {
        sub_name_len = 256;
        LSTATUS st = RegEnumKeyExW(hKey, sub_index, sub_name, &sub_name_len,
                                   nullptr, nullptr, nullptr, nullptr);
        if (st == ERROR_NO_MORE_ITEMS) {
            break;
        }
        sub_index++;
        if (st != ERROR_SUCCESS) {
            continue;
        }

        UniqueHKey child_key;
        st = RegOpenKeyExW(hKey, sub_name, 0, KEY_READ, child_key.put());
        if (st == ERROR_SUCCESS) {
            serialize_key_recursive(child_key.get(), full_key_path + L"\\" + sub_name, out);
        }
    }
}

void RegistryBackup::set_enabled(bool enabled) {
    s_backup_enabled = enabled;
}

bool RegistryBackup::is_enabled() {
    return s_backup_enabled;
}

void RegistryBackup::set_custom_backup_directory(const std::wstring& dir) {
    s_custom_backup_directory = dir;
    s_active_backup_directory.clear();
}

std::wstring RegistryBackup::get_backup_directory() {
    if (!s_active_backup_directory.empty()) {
        return s_active_backup_directory;
    }

    if (!s_custom_backup_directory.empty()) {
        s_active_backup_directory = s_custom_backup_directory;
        return s_active_backup_directory;
    }

    wchar_t local_app_data[MAX_PATH]{};
    DWORD len = ExpandEnvironmentStringsW(L"%LocalAppData%", local_app_data, MAX_PATH);
    std::wstring base_dir;
    if (len > 0 && len <= MAX_PATH) {
        base_dir = local_app_data;
    } else {
        base_dir = L"C:\\Temp";
    }

    SYSTEMTIME st{};
    GetLocalTime(&st);
    wchar_t ts[64];
    swprintf_s(ts, L"%04u-%02u-%02u_%02u-%02u-%02u",
               st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);

    s_active_backup_directory = base_dir + L"\\obliterator\\backup\\" + ts;
    return s_active_backup_directory;
}

Result<std::wstring> RegistryBackup::export_key(HKEY root, const std::wstring& subkey, REGSAM sam) {
    if (!s_backup_enabled) {
        return std::wstring{};
    }

    const std::wstring backup_dir = get_backup_directory();
    std::error_code ec;
    std::filesystem::create_directories(backup_dir, ec);

    const std::wstring file_name = std::wstring(root_key_prefix_short(root)) + L"_" +
                                   sanitize_filename(subkey) + L".reg";
    const std::wstring file_path = backup_dir + L"\\" + file_name;

    // First attempt: use reg.exe export
    wchar_t sys_dir[MAX_PATH]{};
    GetSystemDirectoryW(sys_dir, MAX_PATH);
    const std::wstring reg_exe = std::wstring(sys_dir) + L"\\reg.exe";

    std::wstring cmd = L"\"" + reg_exe + L"\" export \"" +
                       root_key_name(root) + L"\\" + subkey + L"\" \"" +
                       file_path + L"\" /y";
    if ((sam & KEY_WOW64_32KEY) != 0) {
        cmd += L" /reg:32";
    } else if ((sam & KEY_WOW64_64KEY) != 0) {
        cmd += L" /reg:64";
    }

    STARTUPINFOW si{};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;

    PROCESS_INFORMATION pi{};
    std::vector<wchar_t> cmd_buf(cmd.begin(), cmd.end());
    cmd_buf.push_back(L'\0');

    if (CreateProcessW(nullptr, cmd_buf.data(), nullptr, nullptr, FALSE,
                       CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
        WaitForSingleObject(pi.hProcess, 3000);
        DWORD exit_code = 1;
        GetExitCodeProcess(pi.hProcess, &exit_code);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);

        if (exit_code == 0 && std::filesystem::exists(file_path, ec) && !ec) {
            return file_path;
        }
    }

    // Fallback: direct serialization
    UniqueHKey key;
    LSTATUS st = RegOpenKeyExW(root, subkey.c_str(), 0, KEY_READ | sam, key.put());
    if (st != ERROR_SUCCESS) {
        return Win32Error::from_code(st);
    }

    std::vector<wchar_t> reg_content;
    const std::wstring header = L"Windows Registry Editor Version 5.00\r\n";
    reg_content.insert(reg_content.end(), header.begin(), header.end());

    serialize_key_recursive(key.get(), std::wstring(root_key_name(root)) + L"\\" + subkey,
                            reg_content);

    std::ofstream out(file_path, std::ios::binary);
    if (!out) {
        return Win32Error::from_code(ERROR_CAN_NOT_COMPLETE);
    }

    // Write UTF-16LE BOM
    const uint8_t bom[2] = {0xFF, 0xFE};
    out.write(reinterpret_cast<const char*>(bom), sizeof(bom));
    out.write(reinterpret_cast<const char*>(reg_content.data()),
              static_cast<std::streamsize>(reg_content.size() * sizeof(wchar_t)));

    return file_path;
}

Result<std::wstring> RegistryBackup::export_value(HKEY root, const std::wstring& subkey,
                                                  const std::wstring& value_name, REGSAM sam) {
    if (!s_backup_enabled) {
        return std::wstring{};
    }

    const std::wstring backup_dir = get_backup_directory();
    std::error_code ec;
    std::filesystem::create_directories(backup_dir, ec);

    const std::wstring file_name = std::wstring(root_key_prefix_short(root)) + L"_" +
                                   sanitize_filename(subkey) + L"_" +
                                   sanitize_filename(value_name) + L".reg";
    const std::wstring file_path = backup_dir + L"\\" + file_name;

    UniqueHKey key;
    LSTATUS st = RegOpenKeyExW(root, subkey.c_str(), 0, KEY_READ | sam, key.put());
    if (st != ERROR_SUCCESS) {
        return Win32Error::from_code(st);
    }

    DWORD val_type = 0;
    DWORD val_bytes = 0;
    st = RegQueryValueExW(key.get(), value_name.c_str(), nullptr, &val_type, nullptr, &val_bytes);
    if (st != ERROR_SUCCESS) {
        return Win32Error::from_code(st);
    }

    std::vector<BYTE> data(val_bytes);
    st = RegQueryValueExW(key.get(), value_name.c_str(), nullptr, &val_type,
                          data.data(), &val_bytes);
    if (st != ERROR_SUCCESS) {
        return Win32Error::from_code(st);
    }

    std::wstring reg_content = L"Windows Registry Editor Version 5.00\r\n\r\n[";
    reg_content += root_key_name(root);
    reg_content += L"\\";
    reg_content += subkey;
    reg_content += L"]\r\n\"";
    for (wchar_t c : value_name) {
        if (c == L'\\' || c == L'\"') {
            reg_content.push_back(L'\\');
        }
        reg_content.push_back(c);
    }
    reg_content += L"\"=";

    if (val_type == REG_SZ || val_type == REG_EXPAND_SZ) {
        const wchar_t* wdata = reinterpret_cast<const wchar_t*>(data.data());
        size_t wlen = val_bytes / sizeof(wchar_t);
        while (wlen > 0 && wdata[wlen - 1] == L'\0') {
            wlen--;
        }
        reg_content += L"\"";
        for (size_t i = 0; i < wlen; ++i) {
            if (wdata[i] == L'\\' || wdata[i] == L'\"') {
                reg_content.push_back(L'\\');
            }
            reg_content.push_back(wdata[i]);
        }
        reg_content += L"\"\r\n";
    } else if (val_type == REG_DWORD && val_bytes >= sizeof(DWORD)) {
        DWORD dw = *reinterpret_cast<const DWORD*>(data.data());
        wchar_t hex_buf[32];
        swprintf_s(hex_buf, L"dword:%08x\r\n", dw);
        reg_content += hex_buf;
    } else {
        wchar_t hex_prefix[32];
        swprintf_s(hex_prefix, L"hex(%x):", val_type);
        reg_content += hex_prefix;
        for (DWORD i = 0; i < val_bytes; ++i) {
            wchar_t byte_buf[8];
            swprintf_s(byte_buf, (i + 1 == val_bytes) ? L"%02x\r\n" : L"%02x,", data[i]);
            reg_content += byte_buf;
        }
        if (val_bytes == 0) {
            reg_content += L"\r\n";
        }
    }

    std::ofstream out(file_path, std::ios::binary);
    if (!out) {
        return Win32Error::from_code(ERROR_CAN_NOT_COMPLETE);
    }

    const uint8_t bom[2] = {0xFF, 0xFE};
    out.write(reinterpret_cast<const char*>(bom), sizeof(bom));
    out.write(reinterpret_cast<const char*>(reg_content.data()),
              static_cast<std::streamsize>(reg_content.size() * sizeof(wchar_t)));

    return file_path;
}

Result<void> RegistryCleaner::delete_key_tree(HKEY root, const std::wstring& subkey, REGSAM sam) {
    UniqueHKey key;
    LSTATUS status = RegOpenKeyExW(root, subkey.c_str(), 0,
                                   KEY_READ | KEY_WRITE | sam, key.put());
    if (status != ERROR_SUCCESS) {
        if (status == ERROR_FILE_NOT_FOUND) {
            return Result<void>::success();
        }
        return Win32Error::from_code(status);
    }

    while (true) {
        wchar_t child_name[256]{};
        DWORD child_len = 256;
        status = RegEnumKeyExW(key.get(), 0, child_name, &child_len,
                               nullptr, nullptr, nullptr, nullptr);
        if (status == ERROR_NO_MORE_ITEMS) {
            break;
        }
        if (status != ERROR_SUCCESS) {
            break;
        }
        delete_key_tree(key.get(), child_name, sam);
    }
    key.reset();

    const size_t slash_pos = subkey.rfind(L'\\');
    if (slash_pos == std::wstring::npos) {
        status = RegDeleteKeyExW(root, subkey.c_str(), sam, 0);
    } else {
        const std::wstring parent = subkey.substr(0, slash_pos);
        const std::wstring leaf = subkey.substr(slash_pos + 1);
        UniqueHKey parent_key;
        status = RegOpenKeyExW(root, parent.c_str(), 0, KEY_WRITE | sam, parent_key.put());
        if (status == ERROR_SUCCESS) {
            status = RegDeleteKeyExW(parent_key.get(), leaf.c_str(), sam, 0);
        }
    }

    if (status != ERROR_SUCCESS && status != ERROR_FILE_NOT_FOUND) {
        return Win32Error::from_code(status);
    }
    return Result<void>::success();
}

std::vector<AutorunEntry> RegistryCleaner::find_autorun_entries(const std::wstring& target_root) {
    std::vector<AutorunEntry> entries;
    if (target_root.empty()) {
        return entries;
    }

    struct Scope {
        HKEY root;
        const wchar_t* path;
        REGSAM sam;
    };

    const Scope scopes[] = {
        {HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0},
        {HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce", 0},
        {HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run", KEY_WOW64_64KEY},
        {HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run", KEY_WOW64_32KEY},
        {HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce", KEY_WOW64_64KEY},
        {HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce", KEY_WOW64_32KEY}
    };

    for (const auto& s : scopes) {
        UniqueHKey key;
        if (RegOpenKeyExW(s.root, s.path, 0, KEY_READ | s.sam, key.put()) != ERROR_SUCCESS) {
            continue;
        }

        DWORD index = 0;
        wchar_t val_name[256];
        DWORD val_len = 256;

        while (true) {
            val_len = 256;
            LSTATUS st = RegEnumValueW(key.get(), index, val_name, &val_len,
                                       nullptr, nullptr, nullptr, nullptr);
            if (st == ERROR_NO_MORE_ITEMS) {
                break;
            }
            index++;
            if (st != ERROR_SUCCESS) {
                continue;
            }

            const std::wstring cmd = query_reg_string(key.get(), val_name);
            if (PathHelper::contains_path_reference(cmd, target_root)) {
                entries.push_back({s.root, s.path, val_name, cmd, s.sam});
            }
        }
    }

    return entries;
}

std::vector<ShellVerbEntry> RegistryCleaner::find_shell_entries(const std::wstring& target_root) {
    std::vector<ShellVerbEntry> entries;
    if (target_root.empty()) {
        return entries;
    }

    const wchar_t* containers[] = {
        L"*\\shell",
        L"Directory\\shell",
        L"Directory\\Background\\shell",
        L"Drive\\shell",
        L"AllFilesystemObjects\\shell"
    };

    for (const auto* cont : containers) {
        UniqueHKey key;
        if (RegOpenKeyExW(HKEY_CLASSES_ROOT, cont, 0, KEY_READ, key.put()) != ERROR_SUCCESS) {
            continue;
        }

        DWORD idx = 0;
        wchar_t verb[256];
        DWORD verb_len = 256;

        while (true) {
            verb_len = 256;
            LSTATUS st = RegEnumKeyExW(key.get(), idx, verb, &verb_len,
                                       nullptr, nullptr, nullptr, nullptr);
            if (st == ERROR_NO_MORE_ITEMS) {
                break;
            }
            idx++;
            if (st != ERROR_SUCCESS) {
                continue;
            }

            const std::wstring verb_sub = std::wstring(cont) + L"\\" + verb;
            const std::wstring cmd_sub = verb_sub + L"\\command";

            UniqueHKey cmd_key;
            if (RegOpenKeyExW(HKEY_CLASSES_ROOT, cmd_sub.c_str(), 0, KEY_READ, cmd_key.put()) == ERROR_SUCCESS) {
                const std::wstring cmd = query_reg_string(cmd_key.get(), nullptr);
                if (PathHelper::contains_path_reference(cmd, target_root)) {
                    entries.push_back({HKEY_CLASSES_ROOT, verb_sub, cmd, false});
                }
            }
        }
    }

    const wchar_t* handler_containers[] = {
        L"*\\shellex\\ContextMenuHandlers",
        L"Directory\\shellex\\ContextMenuHandlers",
        L"Directory\\Background\\shellex\\ContextMenuHandlers"
    };

    for (const auto* cont : handler_containers) {
        UniqueHKey key;
        if (RegOpenKeyExW(HKEY_CLASSES_ROOT, cont, 0, KEY_READ, key.put()) != ERROR_SUCCESS) {
            continue;
        }

        DWORD idx = 0;
        wchar_t hname[256];
        DWORD hlen = 256;

        while (true) {
            hlen = 256;
            LSTATUS st = RegEnumKeyExW(key.get(), idx, hname, &hlen,
                                       nullptr, nullptr, nullptr, nullptr);
            if (st == ERROR_NO_MORE_ITEMS) {
                break;
            }
            idx++;
            if (st != ERROR_SUCCESS) {
                continue;
            }

            const std::wstring handler_path = std::wstring(cont) + L"\\" + hname;
            UniqueHKey h_key;
            if (RegOpenKeyExW(HKEY_CLASSES_ROOT, handler_path.c_str(), 0, KEY_READ, h_key.put()) != ERROR_SUCCESS) {
                continue;
            }

            const std::wstring clsid_str = query_reg_string(h_key.get(), nullptr);
            if (clsid_str.starts_with(L"{")) {
                const std::wstring clsid_sub = L"CLSID\\" + clsid_str;
                const std::wstring inproc_sub = clsid_sub + L"\\InprocServer32";
                UniqueHKey inproc_key;
                if (RegOpenKeyExW(HKEY_CLASSES_ROOT, inproc_sub.c_str(), 0, KEY_READ, inproc_key.put()) == ERROR_SUCCESS) {
                    const std::wstring dll_path = query_reg_string(inproc_key.get(), nullptr);
                    if (PathHelper::contains_path_reference(dll_path, target_root)) {
                        entries.push_back({HKEY_CLASSES_ROOT, handler_path, dll_path, false});
                        entries.push_back({HKEY_CLASSES_ROOT, clsid_sub, dll_path, true});
                    }
                }
            }
        }
    }

    return entries;
}

static bool is_protected_registry_subkey(std::wstring_view name) {
    const std::wstring lower = to_lower(name);
    const wchar_t* protected_names[] = {
        L"microsoft", L"classes", L"policies", L"registeredapplications",
        L"windows nt", L"clients", L"oem", L"system", L"currentversion",
        L"appdatalow", L"program groups", L"secure", L"services",
        L"software", L"wow6432node", L"windows", L".default"
    };

    for (const auto* p : protected_names) {
        if (lower == p) {
            return true;
        }
    }
    return false;
}

static bool key_references_path_recursive(HKEY hKey, const std::wstring& target_root) {
    DWORD val_index = 0;
    wchar_t val_name[256];
    DWORD val_len = 256;

    while (true) {
        val_len = 256;
        LSTATUS st = RegEnumValueW(hKey, val_index, val_name, &val_len,
                                   nullptr, nullptr, nullptr, nullptr);
        if (st == ERROR_NO_MORE_ITEMS) {
            break;
        }
        val_index++;
        if (st != ERROR_SUCCESS) {
            continue;
        }

        const std::wstring val_data = query_reg_string(hKey, val_name);
        if (PathHelper::contains_path_reference(val_data, target_root)) {
            return true;
        }
    }

    DWORD sub_index = 0;
    wchar_t sub_name[256];
    DWORD sub_len = 256;

    while (true) {
        sub_len = 256;
        LSTATUS st = RegEnumKeyExW(hKey, sub_index, sub_name, &sub_len,
                                   nullptr, nullptr, nullptr, nullptr);
        if (st == ERROR_NO_MORE_ITEMS) {
            break;
        }
        sub_index++;
        if (st != ERROR_SUCCESS) {
            continue;
        }

        UniqueHKey child;
        if (RegOpenKeyExW(hKey, sub_name, 0, KEY_READ, child.put()) == ERROR_SUCCESS) {
            if (key_references_path_recursive(child.get(), target_root)) {
                return true;
            }
        }
    }

    return false;
}

std::vector<ProductKeyEntry> RegistryCleaner::find_product_keys(const Target& target) {
    std::vector<ProductKeyEntry> entries;
    if (target.name.empty() && target.publisher.empty()) {
        return entries;
    }

    struct RootScope {
        HKEY root;
        const wchar_t* base_path;
        REGSAM sam;
    };

    const RootScope scopes[] = {
        {HKEY_CURRENT_USER, L"Software", 0},
        {HKEY_LOCAL_MACHINE, L"SOFTWARE", KEY_WOW64_64KEY},
        {HKEY_LOCAL_MACHINE, L"SOFTWARE", KEY_WOW64_32KEY}
    };

    for (const auto& s : scopes) {
        UniqueHKey base_key;
        if (RegOpenKeyExW(s.root, s.base_path, 0, KEY_READ | s.sam, base_key.put()) != ERROR_SUCCESS) {
            continue;
        }

        // 1. Direct match: Software\<target.name>
        if (!target.name.empty() && !is_protected_registry_subkey(target.name)) {
            UniqueHKey prod_key;
            if (RegOpenKeyExW(base_key.get(), target.name.c_str(), 0, KEY_READ | s.sam, prod_key.put()) == ERROR_SUCCESS) {
                if (target.root_path.empty() || key_references_path_recursive(prod_key.get(), target.root_path)) {
                    entries.push_back({s.root, std::wstring(s.base_path) + L"\\" + target.name, s.sam});
                }
            }
        }

        // 2. Publisher match: Software\<publisher>\<target.name>
        if (!target.publisher.empty() && !is_protected_registry_subkey(target.publisher)) {
            UniqueHKey pub_key;
            if (RegOpenKeyExW(base_key.get(), target.publisher.c_str(), 0, KEY_READ | s.sam, pub_key.put()) == ERROR_SUCCESS) {
                if (!target.name.empty()) {
                    UniqueHKey sub_prod;
                    if (RegOpenKeyExW(pub_key.get(), target.name.c_str(), 0, KEY_READ | s.sam, sub_prod.put()) == ERROR_SUCCESS) {
                        entries.push_back({
                            s.root,
                            std::wstring(s.base_path) + L"\\" + target.publisher + L"\\" + target.name,
                            s.sam
                        });
                    }
                }
            }
        }

        // 3. Scan vendor subkeys: Software\<Vendor>\<target.name>
        DWORD vidx = 0;
        wchar_t vname[256];
        DWORD vlen = 256;

        while (true) {
            vlen = 256;
            LSTATUS st = RegEnumKeyExW(base_key.get(), vidx, vname, &vlen,
                                       nullptr, nullptr, nullptr, nullptr);
            if (st == ERROR_NO_MORE_ITEMS) {
                break;
            }
            vidx++;
            if (st != ERROR_SUCCESS || is_protected_registry_subkey(vname)) {
                continue;
            }

            if (!target.name.empty() && _wcsicmp(vname, target.name.c_str()) != 0) {
                UniqueHKey vkey;
                if (RegOpenKeyExW(base_key.get(), vname, 0, KEY_READ | s.sam, vkey.put()) == ERROR_SUCCESS) {
                    UniqueHKey nested_prod;
                    if (RegOpenKeyExW(vkey.get(), target.name.c_str(), 0, KEY_READ | s.sam, nested_prod.put()) == ERROR_SUCCESS) {
                        if (!target.root_path.empty() && key_references_path_recursive(nested_prod.get(), target.root_path)) {
                            const std::wstring p_path = std::wstring(s.base_path) + L"\\" + vname + L"\\" + target.name;
                            bool dup = false;
                            for (const auto& e : entries) {
                                if (e.root_key == s.root && e.subkey_path == p_path && e.sam_view == s.sam) {
                                    dup = true;
                                    break;
                                }
                            }
                            if (!dup) {
                                entries.push_back({s.root, p_path, s.sam});
                            }
                        }
                    }
                }
            }
        }
    }

    return entries;
}

Result<void> RegistryCleaner::clean(const Target& target, RegistryCleanReport& report,
                                    bool no_backup) {
    RegistryBackup::set_enabled(!no_backup);
    report.backup_directory = RegistryBackup::get_backup_directory();

    // 1. Uninstall entries
    for (const auto& entry : target.registry_entries) {
        auto bkp_res = RegistryBackup::export_key(entry.root_key, entry.subkey_path, entry.sam_view);
        if (bkp_res && !bkp_res.value().empty()) {
            report.items_backed_up++;
        }

        auto del_res = delete_key_tree(entry.root_key, entry.subkey_path, entry.sam_view);
        if (del_res) {
            report.uninstall_keys_deleted++;
            report.total_keys_deleted++;
        } else {
            report.failed_items.push_back(entry.subkey_path);
        }
    }

    // 2. Autorun values
    const auto autoruns = find_autorun_entries(target.root_path);
    for (const auto& ar : autoruns) {
        auto bkp_res = RegistryBackup::export_value(ar.root_key, ar.subkey_path, ar.value_name, ar.sam_view);
        if (bkp_res && !bkp_res.value().empty()) {
            report.items_backed_up++;
        }

        UniqueHKey key;
        if (RegOpenKeyExW(ar.root_key, ar.subkey_path.c_str(), 0,
                          KEY_WRITE | ar.sam_view, key.put()) == ERROR_SUCCESS) {
            if (RegDeleteValueW(key.get(), ar.value_name.c_str()) == ERROR_SUCCESS) {
                report.autorun_values_deleted++;
                report.total_values_deleted++;
            } else {
                report.failed_items.push_back(ar.subkey_path + L"\\" + ar.value_name);
            }
        }
    }

    // 3. Shell context menu verbs and extensions
    const auto shell_entries = find_shell_entries(target.root_path);
    for (const auto& sh : shell_entries) {
        auto bkp_res = RegistryBackup::export_key(sh.root_key, sh.subkey_path);
        if (bkp_res && !bkp_res.value().empty()) {
            report.items_backed_up++;
        }

        auto del_res = delete_key_tree(sh.root_key, sh.subkey_path);
        if (del_res) {
            report.shell_entries_deleted++;
            report.total_keys_deleted++;
        } else {
            report.failed_items.push_back(sh.subkey_path);
        }
    }

    // 4. Product and publisher keys
    const auto prod_keys = find_product_keys(target);
    for (const auto& pk : prod_keys) {
        auto bkp_res = RegistryBackup::export_key(pk.root_key, pk.subkey_path, pk.sam_view);
        if (bkp_res && !bkp_res.value().empty()) {
            report.items_backed_up++;
        }

        auto del_res = delete_key_tree(pk.root_key, pk.subkey_path, pk.sam_view);
        if (del_res) {
            report.product_keys_deleted++;
            report.total_keys_deleted++;

            // If under publisher, clean publisher if now empty
            const size_t last_slash = pk.subkey_path.rfind(L'\\');
            if (last_slash != std::wstring::npos) {
                const std::wstring parent_path = pk.subkey_path.substr(0, last_slash);
                const size_t prev_slash = parent_path.rfind(L'\\');
                const std::wstring parent_leaf = (prev_slash == std::wstring::npos)
                                                 ? parent_path
                                                 : parent_path.substr(prev_slash + 1);

                if (!is_protected_registry_subkey(parent_leaf)) {
                    UniqueHKey parent_key;
                    if (RegOpenKeyExW(pk.root_key, parent_path.c_str(), 0,
                                      KEY_READ | pk.sam_view, parent_key.put()) == ERROR_SUCCESS) {
                        DWORD sub_count = 0;
                        DWORD val_count = 0;
                        if (RegQueryInfoKeyW(parent_key.get(), nullptr, nullptr, nullptr,
                                             &sub_count, nullptr, nullptr, &val_count,
                                             nullptr, nullptr, nullptr, nullptr) == ERROR_SUCCESS) {
                            if (sub_count == 0 && val_count == 0) {
                                parent_key.reset();
                                delete_key_tree(pk.root_key, parent_path, pk.sam_view);
                            }
                        }
                    }
                }
            }
        } else {
            report.failed_items.push_back(pk.subkey_path);
        }
    }

    return Result<void>::success();
}

} // namespace obliterator
