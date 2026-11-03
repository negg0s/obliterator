#include "obliterator/target.hpp"
#include "obliterator/log.hpp"
#include "obliterator/path.hpp"
#include "obliterator/safety.hpp"

#include <algorithm>
#include <cwctype>
#include <filesystem>
#include <vector>

namespace obliterator {

static std::wstring to_lower_string(std::wstring_view input) {
    std::wstring result(input);
    std::transform(result.begin(), result.end(), result.begin(), [](wchar_t c) {
        return static_cast<wchar_t>(std::towlower(c));
    });
    return result;
}

static std::wstring query_registry_string(HKEY key, const wchar_t* value_name) {
    DWORD type = 0;
    DWORD bytes = 0;
    LSTATUS status = RegQueryValueExW(key, value_name, nullptr, &type, nullptr, &bytes);
    if (status != ERROR_SUCCESS || bytes == 0) {
        return {};
    }

    if (type != REG_SZ && type != REG_EXPAND_SZ) {
        return {};
    }

    std::wstring buffer(bytes / sizeof(wchar_t), L'\0');
    status = RegQueryValueExW(key, value_name, nullptr, &type,
                              reinterpret_cast<LPBYTE>(buffer.data()), &bytes);
    if (status != ERROR_SUCCESS) {
        return {};
    }

    while (!buffer.empty() && buffer.back() == L'\0') {
        buffer.pop_back();
    }

    return buffer;
}

static std::wstring extract_path_from_command(std::wstring_view cmd) {
    while (!cmd.empty() && (cmd.front() == L' ' || cmd.front() == L'\t')) {
        cmd.remove_prefix(1);
    }
    if (cmd.empty()) {
        return {};
    }

    if (cmd.front() == L'\"') {
        const size_t end_quote = cmd.find(L'\"', 1);
        if (end_quote != std::wstring_view::npos) {
            return std::wstring(cmd.substr(1, end_quote - 1));
        }
        return std::wstring(cmd.substr(1));
    }

    // Unquoted string: extract up to .exe or first space
    const size_t exe_pos = to_lower_string(cmd).find(L".exe");
    if (exe_pos != std::wstring_view::npos) {
        return std::wstring(cmd.substr(0, exe_pos + 4));
    }

    const size_t space_pos = cmd.find(L' ');
    if (space_pos != std::wstring_view::npos) {
        return std::wstring(cmd.substr(0, space_pos));
    }

    return std::wstring(cmd);
}

static std::wstring strip_icon_index(std::wstring_view icon) {
    while (!icon.empty() && (icon.front() == L'\"' || icon.front() == L' ')) {
        icon.remove_prefix(1);
    }
    while (!icon.empty() && (icon.back() == L'\"' || icon.back() == L' ')) {
        icon.remove_suffix(1);
    }

    const size_t comma = icon.rfind(L',');
    if (comma != std::wstring_view::npos) {
        bool only_digits = true;
        for (size_t i = comma + 1; i < icon.size(); ++i) {
            if (!std::iswdigit(icon[i]) && icon[i] != L'-' && icon[i] != L'+') {
                only_digits = false;
                break;
            }
        }
        if (only_digits && comma > 0) {
            icon = icon.substr(0, comma);
        }
    }

    while (!icon.empty() && (icon.front() == L'\"' || icon.front() == L' ')) {
        icon.remove_prefix(1);
    }
    while (!icon.empty() && (icon.back() == L'\"' || icon.back() == L' ')) {
        icon.remove_suffix(1);
    }

    return std::wstring(icon);
}

std::wstring TargetResolver::deduce_install_folder(const std::wstring& install_loc,
                                                  const std::wstring& display_icon,
                                                  const std::wstring& uninstall_str) {
    if (!install_loc.empty()) {
        const std::wstring norm = SafetyValidator::normalize_path(install_loc);
        if (!norm.empty()) {
            return norm;
        }
    }

    if (!display_icon.empty()) {
        const std::wstring raw_path = strip_icon_index(display_icon);
        const std::wstring norm = SafetyValidator::normalize_path(raw_path);
        if (!norm.empty()) {
            std::error_code ec;
            std::filesystem::path p(norm);
            if (std::filesystem::exists(p, ec) && !ec && !std::filesystem::is_directory(p, ec) && !ec) {
                std::filesystem::path parent = p.parent_path();
                const std::wstring parent_name = to_lower_string(parent.filename().wstring());
                if ((parent_name == L"bin" || parent_name == L"app" || parent_name == L"x64") &&
                    parent.has_parent_path()) {
                    return parent.parent_path().wstring();
                }
                return parent.wstring();
            }
        }
    }

    if (!uninstall_str.empty()) {
        const std::wstring exe_path = extract_path_from_command(uninstall_str);
        const std::wstring lower_exe = to_lower_string(exe_path);
        if (!lower_exe.ends_with(L"msiexec.exe") && !lower_exe.ends_with(L"msiexec")) {
            const std::wstring norm = SafetyValidator::normalize_path(exe_path);
            if (!norm.empty()) {
                std::filesystem::path p(norm);
                if (p.has_parent_path()) {
                    std::filesystem::path parent = p.parent_path();
                    const std::wstring parent_name = to_lower_string(parent.filename().wstring());
                    if ((parent_name == L"bin" || parent_name == L"app") &&
                        parent.has_parent_path()) {
                        return parent.parent_path().wstring();
                    }
                    return parent.wstring();
                }
            }
        }
    }

    return {};
}

struct RegistryScope {
    HKEY root;
    REGSAM sam;
    const wchar_t* name;
};

static const RegistryScope kScopes[] = {
    {HKEY_LOCAL_MACHINE, KEY_WOW64_64KEY, L"HKLM-64"},
    {HKEY_LOCAL_MACHINE, KEY_WOW64_32KEY, L"HKLM-32"},
    {HKEY_CURRENT_USER, KEY_WOW64_64KEY, L"HKCU-64"},
    {HKEY_CURRENT_USER, KEY_WOW64_32KEY, L"HKCU-32"}
};

static constexpr const wchar_t* kUninstallPath =
    L"Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall";

static bool is_direct_path(std::wstring_view input) {
    if (input.find(L'\\') != std::wstring_view::npos ||
        input.find(L'/') != std::wstring_view::npos) {
        return true;
    }
    if (input.size() >= 2 && std::iswalpha(input[0]) && input[1] == L':') {
        return true;
    }
    if (input.starts_with(L".")) {
        return true;
    }
    return false;
}

static std::vector<TargetRegistryEntry> find_registry_entries_for_path(const std::wstring& target_path) {
    std::vector<TargetRegistryEntry> entries;
    const std::wstring lower_target = to_lower_string(target_path);

    for (const auto& scope : kScopes) {
        UniqueHKey root_key;
        LSTATUS status = RegOpenKeyExW(scope.root, kUninstallPath, 0,
                                       KEY_READ | scope.sam, root_key.put());
        if (status != ERROR_SUCCESS) {
            continue;
        }

        DWORD index = 0;
        wchar_t subkey_name[256];
        DWORD subkey_name_len = 256;

        while (RegEnumKeyExW(root_key.get(), index, subkey_name, &subkey_name_len,
                             nullptr, nullptr, nullptr, nullptr) == ERROR_SUCCESS) {
            index++;
            subkey_name_len = 256;

            UniqueHKey subkey;
            status = RegOpenKeyExW(root_key.get(), subkey_name, 0,
                                   KEY_READ | scope.sam, subkey.put());
            if (status != ERROR_SUCCESS) {
                continue;
            }

            const std::wstring display_name = query_registry_string(subkey.get(), L"DisplayName");
            const std::wstring install_loc = query_registry_string(subkey.get(), L"InstallLocation");
            const std::wstring display_icon = query_registry_string(subkey.get(), L"DisplayIcon");
            const std::wstring uninstall_str = query_registry_string(subkey.get(), L"UninstallString");

            const std::wstring deduced =
                TargetResolver::deduce_install_folder(install_loc, display_icon, uninstall_str);
            if (!deduced.empty() && (PathHelper::is_same_or_subpath(target_path, deduced) ||
                                     PathHelper::is_same_or_subpath(deduced, target_path))) {
                entries.push_back({
                    scope.root,
                    std::wstring(kUninstallPath) + L"\\" + subkey_name,
                    scope.sam,
                    display_name
                });
            }
        }
    }

    return entries;
}

Result<Target> TargetResolver::resolve(const std::wstring& input) {
    if (input.empty()) {
        return Win32Error::from_code(ERROR_INVALID_PARAMETER);
    }

    if (is_direct_path(input)) {
        const std::wstring norm = SafetyValidator::normalize_path(input);
        if (norm.empty()) {
            return Win32Error::from_code(ERROR_PATH_NOT_FOUND);
        }

        auto safe_res = SafetyValidator::validate_path(norm);
        if (!safe_res) {
            return safe_res.error();
        }

        std::error_code ec;
        std::filesystem::path p(norm);
        if (!std::filesystem::exists(p, ec) || ec) {
            Logger::error(L"Target path does not exist on disk: " + norm);
            return Win32Error::from_code(ERROR_FILE_NOT_FOUND);
        }

        Target target;
        target.root_path = norm;
        target.name = p.filename().wstring();
        if (target.name.empty()) {
            target.name = norm;
        }

        target.registry_entries = find_registry_entries_for_path(norm);
        for (const auto& reg_entry : target.registry_entries) {
            UniqueHKey hKey;
            if (RegOpenKeyExW(reg_entry.root_key, reg_entry.subkey_path.c_str(), 0,
                              KEY_READ | reg_entry.sam_view, hKey.put()) == ERROR_SUCCESS) {
                const std::wstring pub = query_registry_string(hKey.get(), L"Publisher");
                if (!pub.empty()) {
                    target.publisher = pub;
                    break;
                }
            }
        }
        return target;
    }

    // Name-based resolution via registry uninstall entries
    struct Candidate {
        std::wstring display_name;
        std::wstring publisher;
        std::wstring root_path;
        TargetRegistryEntry entry;
    };

    std::vector<Candidate> candidates;
    const std::wstring lower_input = to_lower_string(input);

    for (const auto& scope : kScopes) {
        UniqueHKey root_key;
        LSTATUS status = RegOpenKeyExW(scope.root, kUninstallPath, 0,
                                       KEY_READ | scope.sam, root_key.put());
        if (status != ERROR_SUCCESS) {
            continue;
        }

        DWORD index = 0;
        wchar_t subkey_name[256];
        DWORD subkey_name_len = 256;

        while (RegEnumKeyExW(root_key.get(), index, subkey_name, &subkey_name_len,
                             nullptr, nullptr, nullptr, nullptr) == ERROR_SUCCESS) {
            index++;
            subkey_name_len = 256;

            UniqueHKey subkey;
            status = RegOpenKeyExW(root_key.get(), subkey_name, 0,
                                   KEY_READ | scope.sam, subkey.put());
            if (status != ERROR_SUCCESS) {
                continue;
            }

            const std::wstring display_name = query_registry_string(subkey.get(), L"DisplayName");
            if (display_name.empty()) {
                continue;
            }

            if (to_lower_string(display_name).find(lower_input) == std::wstring::npos) {
                continue;
            }

            const std::wstring install_loc = query_registry_string(subkey.get(), L"InstallLocation");
            const std::wstring display_icon = query_registry_string(subkey.get(), L"DisplayIcon");
            const std::wstring uninstall_str = query_registry_string(subkey.get(), L"UninstallString");
            const std::wstring publisher = query_registry_string(subkey.get(), L"Publisher");

            const std::wstring deduced =
                deduce_install_folder(install_loc, display_icon, uninstall_str);
            if (deduced.empty()) {
                continue;
            }

            // Verify safety on deduced path before accepting as candidate
            if (!SafetyValidator::validate_path(deduced)) {
                continue;
            }

            // Deduplicate across registry scopes
            bool duplicate = false;
            for (const auto& existing : candidates) {
                if (PathHelper::is_same_or_subpath(existing.root_path, deduced) &&
                    PathHelper::is_same_or_subpath(deduced, existing.root_path)) {
                    duplicate = true;
                    break;
                }
            }

            if (!duplicate) {
                candidates.push_back({
                    display_name,
                    publisher,
                    deduced,
                    {scope.root, std::wstring(kUninstallPath) + L"\\" + subkey_name, scope.sam, display_name}
                });
            }
        }
    }

    if (candidates.empty()) {
        Logger::error(L"No installed software or directory matches: " + input);
        return Win32Error::from_code(ERROR_NOT_FOUND);
    }

    if (candidates.size() > 1) {
        Logger::warn(L"Multiple matches found. Please re-run with exact name or path:");
        for (const auto& cand : candidates) {
            Logger::info(L"  * " + cand.display_name + L" -> " + cand.root_path);
        }
        return Win32Error::from_code(ERROR_MORE_DATA);
    }

    Target target;
    target.name = candidates[0].display_name;
    target.publisher = candidates[0].publisher;
    target.root_path = candidates[0].root_path;
    target.registry_entries.push_back(candidates[0].entry);

    // Find any additional registry entries associated with this same root directory
    auto extra_entries = find_registry_entries_for_path(target.root_path);
    for (const auto& extra : extra_entries) {
        bool exists = false;
        for (const auto& current : target.registry_entries) {
            if (current.root_key == extra.root_key &&
                current.subkey_path == extra.subkey_path &&
                current.sam_view == extra.sam_view) {
                exists = true;
                break;
            }
        }
        if (!exists) {
            target.registry_entries.push_back(extra);
        }
    }

    return target;
}

} // namespace obliterator
