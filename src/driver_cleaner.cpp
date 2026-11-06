#include "obliterator/driver_cleaner.hpp"
#include "obliterator/handles.hpp"
#include "obliterator/log.hpp"
#include "obliterator/path.hpp"

#include <algorithm>
#include <cwctype>
#include <filesystem>
#include <fstream>
#include <map>
#include <vector>

namespace obliterator {

namespace fs = std::filesystem;

typedef BOOL (WINAPI *PFN_SetupUninstallOEMInfW)(
    PCWSTR InfFileName,
    DWORD Flags,
    PVOID Reserved
);

constexpr DWORD SUOI_FORCEDELETE_FLAG = 0x00000001;

static bool string_equals_ignore_case(std::wstring_view a, std::wstring_view b) {
    if (a.size() != b.size()) {
        return false;
    }
    for (size_t i = 0; i < a.size(); ++i) {
        if (std::towlower(a[i]) != std::towlower(b[i])) {
            return false;
        }
    }
    return true;
}

static bool string_contains_ignore_case(std::wstring_view text, std::wstring_view needle) {
    if (needle.empty() || text.empty()) {
        return false;
    }
    const std::wstring t_lower = PathHelper::to_lower_unicode(text);
    const std::wstring n_lower = PathHelper::to_lower_unicode(needle);
    return t_lower.find(n_lower) != std::wstring::npos;
}

static std::wstring trim_whitespace_and_quotes(std::wstring_view s) {
    size_t start = 0;
    while (start < s.size() && (std::iswspace(s[start]) || s[start] == L'\"')) {
        start++;
    }
    size_t end = s.size();
    while (end > start && (std::iswspace(s[end - 1]) || s[end - 1] == L'\"')) {
        end--;
    }
    return std::wstring(s.substr(start, end - start));
}

bool DriverCleaner::is_protected_vendor(std::wstring_view provider) {
    static const wchar_t* const protected_vendors[] = {
        L"Microsoft",
        L"Microsoft Corporation",
        L"Intel",
        L"Intel Corporation",
        L"AMD",
        L"Advanced Micro Devices",
        L"NVIDIA",
        L"NVIDIA Corporation",
        L"Realtek",
        L"Realtek Semiconductor",
        L"Qualcomm"
    };

    const std::wstring clean = trim_whitespace_and_quotes(provider);
    for (const auto* v : protected_vendors) {
        if (string_equals_ignore_case(clean, v)) {
            return true;
        }
    }
    return false;
}

struct ParsedInf {
    std::wstring provider;
    std::wstring catalog_file;
    std::wstring driver_version;
    std::vector<std::wstring> service_binaries;
    std::vector<std::wstring> all_string_values;
};

static ParsedInf parse_inf_content(const fs::path& inf_path) {
    ParsedInf parsed;
    std::ifstream in(inf_path, std::ios::binary);
    if (!in.is_open()) {
        return parsed;
    }

    std::string line_a;
    std::map<std::wstring, std::wstring> strings_table;
    bool in_strings_section = false;

    while (std::getline(in, line_a)) {
        if (line_a.empty() || line_a[0] == ';') {
            continue;
        }

        std::wstring line_w;
        line_w.reserve(line_a.size());
        for (char c : line_a) {
            line_w.push_back(static_cast<wchar_t>(static_cast<unsigned char>(c)));
        }

        std::wstring trimmed = trim_whitespace_and_quotes(line_w);
        if (trimmed.empty()) {
            continue;
        }

        if (trimmed.front() == L'[' && trimmed.back() == L']') {
            std::wstring section_name = trimmed.substr(1, trimmed.size() - 2);
            in_strings_section = string_contains_ignore_case(section_name, L"Strings");
            continue;
        }

        size_t eq_pos = trimmed.find(L'=');
        if (eq_pos == std::wstring::npos) {
            continue;
        }

        std::wstring key = trim_whitespace_and_quotes(trimmed.substr(0, eq_pos));
        std::wstring val = trim_whitespace_and_quotes(trimmed.substr(eq_pos + 1));

        if (in_strings_section) {
            strings_table[PathHelper::to_lower_unicode(key)] = val;
            parsed.all_string_values.push_back(val);
        } else {
            if (string_equals_ignore_case(key, L"Provider")) {
                parsed.provider = val;
            } else if (string_equals_ignore_case(key, L"CatalogFile")) {
                parsed.catalog_file = val;
            } else if (string_equals_ignore_case(key, L"DriverVer")) {
                parsed.driver_version = val;
            } else if (string_equals_ignore_case(key, L"ServiceBinary")) {
                size_t last_sep = val.find_last_of(L"\\/");
                std::wstring bin_name = (last_sep != std::wstring::npos) ? val.substr(last_sep + 1) : val;
                parsed.service_binaries.push_back(trim_whitespace_and_quotes(bin_name));
            }
        }
    }

    // Resolve macro references like %Manufacturer% or %Provider%
    if (parsed.provider.size() >= 2 && parsed.provider.front() == L'%' && parsed.provider.back() == L'%') {
        std::wstring token = parsed.provider.substr(1, parsed.provider.size() - 2);
        auto it = strings_table.find(PathHelper::to_lower_unicode(token));
        if (it != strings_table.end()) {
            parsed.provider = it->second;
        }
    }

    return parsed;
}

std::vector<OemDriverInfo> DriverCleaner::discover_oem_drivers(
    const Target& target,
    const std::vector<std::wstring>& known_service_binaries
) {
    std::vector<OemDriverInfo> matched_drivers;

    wchar_t windir_buf[MAX_PATH] = {0};
    if (GetWindowsDirectoryW(windir_buf, MAX_PATH) == 0) {
        return matched_drivers;
    }

    const fs::path inf_dir = fs::path(windir_buf) / L"INF";
    std::error_code ec;
    if (!fs::exists(inf_dir, ec) || !fs::is_directory(inf_dir, ec)) {
        return matched_drivers;
    }

    for (const auto& entry : fs::directory_iterator(inf_dir, ec)) {
        if (!entry.is_regular_file(ec)) {
            continue;
        }

        const std::wstring filename = entry.path().filename().wstring();
        const std::wstring lower_name = PathHelper::to_lower_unicode(filename);
        if (!lower_name.starts_with(L"oem") || !lower_name.ends_with(L".inf")) {
            continue;
        }

        ParsedInf parsed = parse_inf_content(entry.path());
        if (is_protected_vendor(parsed.provider)) {
            continue;
        }

        bool matched = false;
        std::wstring match_reason;

        // 1. Check if the INF references one of the target's discovered driver service binaries
        for (const auto& known_bin : known_service_binaries) {
            const std::wstring base_known = fs::path(known_bin).filename().wstring();
            for (const auto& inf_bin : parsed.service_binaries) {
                if (string_equals_ignore_case(base_known, inf_bin)) {
                    matched = true;
                    match_reason = L"INF installs target service binary: " + inf_bin;
                    break;
                }
            }
            if (matched) {
                break;
            }
        }

        // 2. Check if the INF provider matches target publisher
        if (!matched && !target.publisher.empty() && !parsed.provider.empty()) {
            if (string_equals_ignore_case(parsed.provider, target.publisher)) {
                matched = true;
                match_reason = L"OEM driver provider exact match: " + parsed.provider;
            } else if (string_contains_ignore_case(parsed.provider, target.publisher)) {
                matched = true;
                match_reason = L"OEM driver provider partial match: " + parsed.provider;
            }
        }

        // 3. Check if target name matches catalog or INF string values
        if (!matched && !target.name.empty()) {
            if (!parsed.catalog_file.empty() && string_contains_ignore_case(parsed.catalog_file, target.name)) {
                matched = true;
                match_reason = L"driver catalog file matches product name: " + parsed.catalog_file;
            } else {
                for (const auto& str_val : parsed.all_string_values) {
                    if (string_contains_ignore_case(str_val, target.name)) {
                        matched = true;
                        match_reason = L"driver metadata matches target name: " + str_val;
                        break;
                    }
                }
            }
        }

        if (matched) {
            OemDriverInfo info;
            info.inf_filename = filename;
            info.full_path = entry.path().wstring();
            info.provider = parsed.provider;
            info.catalog_file = parsed.catalog_file;
            info.driver_version = parsed.driver_version;
            info.service_binaries = std::move(parsed.service_binaries);
            info.matched_reason = std::move(match_reason);
            matched_drivers.push_back(std::move(info));
        }
    }

    return matched_drivers;
}

size_t DriverCleaner::uninstall_oem_driver(const OemDriverInfo& driver, bool dry_run) {
    if (dry_run) {
        Logger::info(L"[DRY-RUN] Would uninstall OEM driver package: " + driver.inf_filename +
                     L" (" + driver.provider + L", " + driver.matched_reason + L")");
        return 1;
    }

    HMODULE hSetupApi = LoadLibraryW(L"setupapi.dll");
    if (!hSetupApi) {
        Logger::warn(L"Could not load setupapi.dll to uninstall OEM driver: " + driver.inf_filename);
        return 0;
    }

    auto pfnUninstall = reinterpret_cast<PFN_SetupUninstallOEMInfW>(
        GetProcAddress(hSetupApi, "SetupUninstallOEMInfW")
    );

    size_t result = 0;
    if (pfnUninstall) {
        if (pfnUninstall(driver.inf_filename.c_str(), SUOI_FORCEDELETE_FLAG, nullptr)) {
            Logger::info(L"Uninstalled OEM driver and purged DriverStore package: " + driver.inf_filename +
                         L" (" + driver.provider + L")");
            result = 1;
        } else {
            const DWORD err = GetLastError();
            Logger::warn(L"SetupUninstallOEMInfW failed for " + driver.inf_filename +
                         L" (Win32 error: " + std::to_wstring(err) + L")");
        }
    } else {
        Logger::warn(L"SetupUninstallOEMInfW export not found in setupapi.dll");
    }

    FreeLibrary(hSetupApi);
    return result;
}

size_t DriverCleaner::uninstall_oem_drivers(const std::vector<OemDriverInfo>& drivers, bool dry_run) {
    size_t total = 0;
    for (const auto& drv : drivers) {
        total += uninstall_oem_driver(drv, dry_run);
    }
    return total;
}

} // namespace obliterator
