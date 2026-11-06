#include "obliterator/print_cleaner.hpp"

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

bool PrintCleaner::is_protected_monitor(const std::wstring& name) {
    static const wchar_t* const kProtected[] = {
        L"Local Port",
        L"Standard TCP/IP Port",
        L"USB Monitor",
        L"WSD Port",
        L"Microsoft Shared Fax Monitor",
        L"AppContainer Monitor",
        L"TCP/IP Port"
    };

    for (const auto* p : kProtected) {
        if (_wcsicmp(name.c_str(), p) == 0) {
            return true;
        }
    }
    return false;
}

bool PrintCleaner::is_protected_processor(const std::wstring& name) {
    return _wcsicmp(name.c_str(), L"winprint") == 0;
}

bool PrintCleaner::is_protected_printer(const std::wstring& name) {
    static const wchar_t* const kProtected[] = {
        L"Microsoft Print to PDF",
        L"Microsoft XPS Document Writer",
        L"Fax",
        L"OneNote"
    };

    for (const auto* p : kProtected) {
        if (_wcsicmp(name.c_str(), p) == 0) {
            return true;
        }
    }
    return false;
}

bool PrintCleaner::matches_target(const std::wstring& name, const Target& target) {
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

bool PrintCleaner::path_references_target(const std::wstring& path, const Target& target) {
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

PrintCleanReport PrintCleaner::clean_print_artifacts(const Target& target, bool dry_run) {
    PrintCleanReport report;
    const HKEY kRoots[] = { HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER };

    // 1. Print Monitors
    const wchar_t* const kMonitorsPath = L"SYSTEM\\CurrentControlSet\\Control\\Print\\Monitors";
    for (HKEY root : kRoots) {
        const REGSAM access = dry_run ? KEY_READ : (KEY_READ | KEY_WRITE);
        UniqueHKey hMonitors;
        if (RegOpenKeyExW(root, kMonitorsPath, 0, access, hMonitors.put()) != ERROR_SUCCESS) {
            continue;
        }

        DWORD subkey_count = 0;
        DWORD max_subkey_len = 0;
        if (RegQueryInfoKeyW(hMonitors.get(), nullptr, nullptr, nullptr, &subkey_count,
                             &max_subkey_len, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) {
            continue;
        }

        std::vector<wchar_t> name_buf(max_subkey_len + 2, L'\0');
        std::vector<std::wstring> to_delete;

        for (DWORD i = 0; i < subkey_count; ++i) {
            DWORD len = static_cast<DWORD>(name_buf.size());
            if (RegEnumKeyExW(hMonitors.get(), i, name_buf.data(), &len, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) {
                continue;
            }

            const std::wstring mon_name(name_buf.data(), len);
            if (is_protected_monitor(mon_name)) {
                continue;
            }

            bool matches = matches_target(mon_name, target);
            if (!matches) {
                UniqueHKey hSub;
                if (RegOpenKeyExW(hMonitors.get(), mon_name.c_str(), 0, KEY_READ, hSub.put()) == ERROR_SUCCESS) {
                    wchar_t driver_buf[MAX_PATH] = { 0 };
                    DWORD driver_len = sizeof(driver_buf);
                    DWORD type = 0;
                    if (RegQueryValueExW(hSub.get(), L"Driver", nullptr, &type,
                                         reinterpret_cast<BYTE*>(driver_buf), &driver_len) == ERROR_SUCCESS &&
                        type == REG_SZ) {
                        matches = path_references_target(driver_buf, target);
                    }
                }
            }

            if (matches) {
                to_delete.push_back(mon_name);
            }
        }

        for (const auto& m : to_delete) {
            if (!dry_run) {
                RegDeleteTreeW(hMonitors.get(), m.c_str());
            }
            ++report.monitors_removed;
            report.details.push_back(L"Print Monitor: " + m);
        }
    }

    // 2. Print Processors
    const wchar_t* const kProcessorsPaths[] = {
        L"SYSTEM\\CurrentControlSet\\Control\\Print\\Environments\\Windows x64\\Print Processors",
        L"SYSTEM\\CurrentControlSet\\Control\\Print\\Environments\\Windows NT x86\\Print Processors"
    };

    for (HKEY root : kRoots) {
        for (const auto* proc_path : kProcessorsPaths) {
            const REGSAM access = dry_run ? KEY_READ : (KEY_READ | KEY_WRITE);
            UniqueHKey hProcessors;
            if (RegOpenKeyExW(root, proc_path, 0, access, hProcessors.put()) != ERROR_SUCCESS) {
                continue;
            }

            DWORD subkey_count = 0;
            DWORD max_subkey_len = 0;
            if (RegQueryInfoKeyW(hProcessors.get(), nullptr, nullptr, nullptr, &subkey_count,
                                 &max_subkey_len, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) {
                continue;
            }

            std::vector<wchar_t> name_buf(max_subkey_len + 2, L'\0');
            std::vector<std::wstring> to_delete;

            for (DWORD i = 0; i < subkey_count; ++i) {
                DWORD len = static_cast<DWORD>(name_buf.size());
                if (RegEnumKeyExW(hProcessors.get(), i, name_buf.data(), &len, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) {
                    continue;
                }

                const std::wstring proc_name(name_buf.data(), len);
                if (is_protected_processor(proc_name)) {
                    continue;
                }

                bool matches = matches_target(proc_name, target);
                if (!matches) {
                    UniqueHKey hSub;
                    if (RegOpenKeyExW(hProcessors.get(), proc_name.c_str(), 0, KEY_READ, hSub.put()) == ERROR_SUCCESS) {
                        wchar_t driver_buf[MAX_PATH] = { 0 };
                        DWORD driver_len = sizeof(driver_buf);
                        DWORD type = 0;
                        if (RegQueryValueExW(hSub.get(), L"Driver", nullptr, &type,
                                             reinterpret_cast<BYTE*>(driver_buf), &driver_len) == ERROR_SUCCESS &&
                            type == REG_SZ) {
                            matches = path_references_target(driver_buf, target);
                        }
                    }
                }

                if (matches) {
                    to_delete.push_back(proc_name);
                }
            }

            for (const auto& p : to_delete) {
                if (!dry_run) {
                    RegDeleteTreeW(hProcessors.get(), p.c_str());
                }
                ++report.processors_removed;
                report.details.push_back(L"Print Processor: " + p);
            }
        }
    }

    // 3. Printers
    const wchar_t* const kPrintersPath = L"SYSTEM\\CurrentControlSet\\Control\\Print\\Printers";
    for (HKEY root : kRoots) {
        const REGSAM access = dry_run ? KEY_READ : (KEY_READ | KEY_WRITE);
        UniqueHKey hPrinters;
        if (RegOpenKeyExW(root, kPrintersPath, 0, access, hPrinters.put()) != ERROR_SUCCESS) {
            continue;
        }

        DWORD subkey_count = 0;
        DWORD max_subkey_len = 0;
        if (RegQueryInfoKeyW(hPrinters.get(), nullptr, nullptr, nullptr, &subkey_count,
                             &max_subkey_len, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) {
            continue;
        }

        std::vector<wchar_t> name_buf(max_subkey_len + 2, L'\0');
        std::vector<std::wstring> to_delete;

        for (DWORD i = 0; i < subkey_count; ++i) {
            DWORD len = static_cast<DWORD>(name_buf.size());
            if (RegEnumKeyExW(hPrinters.get(), i, name_buf.data(), &len, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) {
                continue;
            }

            const std::wstring printer_name(name_buf.data(), len);
            if (is_protected_printer(printer_name)) {
                continue;
            }

            bool matches = matches_target(printer_name, target);
            if (!matches) {
                UniqueHKey hSub;
                if (RegOpenKeyExW(hPrinters.get(), printer_name.c_str(), 0, KEY_READ, hSub.put()) == ERROR_SUCCESS) {
                    wchar_t driver_buf[MAX_PATH] = { 0 };
                    DWORD driver_len = sizeof(driver_buf);
                    DWORD type = 0;
                    if (RegQueryValueExW(hSub.get(), L"Printer Driver", nullptr, &type,
                                         reinterpret_cast<BYTE*>(driver_buf), &driver_len) == ERROR_SUCCESS &&
                        type == REG_SZ) {
                        matches = path_references_target(driver_buf, target);
                    }
                }
            }

            if (matches) {
                to_delete.push_back(printer_name);
            }
        }

        for (const auto& pr : to_delete) {
            if (!dry_run) {
                RegDeleteTreeW(hPrinters.get(), pr.c_str());
            }
            ++report.printers_removed;
            report.details.push_back(L"Printer: " + pr);
        }
    }

    return report;
}

} // namespace obliterator
