#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include "obliterator/result.hpp"
#include "obliterator/target.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace obliterator {

enum class UninstallerType {
    None,
    Msi,
    InnoSetup,
    Nsis,
    InstallShield,
    Uwp,
    Unknown
};

struct ParsedUninstallCommand {
    std::wstring executable_path;
    std::wstring arguments;
    std::wstring raw_command;
    bool is_valid{false};
};

struct NativeUninstallerInfo {
    UninstallerType type{UninstallerType::None};
    std::wstring quiet_command;
    std::wstring raw_uninstall_string;
    std::wstring raw_quiet_string;
    std::wstring product_code;
    std::wstring package_full_name;
    std::wstring package_family_name;
    std::wstring display_name;
};

class NativeUninstaller {
public:
    static ParsedUninstallCommand parse_command(std::wstring_view cmd);
    static std::wstring extract_product_code(std::wstring_view cmd);

    static UninstallerType detect_pe_signature(const std::wstring& exe_path);

    static NativeUninstallerInfo detect(const Target& target);
    static NativeUninstallerInfo detect_from_strings(
        const std::wstring& uninstall_str,
        const std::wstring& quiet_uninstall_str,
        const std::wstring& install_loc,
        const std::wstring& display_name = {}
    );

    static Result<void> execute_with_timeout(
        const NativeUninstallerInfo& info,
        uint32_t timeout_seconds
    );

    static const wchar_t* type_name(UninstallerType type);
};

} // namespace obliterator
