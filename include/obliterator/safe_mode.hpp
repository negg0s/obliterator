#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include <string>

namespace obliterator {

class SafeModeManager {
public:
    // Displays Safe Mode explanation, instructions, and bcdedit commands
    // If auto_confirm is true or user confirms at interactive prompt, configures bcdedit for minimal safe boot
    static int execute_safe_mode_plan(bool auto_confirm, const std::wstring& target_arg = {});

    static bool enable_safeboot_minimal();
    static bool disable_safeboot();
};

} // namespace obliterator
