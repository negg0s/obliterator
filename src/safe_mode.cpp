#include "obliterator/safe_mode.hpp"
#include "obliterator/handles.hpp"
#include "obliterator/log.hpp"
#include "obliterator/resume.hpp"

#include <iostream>
#include <string>

namespace obliterator {

static bool run_system_command(const std::wstring& cmd) {
    STARTUPINFOW si{};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    PROCESS_INFORMATION pi{};

    std::wstring mutable_cmd = cmd;
    if (!CreateProcessW(nullptr, mutable_cmd.data(), nullptr, nullptr, FALSE,
                        CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
        return false;
    }

    WaitForSingleObject(pi.hProcess, 10000);
    DWORD exit_code = 1;
    GetExitCodeProcess(pi.hProcess, &exit_code);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    return exit_code == 0;
}

bool SafeModeManager::enable_safeboot_minimal() {
    return run_system_command(L"bcdedit.exe /set {current} safeboot minimal");
}

bool SafeModeManager::disable_safeboot() {
    return run_system_command(L"bcdedit.exe /deletevalue {current} safeboot");
}

int SafeModeManager::execute_safe_mode_plan(bool auto_confirm, const std::wstring& target_arg) {
    std::wcout << L"\n================================================================================\n"
               << L" SAFE MODE REMOVAL PLAN\n"
               << L"================================================================================\n"
               << L" Protected processes and self-defense drivers (ObRegisterCallbacks, PPL, ELAM)\n"
               << L" cannot be terminated in normal Windows execution without risking BSOD.\n\n"
               << L" In Windows Safe Mode (Minimal):\n"
               << L"  1. Third-party drivers and self-defense callbacks are not loaded by the kernel.\n"
               << L"  2. Watchdog processes, companion services, and WMI consumers remain inactive.\n"
               << L"  3. Locked files and driver binaries can be safely removed.\n\n"
               << L" Safe Mode Workflow:\n"
               << L"  Step 1: Configure BCD to boot into Safe Mode:\n"
               << L"          bcdedit.exe /set {current} safeboot minimal\n"
               << L"  Step 2: Restart the computer:\n"
               << L"          shutdown.exe /r /t 5\n"
               << L"  Step 3: After login in Safe Mode, run Obliterator to complete removal:\n"
               << L"          obliterator.exe --resume\n"
               << L"  Step 4: Restore normal boot mode:\n"
               << L"          bcdedit.exe /deletevalue {current} safeboot\n"
               << L"  Step 5: Restart the computer to return to normal Windows.\n"
               << L"================================================================================\n\n";

    bool proceed = auto_confirm;
    if (!proceed) {
        std::wcout << L"Do you want to configure Windows to boot into Safe Mode? [y/N]: ";
        std::wstring line;
        if (std::getline(std::wcin, line)) {
            if (!line.empty() && (line[0] == L'y' || line[0] == L'Y')) {
                proceed = true;
            }
        }
    }

    if (!proceed) {
        std::wcout << L"Safe Mode configuration cancelled. No boot settings were changed.\n";
        return 0;
    }

    if (!target_arg.empty()) {
        ResumeState state;
        state.target_name = target_arg;
        state.target_root = target_arg;
        state.pending_directories.push_back(target_arg);
        ResumeManager::save_resume_state(state);
    } else {
        ResumeManager::register_run_once();
    }

    if (enable_safeboot_minimal()) {
        std::wcout << L"\n[SUCCESS] Windows has been configured to boot into Safe Mode.\n"
                   << L"To reboot into Safe Mode now, execute:\n"
                   << L"  shutdown /r /t 5\n\n"
                   << L"To revert back to normal boot at any time, execute:\n"
                   << L"  bcdedit /deletevalue {current} safeboot\n\n";
        return 0;
    } else {
        std::wcout << L"\n[ERROR] Failed to modify BCD settings via bcdedit.\n"
                   << L"Ensure you are running Obliterator from an elevated Administrator prompt.\n";
        return 1;
    }
}

} // namespace obliterator
