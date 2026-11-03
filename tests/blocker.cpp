#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include <string>

int wmain(int argc, wchar_t* argv[]) {
    wchar_t own_path[MAX_PATH]{};
    GetModuleFileNameW(nullptr, own_path, MAX_PATH);

    // Watchdog child mode
    if (argc >= 3 && std::wstring_view(argv[1]) == L"--child") {
        DWORD parent_pid = static_cast<DWORD>(std::stoul(argv[2]));
        HANDLE hParent = OpenProcess(SYNCHRONIZE, FALSE, parent_pid);

        while (true) {
            Sleep(50);
            if (hParent != nullptr) {
                DWORD wait_res = WaitForSingleObject(hParent, 0);
                if (wait_res == WAIT_OBJECT_0) {
                    // Parent died, attempt watchdog restart
                    CloseHandle(hParent);
                    hParent = nullptr;

                    STARTUPINFOW si{};
                    si.cb = sizeof(si);
                    PROCESS_INFORMATION pi{};
                    std::wstring cmd = L"\"" + std::wstring(own_path) + L"\"";
                    if (CreateProcessW(nullptr, cmd.data(), nullptr, nullptr, FALSE, 0,
                                       nullptr, nullptr, &si, &pi)) {
                        CloseHandle(pi.hProcess);
                        CloseHandle(pi.hThread);
                    }
                }
            }
        }
        return 0;
    }

    // Parent mode: open locked file exclusively
    HANDLE hFile = CreateFileW(
        L"locked_file.bin",
        GENERIC_READ | GENERIC_WRITE,
        0, // Exclusive access, no sharing
        nullptr,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        nullptr
    );

    // Spawn watchdog child
    STARTUPINFOW si{};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};
    std::wstring child_cmd = L"\"" + std::wstring(own_path) + L"\" --child " +
                             std::to_wstring(GetCurrentProcessId());

    if (CreateProcessW(nullptr, child_cmd.data(), nullptr, nullptr, FALSE, 0,
                       nullptr, nullptr, &si, &pi)) {
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }

    // Hold lock indefinitely until terminated
    while (true) {
        Sleep(50);
    }

    if (hFile != INVALID_HANDLE_VALUE) {
        CloseHandle(hFile);
    }
    return 0;
}
