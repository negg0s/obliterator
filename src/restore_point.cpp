#include "obliterator/restore_point.hpp"
#include "obliterator/log.hpp"

#include <srrestoreptapi.h>

namespace obliterator {

typedef BOOL (WINAPI *pfnSRSetRestorePointW)(PRESTOREPOINTINFOW, PSTATEMGRSTATUS);

Result<RestorePointResult> RestorePointManager::create_restore_point(
    const std::wstring& target_name, bool require_restore_point) {
    RestorePointResult result;
    result.description = L"Obliterator uninstall " + target_name;

    HMODULE hSr = LoadLibraryW(L"srclient.dll");
    if (!hSr) {
        std::wstring msg = L"System Restore client library (srclient.dll) is not available";
        if (require_restore_point) {
            Logger::error(msg);
            return Win32Error::from_code(ERROR_SERVICE_DISABLED);
        }
        Logger::warn(msg + L"; proceeding without restore point");
        result.warning = msg;
        return result;
    }

    auto pfnSet = reinterpret_cast<pfnSRSetRestorePointW>(GetProcAddress(hSr, "SRSetRestorePointW"));
    if (!pfnSet) {
        FreeLibrary(hSr);
        std::wstring msg = L"SRSetRestorePointW export not found in srclient.dll";
        if (require_restore_point) {
            Logger::error(msg);
            return Win32Error::from_code(ERROR_PROC_NOT_FOUND);
        }
        Logger::warn(msg + L"; proceeding without restore point");
        result.warning = msg;
        return result;
    }

    RESTOREPOINTINFOW rpi{};
    rpi.dwEventType = BEGIN_SYSTEM_CHANGE;
    rpi.dwRestorePtType = APPLICATION_UNINSTALL;
    rpi.llSequenceNumber = 0;
    wcsncpy_s(rpi.szDescription, result.description.c_str(), MAX_DESC_W - 1);

    STATEMGRSTATUS smStatus{};
    BOOL ok = pfnSet(&rpi, &smStatus);
    FreeLibrary(hSr);

    if (!ok || smStatus.nStatus != ERROR_SUCCESS) {
        DWORD err = smStatus.nStatus != ERROR_SUCCESS ? smStatus.nStatus : GetLastError();
        std::wstring reason;
        if (err == ERROR_SERVICE_DISABLED) {
            reason = L"System Protection is disabled on this machine";
        } else if (err == ERROR_TIMEOUT || err == 0x80070005) {
            reason = L"System Restore frequency limit or timeout reached";
        } else {
            reason = Win32Error::from_code(err).message();
        }

        std::wstring warn_text = L"Could not create System Restore Point (" + reason + L")";
        if (require_restore_point) {
            Logger::error(warn_text + L" and --require-restore-point was specified. Aborting.");
            return Win32Error::from_code(err);
        }

        Logger::warn(warn_text + L"; proceeding anyway");
        result.warning = warn_text;
        return result;
    }

    result.created = true;
    result.sequence_number = smStatus.llSequenceNumber;
    Logger::info(L"Created System Restore Point: " + result.description +
                 L" (Sequence: " + std::to_wstring(result.sequence_number) + L")");
    return result;
}

void RestorePointManager::finish_restore_point(int64_t sequence_number, bool cancelled) {
    if (sequence_number <= 0) {
        return;
    }

    HMODULE hSr = LoadLibraryW(L"srclient.dll");
    if (!hSr) {
        return;
    }

    auto pfnSet = reinterpret_cast<pfnSRSetRestorePointW>(GetProcAddress(hSr, "SRSetRestorePointW"));
    if (pfnSet) {
        RESTOREPOINTINFOW rpi{};
        rpi.dwEventType = END_SYSTEM_CHANGE;
        rpi.dwRestorePtType = cancelled ? CANCELLED_OPERATION : APPLICATION_UNINSTALL;
        rpi.llSequenceNumber = sequence_number;

        STATEMGRSTATUS smStatus{};
        pfnSet(&rpi, &smStatus);
    }

    FreeLibrary(hSr);
}

} // namespace obliterator
