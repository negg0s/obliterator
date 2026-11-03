#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include "obliterator/result.hpp"

#include <cstdint>
#include <string>

namespace obliterator {

struct RestorePointResult {
    bool created{false};
    int64_t sequence_number{0};
    std::wstring description;
    std::wstring warning;
};

class RestorePointManager {
public:
    // Creates a system restore point of type APPLICATION_UNINSTALL before operations begin.
    // Dynamically loads srclient.dll.
    // If System Restore is disabled or frequency rate-limited:
    // - if require_restore_point is true: returns an error
    // - if require_restore_point is false: logs warning and continues
    static Result<RestorePointResult> create_restore_point(const std::wstring& target_name,
                                                         bool require_restore_point);

    // Closes an active system restore point session with END_SYSTEM_CHANGE.
    static void finish_restore_point(int64_t sequence_number, bool cancelled = false);
};

} // namespace obliterator
