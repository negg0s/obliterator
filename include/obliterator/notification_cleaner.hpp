#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include "obliterator/target.hpp"

#include <string>
#include <vector>

namespace obliterator {

struct NotificationCleanReport {
    size_t notification_settings_removed{0};
    size_t startup_approved_removed{0};
    std::vector<std::wstring> details;
};

class NotificationCleaner {
public:
    static NotificationCleanReport clean_notifications_and_startup(const Target& target, bool dry_run);

private:
    static void clean_notification_settings(const Target& target, bool dry_run, NotificationCleanReport& report);
    static void clean_startup_approved(const Target& target, bool dry_run, NotificationCleanReport& report);
    static bool matches_target_identifier(const std::wstring& identifier, const Target& target);
};

} // namespace obliterator
