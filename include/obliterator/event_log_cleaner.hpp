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

struct EventLogCleanReport {
    size_t event_sources_removed{0};
    size_t etw_publishers_removed{0};
    std::vector<std::wstring> details;
};

class EventLogCleaner {
public:
    static EventLogCleanReport clean_event_log_sources(const Target& target, bool dry_run);

private:
    static void clean_classic_sources(const Target& target, bool dry_run, EventLogCleanReport& report);
    static void clean_etw_publishers(const Target& target, bool dry_run, EventLogCleanReport& report);
    static bool path_references_target(const std::wstring& path, const Target& target);
    static bool is_protected_event_source(const std::wstring& source);
};

} // namespace obliterator
