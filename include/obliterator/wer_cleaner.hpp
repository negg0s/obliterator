#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include "obliterator/target.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace obliterator {

struct WerCleanReport {
    size_t local_dumps_keys_removed{0};
    size_t crash_dumps_deleted{0};
    size_t wer_reports_deleted{0};
    uint64_t bytes_reclaimed{0};
    std::vector<std::wstring> details;
};

class WerCleaner {
public:
    static WerCleanReport clean_wer_artifacts(const Target& target, bool dry_run);

private:
    static void clean_local_dumps_registry(const Target& target, bool dry_run, WerCleanReport& report);
    static void clean_crash_dumps_files(const Target& target, bool dry_run, WerCleanReport& report);
    static void clean_report_archive(const Target& target, bool dry_run, WerCleanReport& report);
    static bool matches_target_executable(const std::wstring& filename, const Target& target);
};

} // namespace obliterator
