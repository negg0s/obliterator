#pragma once

#include "obliterator/result.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace obliterator {

struct CommandLineOptions {
    std::wstring target;
    bool dry_run{false};
    bool yes{false};
    bool verbose{false};
    bool no_handle_kill{false};
    bool no_backup{false};
    bool aggressive{false};
    bool json{false};
    bool install_menu{false};
    bool uninstall_menu{false};
    bool help_requested{false};
    bool bench{false};
    bool force{false};
    bool native_only{false};
    uint32_t timeout_seconds{5};
    uint32_t native_timeout_seconds{120};
    std::wstring scan_portable_dir;
    std::wstring explain_artifact;
    bool all_users{false};
    std::wstring user_filter;
    bool include_system_profiles{false};
    bool resume{false};
    bool safe_mode_plan{false};
    bool quarantine{false};
    bool no_restore_point{false};
    bool require_restore_point{false};
    bool list_sessions{false};
    std::wstring restore_session_id;
    std::wstring purge_quarantine_arg;
};

class CommandLineParser {
public:
    static void print_usage();
    static Result<CommandLineOptions> parse(const std::vector<std::wstring>& args);
    static Result<CommandLineOptions> parse(int argc, const wchar_t* const argv[]);
};

} // namespace obliterator
