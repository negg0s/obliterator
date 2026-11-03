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
};

class CommandLineParser {
public:
    static void print_usage();
    static Result<CommandLineOptions> parse(const std::vector<std::wstring>& args);
    static Result<CommandLineOptions> parse(int argc, const wchar_t* const argv[]);
};

} // namespace obliterator
