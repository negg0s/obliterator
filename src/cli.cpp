#include "obliterator/cli.hpp"
#include "obliterator/log.hpp"

#include <iostream>

namespace obliterator {

void CommandLineParser::print_usage() {
    std::wcout << L"Usage: obliterator [target-name-or-path] [options]\n\n"
               << L"Arguments:\n"
               << L"  [target-name-or-path]  Target directory or application name to wipe.\n"
               << L"                         If omitted, launches interactive program selector.\n\n"
               << L"Options:\n"
               << L"  --dry-run              Inspect and plan without modifying the system\n"
               << L"  --yes, -y              Skip confirmation prompt\n"
               << L"  --aggressive           Delete possible leftovers matching heuristic\n"
               << L"  --no-backup            Disable registry export to .reg before deletion\n"
               << L"  --no-handle-kill       Disable remote file handle duplication and closure\n"
               << L"  --timeout <sec>        Process kill wait timeout in seconds (default: 5)\n"
               << L"  --verbose, -v          Enable debug output\n"
               << L"  --json                 Output final report in JSON format\n"
               << L"  --bench                Run benchmark on target directory with stage timings\n"
               << L"  --force                Skip native uninstaller and obliterate directly\n"
               << L"  --native-only          Run native uninstaller only, skip forced obliteration\n"
               << L"  --native-timeout <sec> Native uninstaller wait timeout in seconds (default: 120)\n"
               << L"  --scan-portable <dir>  Scan directory for portable applications\n"
               << L"  --install-menu         Add 'Force Obliterate' to folder context menu in HKCU\n"
               << L"  --uninstall-menu       Remove 'Force Obliterate' from folder context menu\n"
               << L"  --help, -h             Display this help message\n";
}

Result<CommandLineOptions> CommandLineParser::parse(const std::vector<std::wstring>& args) {
    CommandLineOptions options;

    for (size_t i = 0; i < args.size(); ++i) {
        const std::wstring& arg = args[i];

        if (arg == L"--dry-run") {
            options.dry_run = true;
        } else if (arg == L"--yes" || arg == L"-y") {
            options.yes = true;
        } else if (arg == L"--verbose" || arg == L"-v") {
            options.verbose = true;
        } else if (arg == L"--no-handle-kill") {
            options.no_handle_kill = true;
        } else if (arg == L"--no-backup") {
            options.no_backup = true;
        } else if (arg == L"--aggressive") {
            options.aggressive = true;
        } else if (arg == L"--json") {
            options.json = true;
        } else if (arg == L"--bench") {
            options.bench = true;
        } else if (arg == L"--force") {
            options.force = true;
        } else if (arg == L"--native-only") {
            options.native_only = true;
        } else if (arg == L"--native-timeout") {
            if (i + 1 < args.size()) {
                try {
                    options.native_timeout_seconds = static_cast<uint32_t>(std::stoul(args[++i]));
                } catch (...) {
                    Logger::error(L"Invalid timeout value provided for --native-timeout");
                    return Win32Error::from_code(ERROR_INVALID_PARAMETER);
                }
            } else {
                Logger::error(L"Missing argument for --native-timeout");
                return Win32Error::from_code(ERROR_INVALID_PARAMETER);
            }
        } else if (arg == L"--scan-portable") {
            if (i + 1 < args.size() && !args[i + 1].starts_with(L"-")) {
                options.scan_portable_dir = args[++i];
            } else {
                options.scan_portable_dir = L".";
            }
        } else if (arg == L"--install-menu") {
            options.install_menu = true;
        } else if (arg == L"--uninstall-menu") {
            options.uninstall_menu = true;
        } else if (arg == L"--timeout") {
            if (i + 1 < args.size()) {
                try {
                    options.timeout_seconds = static_cast<uint32_t>(std::stoul(args[++i]));
                } catch (...) {
                    Logger::error(L"Invalid timeout value provided");
                    return Win32Error::from_code(ERROR_INVALID_PARAMETER);
                }
            } else {
                Logger::error(L"Missing argument for --timeout");
                return Win32Error::from_code(ERROR_INVALID_PARAMETER);
            }
        } else if (arg == L"--help" || arg == L"-h") {
            options.help_requested = true;
            return options;
        } else if (arg.starts_with(L"-")) {
            Logger::error(std::wstring(L"Unknown option: ") + arg);
            return Win32Error::from_code(ERROR_INVALID_PARAMETER);
        } else {
            if (options.target.empty()) {
                options.target = arg;
            } else {
                Logger::error(L"Multiple targets specified; provide at most one target.");
                return Win32Error::from_code(ERROR_INVALID_PARAMETER);
            }
        }
    }

    return options;
}

Result<CommandLineOptions> CommandLineParser::parse(int argc, const wchar_t* const argv[]) {
    std::vector<std::wstring> args;
    args.reserve(static_cast<size_t>(argc > 1 ? argc - 1 : 0));
    for (int i = 1; i < argc; ++i) {
        if (argv[i] != nullptr) {
            args.emplace_back(argv[i]);
        }
    }
    return parse(args);
}

} // namespace obliterator
