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
               << L"  --explain <artifact>   Explain confidence score and reasons for an artifact\n"
               << L"  --all-users            Clean traces in all user profiles on this system\n"
               << L"  --user <name-or-sid>   Clean traces in specified user profile\n"
               << L"  --include-system-profiles Include service accounts (SYSTEM, LocalService, NetworkService)\n"
               << L"  --resume               Resume cleanup after system reboot from saved state\n"
               << L"  --safe-mode-plan       Display Safe Mode removal plan and boot configuration\n"
               << L"  --quarantine           Move files to quarantine instead of deleting\n"
               << L"  --quarantine-dir <dir> Custom base directory for quarantine storage\n"
               << L"  --rpc                  Start headless JSON-RPC automation server on stdin/stdout\n"
               << L"  --batch <file>         Obliterate targets listed sequentially in a batch file\n"
               << L"  --no-restore-point     Skip creating a system restore point\n"
               << L"  --require-restore-point Abort if system restore point creation fails\n"
               << L"  --list-sessions        List past quarantine and cleanup sessions\n"
               << L"  --restore <id>         Restore files, ACLs, and registry keys from quarantine session\n"
               << L"  --purge-quarantine <id|--older-than Nd> Purge quarantine session or sessions older than N days\n"
               << L"  --install-menu         Add 'Force Obliterate' to folder context menu in HKCU\n"
               << L"  --uninstall-menu       Remove 'Force Obliterate' from folder context menu\n"
               << L"  --diagnose [file]      Collect sanitized system diagnostics for bug reports\n"
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
        } else if (arg == L"--explain") {
            if (i + 1 < args.size()) {
                options.explain_artifact = args[++i];
            } else {
                Logger::error(L"Missing artifact argument for --explain");
                return Win32Error::from_code(ERROR_INVALID_PARAMETER);
            }
        } else if (arg == L"--all-users") {
            options.all_users = true;
        } else if (arg == L"--user") {
            if (i + 1 < args.size()) {
                options.user_filter = args[++i];
            } else {
                Logger::error(L"Missing user name or SID argument for --user");
                return Win32Error::from_code(ERROR_INVALID_PARAMETER);
            }
        } else if (arg == L"--include-system-profiles") {
            options.include_system_profiles = true;
        } else if (arg == L"--resume") {
            options.resume = true;
        } else if (arg == L"--safe-mode-plan") {
            options.safe_mode_plan = true;
        } else if (arg == L"--quarantine") {
            options.quarantine = true;
        } else if (arg == L"--quarantine-dir") {
            if (i + 1 < args.size()) {
                options.quarantine_dir = args[++i];
                options.quarantine = true;
            } else {
                Logger::error(L"Missing directory argument for --quarantine-dir");
                return Win32Error::from_code(ERROR_INVALID_PARAMETER);
            }
        } else if (arg == L"--rpc") {
            options.rpc = true;
        } else if (arg == L"--batch") {
            if (i + 1 < args.size()) {
                options.batch_file = args[++i];
            } else {
                Logger::error(L"Missing batch file argument for --batch");
                return Win32Error::from_code(ERROR_INVALID_PARAMETER);
            }
        } else if (arg == L"--no-restore-point") {
            options.no_restore_point = true;
        } else if (arg == L"--require-restore-point") {
            options.require_restore_point = true;
        } else if (arg == L"--list-sessions") {
            options.list_sessions = true;
        } else if (arg == L"--restore") {
            if (i + 1 < args.size() && !args[i + 1].starts_with(L"-")) {
                options.restore_session_id = args[++i];
            } else {
                Logger::error(L"Missing session id argument for --restore");
                return Win32Error::from_code(ERROR_INVALID_PARAMETER);
            }
        } else if (arg == L"--purge-quarantine") {
            if (i + 1 < args.size()) {
                if (args[i + 1] == L"--older-than" && i + 2 < args.size()) {
                    options.purge_quarantine_arg = L"--older-than " + args[i + 2];
                    i += 2;
                } else if (!args[i + 1].starts_with(L"-")) {
                    options.purge_quarantine_arg = args[++i];
                } else {
                    Logger::error(L"Invalid argument for --purge-quarantine");
                    return Win32Error::from_code(ERROR_INVALID_PARAMETER);
                }
            } else {
                Logger::error(L"Missing argument for --purge-quarantine");
                return Win32Error::from_code(ERROR_INVALID_PARAMETER);
            }
        } else if (arg == L"--install-menu") {
            options.install_menu = true;
        } else if (arg == L"--uninstall-menu") {
            options.uninstall_menu = true;
        } else if (arg == L"--diagnose") {
            options.diagnose = true;
            if (i + 1 < args.size() && !args[i + 1].starts_with(L"-")) {
                options.diagnose_output_file = args[++i];
            } else {
                options.diagnose_output_file = L"obliterator-diagnose.txt";
            }
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
