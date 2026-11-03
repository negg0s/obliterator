#include "obliterator/error.hpp"
#include "obliterator/log.hpp"
#include "obliterator/plan.hpp"
#include "obliterator/privileges.hpp"
#include "obliterator/target.hpp"

#include <iostream>
#include <string>
#include <string_view>

namespace obliterator {

struct CommandLineOptions {
    std::wstring target;
    bool dry_run{false};
    bool yes{false};
    bool verbose{false};
};

static void print_usage() {
    std::wcout << L"Usage: obliterator <target-name-or-path> [--dry-run] [--yes] [--verbose]\n\n"
               << L"Arguments:\n"
               << L"  <target-name-or-path>  Target directory or application name to wipe\n\n"
               << L"Options:\n"
               << L"  --dry-run              Inspect and plan without modifying the system\n"
               << L"  --yes, -y              Skip confirmation prompt\n"
               << L"  --verbose, -v          Enable debug output\n"
               << L"  --help, -h             Display this help message\n";
}

static Result<CommandLineOptions> parse_arguments(int argc, wchar_t* argv[]) {
    CommandLineOptions options;

    for (int i = 1; i < argc; ++i) {
        std::wstring_view arg = argv[i];

        if (arg == L"--dry-run") {
            options.dry_run = true;
        } else if (arg == L"--yes" || arg == L"-y") {
            options.yes = true;
        } else if (arg == L"--verbose" || arg == L"-v") {
            options.verbose = true;
        } else if (arg == L"--help" || arg == L"-h") {
            print_usage();
            ExitProcess(0);
        } else if (arg.starts_with(L"-")) {
            Logger::error(std::wstring(L"Unknown option: ") + std::wstring(arg));
            return Win32Error::from_code(ERROR_INVALID_PARAMETER);
        } else {
            if (options.target.empty()) {
                options.target = arg;
            } else {
                Logger::error(L"Multiple targets specified; provide exactly one target.");
                return Win32Error::from_code(ERROR_INVALID_PARAMETER);
            }
        }
    }

    if (options.target.empty()) {
        print_usage();
        return Win32Error::from_code(ERROR_BAD_ARGUMENTS);
    }

    return options;
}

} // namespace obliterator

int wmain(int argc, wchar_t* argv[]) {
    using namespace obliterator;

    auto parse_res = parse_arguments(argc, argv);
    if (!parse_res) {
        return 1;
    }

    const auto& options = parse_res.value();
    Logger::set_verbose(options.verbose);

    Logger::debug(L"Verbosity enabled");
    Logger::debug(std::wstring(L"Input target: ") + options.target);

    auto priv_res = enable_required_privileges();
    if (!priv_res) {
        Logger::warn(std::wstring(L"Could not assign all process privileges: ") +
                     priv_res.error().message());
    } else {
        Logger::debug(L"Required privileges enabled");
    }

    auto target_res = TargetResolver::resolve(options.target);
    if (!target_res) {
        Logger::error(L"Failed to resolve target: " + target_res.error().message());
        return 1;
    }

    const auto& target = target_res.value();
    Plan plan(target);

    if (options.dry_run) {
        Logger::info(L"Dry-run mode active; displaying plan without making modifications");
        plan.print();
        return 0;
    }

    plan.print();
    return 0;
}
