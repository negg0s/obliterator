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

struct PrintCleanReport {
    size_t monitors_removed{0};
    size_t processors_removed{0};
    size_t printers_removed{0};
    std::vector<std::wstring> details;
};

class PrintCleaner {
public:
    static PrintCleanReport clean_print_artifacts(const Target& target, bool dry_run);

private:
    static bool is_protected_monitor(const std::wstring& name);
    static bool is_protected_processor(const std::wstring& name);
    static bool is_protected_printer(const std::wstring& name);
    static bool matches_target(const std::wstring& name, const Target& target);
    static bool path_references_target(const std::wstring& path, const Target& target);
};

} // namespace obliterator
