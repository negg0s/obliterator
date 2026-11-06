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

struct AppCompatCleanReport {
    size_t layers_values_removed{0};
    size_t store_values_removed{0};
    size_t custom_keys_removed{0};
    std::vector<std::wstring> details;
};

class AppCompatCleaner {
public:
    static AppCompatCleanReport clean_app_compat(const Target& target, bool dry_run);

private:
    static void clean_layers_values(const Target& target, bool dry_run, AppCompatCleanReport& report);
    static void clean_store_values(const Target& target, bool dry_run, AppCompatCleanReport& report);
    static void clean_custom_keys(const Target& target, bool dry_run, AppCompatCleanReport& report);
    static bool path_references_target(const std::wstring& path, const Target& target);
};

} // namespace obliterator
