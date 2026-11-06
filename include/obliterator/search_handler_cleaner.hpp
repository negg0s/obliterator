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

struct SearchHandlerCleanReport {
    size_t protocol_handlers_removed{0};
    std::vector<std::wstring> details;
};

class SearchHandlerCleaner {
public:
    static SearchHandlerCleanReport clean_search_handlers(const Target& target, bool dry_run);

private:
    static bool is_protected_protocol(const std::wstring& protocol);
    static bool matches_target(const std::wstring& name, const Target& target);
    static bool inspect_clsid_server(HKEY root, const std::wstring& clsid_str, const Target& target);
};

} // namespace obliterator
