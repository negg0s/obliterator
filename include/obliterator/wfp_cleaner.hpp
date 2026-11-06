#pragma once

#include "obliterator/target.hpp"

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace obliterator {

struct DiscoveredWfpFilter {
    uint64_t filter_id = 0;
    std::wstring name;
    std::wstring description;
    std::wstring provider_name;
    std::wstring match_reason;
};

struct DiscoveredWfpProvider {
    std::wstring provider_key_guid;
    std::wstring name;
    std::wstring description;
    std::wstring service_name;
    std::wstring match_reason;
};

struct WfpCleanReport {
    size_t filters_removed = 0;
    size_t providers_removed = 0;
    std::vector<DiscoveredWfpFilter> removed_filters;
    std::vector<DiscoveredWfpProvider> removed_providers;
};

class WfpCleaner {
public:
    static bool is_wfp_available();

    static std::vector<DiscoveredWfpProvider> discover_providers(const Target& target);
    static std::vector<DiscoveredWfpFilter> discover_filters(const Target& target);

    static WfpCleanReport clean_wfp_artifacts(const Target& target, bool dry_run);
};

} // namespace obliterator
