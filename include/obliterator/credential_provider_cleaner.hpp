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

struct CredentialProviderCleanReport {
    size_t providers_removed{0};
    size_t filters_removed{0};
    size_t plap_providers_removed{0};
    std::vector<std::wstring> details;
};

class CredentialProviderCleaner {
public:
    static CredentialProviderCleanReport clean_credential_providers(const Target& target, bool dry_run);

private:
    static bool is_protected_provider_guid(const std::wstring& guid_str);
    static bool matches_target(const std::wstring& name, const Target& target);
    static bool inspect_clsid_server(HKEY root, const std::wstring& clsid_str, const Target& target);
};

} // namespace obliterator
