#include "obliterator/wfp_cleaner.hpp"
#include "obliterator/log.hpp"
#include "obliterator/path.hpp"

#include <windows.h>
#include <objbase.h>
#include <fwpmu.h>

#include <algorithm>
#include <cwctype>
#include <vector>

namespace obliterator {

typedef DWORD (WINAPI *PFN_FwpmEngineOpen0)(
    const wchar_t* serverName,
    UINT32 authnService,
    SEC_WINNT_AUTH_IDENTITY_W* authIdentity,
    const FWPM_SESSION0* session,
    HANDLE* engineHandle
);

typedef DWORD (WINAPI *PFN_FwpmEngineClose0)(
    HANDLE engineHandle
);

typedef DWORD (WINAPI *PFN_FwpmProviderCreateEnumHandle0)(
    HANDLE engineHandle,
    const FWPM_PROVIDER_ENUM_TEMPLATE0* enumTemplate,
    HANDLE* enumHandle
);

typedef DWORD (WINAPI *PFN_FwpmProviderEnum0)(
    HANDLE engineHandle,
    HANDLE enumHandle,
    UINT32 numEntriesRequested,
    FWPM_PROVIDER0*** entries,
    UINT32* numEntriesReturned
);

typedef DWORD (WINAPI *PFN_FwpmProviderDestroyEnumHandle0)(
    HANDLE engineHandle,
    HANDLE enumHandle
);

typedef DWORD (WINAPI *PFN_FwpmProviderDeleteByKey0)(
    HANDLE engineHandle,
    const GUID* key
);

typedef DWORD (WINAPI *PFN_FwpmFreeMemory0)(
    void** p
);

typedef DWORD (WINAPI *PFN_FwpmFilterCreateEnumHandle0)(
    HANDLE engineHandle,
    const FWPM_FILTER_ENUM_TEMPLATE0* enumTemplate,
    HANDLE* enumHandle
);

typedef DWORD (WINAPI *PFN_FwpmFilterEnum0)(
    HANDLE engineHandle,
    HANDLE enumHandle,
    UINT32 numEntriesRequested,
    FWPM_FILTER0*** entries,
    UINT32* numEntriesReturned
);

typedef DWORD (WINAPI *PFN_FwpmFilterDestroyEnumHandle0)(
    HANDLE engineHandle,
    HANDLE enumHandle
);

typedef DWORD (WINAPI *PFN_FwpmFilterDeleteById0)(
    HANDLE engineHandle,
    UINT64 id
);

struct WfpFunctions {
    HMODULE hLib = nullptr;
    PFN_FwpmEngineOpen0 fnOpen = nullptr;
    PFN_FwpmEngineClose0 fnClose = nullptr;
    PFN_FwpmProviderCreateEnumHandle0 fnProvCreateEnum = nullptr;
    PFN_FwpmProviderEnum0 fnProvEnum = nullptr;
    PFN_FwpmProviderDestroyEnumHandle0 fnProvDestroyEnum = nullptr;
    PFN_FwpmProviderDeleteByKey0 fnProvDeleteByKey = nullptr;
    PFN_FwpmFilterCreateEnumHandle0 fnFilterCreateEnum = nullptr;
    PFN_FwpmFilterEnum0 fnFilterEnum = nullptr;
    PFN_FwpmFilterDestroyEnumHandle0 fnFilterDestroyEnum = nullptr;
    PFN_FwpmFilterDeleteById0 fnFilterDeleteById = nullptr;
    PFN_FwpmFreeMemory0 fnFree = nullptr;

    WfpFunctions() {
        hLib = LoadLibraryW(L"fwpuclnt.dll");
        if (hLib) {
            fnOpen = reinterpret_cast<PFN_FwpmEngineOpen0>(GetProcAddress(hLib, "FwpmEngineOpen0"));
            fnClose = reinterpret_cast<PFN_FwpmEngineClose0>(GetProcAddress(hLib, "FwpmEngineClose0"));
            fnProvCreateEnum = reinterpret_cast<PFN_FwpmProviderCreateEnumHandle0>(GetProcAddress(hLib, "FwpmProviderCreateEnumHandle0"));
            fnProvEnum = reinterpret_cast<PFN_FwpmProviderEnum0>(GetProcAddress(hLib, "FwpmProviderEnum0"));
            fnProvDestroyEnum = reinterpret_cast<PFN_FwpmProviderDestroyEnumHandle0>(GetProcAddress(hLib, "FwpmProviderDestroyEnumHandle0"));
            fnProvDeleteByKey = reinterpret_cast<PFN_FwpmProviderDeleteByKey0>(GetProcAddress(hLib, "FwpmProviderDeleteByKey0"));
            fnFilterCreateEnum = reinterpret_cast<PFN_FwpmFilterCreateEnumHandle0>(GetProcAddress(hLib, "FwpmFilterCreateEnumHandle0"));
            fnFilterEnum = reinterpret_cast<PFN_FwpmFilterEnum0>(GetProcAddress(hLib, "FwpmFilterEnum0"));
            fnFilterDestroyEnum = reinterpret_cast<PFN_FwpmFilterDestroyEnumHandle0>(GetProcAddress(hLib, "FwpmFilterDestroyEnumHandle0"));
            fnFilterDeleteById = reinterpret_cast<PFN_FwpmFilterDeleteById0>(GetProcAddress(hLib, "FwpmFilterDeleteById0"));
            fnFree = reinterpret_cast<PFN_FwpmFreeMemory0>(GetProcAddress(hLib, "FwpmFreeMemory0"));
        }
    }

    ~WfpFunctions() {
        if (hLib) {
            FreeLibrary(hLib);
        }
    }

    [[nodiscard]] bool valid() const noexcept {
        return hLib && fnOpen && fnClose && fnProvCreateEnum && fnProvEnum &&
               fnProvDestroyEnum && fnProvDeleteByKey && fnFilterCreateEnum &&
               fnFilterEnum && fnFilterDestroyEnum && fnFilterDeleteById && fnFree;
    }
};

static bool string_equals_ignore_case(std::wstring_view a, std::wstring_view b) {
    if (a.size() != b.size()) {
        return false;
    }
    for (size_t i = 0; i < a.size(); ++i) {
        if (std::towlower(a[i]) != std::towlower(b[i])) {
            return false;
        }
    }
    return true;
}

static bool string_contains_ignore_case(std::wstring_view text, std::wstring_view needle) {
    if (needle.empty() || text.empty()) {
        return false;
    }
    const std::wstring t_lower = PathHelper::to_lower_unicode(text);
    const std::wstring n_lower = PathHelper::to_lower_unicode(needle);
    return t_lower.find(n_lower) != std::wstring::npos;
}

static bool is_protected_wfp_name(std::wstring_view name) {
    static const wchar_t* const protected_names[] = {
        L"Microsoft",
        L"Windows",
        L"Base Filtering Engine",
        L"IPsec",
        L"Firewall",
        L"Defender"
    };
    for (const auto* p : protected_names) {
        if (string_contains_ignore_case(name, p)) {
            return true;
        }
    }
    return false;
}

static std::wstring guid_to_string(const GUID& guid) {
    wchar_t buf[64] = {0};
    if (StringFromGUID2(guid, buf, 64) > 0) {
        return buf;
    }
    return {};
}

bool WfpCleaner::is_wfp_available() {
    WfpFunctions wfp;
    return wfp.valid();
}

std::vector<DiscoveredWfpProvider> WfpCleaner::discover_providers(const Target& target) {
    std::vector<DiscoveredWfpProvider> matches;
    if (target.name.empty() && target.publisher.empty()) {
        return matches;
    }

    WfpFunctions wfp;
    if (!wfp.valid()) {
        return matches;
    }

    HANDLE hEngine = nullptr;
    FWPM_SESSION0 session{};
    session.displayData.name = const_cast<wchar_t*>(L"obliterator_session");
    if (wfp.fnOpen(nullptr, RPC_C_AUTHN_DEFAULT, nullptr, &session, &hEngine) != ERROR_SUCCESS || !hEngine) {
        return matches;
    }

    HANDLE hEnum = nullptr;
    if (wfp.fnProvCreateEnum(hEngine, nullptr, &hEnum) == ERROR_SUCCESS && hEnum) {
        FWPM_PROVIDER0** entries = nullptr;
        UINT32 returned = 0;

        while (wfp.fnProvEnum(hEngine, hEnum, 50, &entries, &returned) == ERROR_SUCCESS && returned > 0) {
            for (UINT32 i = 0; i < returned; ++i) {
                const auto* prov = entries[i];
                if (!prov) continue;

                std::wstring name = prov->displayData.name ? prov->displayData.name : L"";
                std::wstring desc = prov->displayData.description ? prov->displayData.description : L"";
                std::wstring svc = prov->serviceName ? prov->serviceName : L"";

                if (is_protected_wfp_name(name) || is_protected_wfp_name(desc)) {
                    continue;
                }

                bool matched = false;
                std::wstring reason;

                if (!target.publisher.empty()) {
                    if (string_equals_ignore_case(name, target.publisher) ||
                        string_equals_ignore_case(desc, target.publisher)) {
                        matched = true;
                        reason = L"WFP provider name/description exact match to publisher: " + target.publisher;
                    } else if (string_contains_ignore_case(name, target.publisher) ||
                               string_contains_ignore_case(desc, target.publisher)) {
                        matched = true;
                        reason = L"WFP provider name/description contains publisher: " + target.publisher;
                    }
                }

                if (!matched && !target.name.empty()) {
                    if (string_equals_ignore_case(name, target.name) ||
                        string_equals_ignore_case(desc, target.name)) {
                        matched = true;
                        reason = L"WFP provider name/description exact match to product: " + target.name;
                    } else if (string_contains_ignore_case(name, target.name) ||
                               string_contains_ignore_case(desc, target.name)) {
                        matched = true;
                        reason = L"WFP provider name/description contains product: " + target.name;
                    }
                }

                if (matched) {
                    DiscoveredWfpProvider item;
                    item.provider_key_guid = guid_to_string(prov->providerKey);
                    item.name = name;
                    item.description = desc;
                    item.service_name = svc;
                    item.match_reason = reason;
                    matches.push_back(std::move(item));
                }
            }

            wfp.fnFree(reinterpret_cast<void**>(&entries));
        }

        wfp.fnProvDestroyEnum(hEngine, hEnum);
    }

    wfp.fnClose(hEngine);
    return matches;
}

std::vector<DiscoveredWfpFilter> WfpCleaner::discover_filters(const Target& target) {
    std::vector<DiscoveredWfpFilter> matches;
    if (target.name.empty() && target.publisher.empty()) {
        return matches;
    }

    WfpFunctions wfp;
    if (!wfp.valid()) {
        return matches;
    }

    HANDLE hEngine = nullptr;
    FWPM_SESSION0 session{};
    session.displayData.name = const_cast<wchar_t*>(L"obliterator_session");
    if (wfp.fnOpen(nullptr, RPC_C_AUTHN_DEFAULT, nullptr, &session, &hEngine) != ERROR_SUCCESS || !hEngine) {
        return matches;
    }

    HANDLE hEnum = nullptr;
    if (wfp.fnFilterCreateEnum(hEngine, nullptr, &hEnum) == ERROR_SUCCESS && hEnum) {
        FWPM_FILTER0** entries = nullptr;
        UINT32 returned = 0;

        while (wfp.fnFilterEnum(hEngine, hEnum, 50, &entries, &returned) == ERROR_SUCCESS && returned > 0) {
            for (UINT32 i = 0; i < returned; ++i) {
                const auto* filter = entries[i];
                if (!filter) continue;

                std::wstring name = filter->displayData.name ? filter->displayData.name : L"";
                std::wstring desc = filter->displayData.description ? filter->displayData.description : L"";

                if (is_protected_wfp_name(name) || is_protected_wfp_name(desc)) {
                    continue;
                }

                bool matched = false;
                std::wstring reason;

                if (!target.publisher.empty()) {
                    if (string_contains_ignore_case(name, target.publisher) ||
                        string_contains_ignore_case(desc, target.publisher)) {
                        matched = true;
                        reason = L"WFP filter references target publisher: " + target.publisher;
                    }
                }

                if (!matched && !target.name.empty()) {
                    if (string_contains_ignore_case(name, target.name) ||
                        string_contains_ignore_case(desc, target.name)) {
                        matched = true;
                        reason = L"WFP filter references target product name: " + target.name;
                    }
                }

                if (matched) {
                    DiscoveredWfpFilter item;
                    item.filter_id = filter->filterId;
                    item.name = name;
                    item.description = desc;
                    item.match_reason = reason;
                    matches.push_back(std::move(item));
                }
            }

            wfp.fnFree(reinterpret_cast<void**>(&entries));
        }

        wfp.fnFilterDestroyEnum(hEngine, hEnum);
    }

    wfp.fnClose(hEngine);
    return matches;
}

WfpCleanReport WfpCleaner::clean_wfp_artifacts(const Target& target, bool dry_run) {
    WfpCleanReport report;
    auto filters = discover_filters(target);
    auto providers = discover_providers(target);

    if (filters.empty() && providers.empty()) {
        return report;
    }

    if (dry_run) {
        for (const auto& f : filters) {
            Logger::info(L"[DRY-RUN] Would remove WFP filter ID " + std::to_wstring(f.filter_id) +
                         L" (" + f.name + L")");
            report.filters_removed++;
            report.removed_filters.push_back(f);
        }
        for (const auto& p : providers) {
            Logger::info(L"[DRY-RUN] Would remove WFP provider: " + p.name +
                         L" (" + p.provider_key_guid + L")");
            report.providers_removed++;
            report.removed_providers.push_back(p);
        }
        return report;
    }

    WfpFunctions wfp;
    if (!wfp.valid()) {
        return report;
    }

    HANDLE hEngine = nullptr;
    FWPM_SESSION0 session{};
    session.displayData.name = const_cast<wchar_t*>(L"obliterator_session");
    if (wfp.fnOpen(nullptr, RPC_C_AUTHN_DEFAULT, nullptr, &session, &hEngine) != ERROR_SUCCESS || !hEngine) {
        Logger::warn(L"Could not open WFP engine for cleanup.");
        return report;
    }

    // 1. Delete filters
    for (const auto& f : filters) {
        if (wfp.fnFilterDeleteById(hEngine, f.filter_id) == ERROR_SUCCESS) {
            Logger::info(L"Purged WFP filter ID " + std::to_wstring(f.filter_id) + L" (" + f.name + L")");
            report.filters_removed++;
            report.removed_filters.push_back(f);
        } else {
            Logger::warn(L"Failed to delete WFP filter ID " + std::to_wstring(f.filter_id));
        }
    }

    // 2. Delete providers
    for (const auto& p : providers) {
        GUID guid{};
        if (SUCCEEDED(CLSIDFromString(p.provider_key_guid.c_str(), &guid))) {
            if (wfp.fnProvDeleteByKey(hEngine, &guid) == ERROR_SUCCESS) {
                Logger::info(L"Purged WFP provider: " + p.name + L" (" + p.provider_key_guid + L")");
                report.providers_removed++;
                report.removed_providers.push_back(p);
            } else {
                Logger::warn(L"Failed to delete WFP provider: " + p.name);
            }
        }
    }

    wfp.fnClose(hEngine);
    return report;
}

} // namespace obliterator
