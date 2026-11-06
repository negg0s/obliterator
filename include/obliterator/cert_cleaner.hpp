#pragma once

#include "obliterator/target.hpp"

#include <string>
#include <string_view>
#include <vector>

namespace obliterator {

struct DiscoveredCertificate {
    std::wstring store_name;
    bool is_local_machine = false;
    std::wstring subject_name;
    std::wstring issuer_name;
    std::wstring sha1_thumbprint;
    std::wstring match_reason;
};

struct CertCleanReport {
    size_t certificates_removed = 0;
    std::vector<DiscoveredCertificate> removed_certificates;
};

class CertificateCleaner {
public:
    static bool is_protected_root_ca(std::wstring_view name);

    static std::vector<DiscoveredCertificate> discover_target_certificates(const Target& target);

    static size_t purge_certificate(const DiscoveredCertificate& cert, bool dry_run);
    static CertCleanReport clean_certificates(const Target& target, bool dry_run);
};

} // namespace obliterator
