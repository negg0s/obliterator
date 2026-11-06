#include "obliterator/cert_cleaner.hpp"
#include "obliterator/log.hpp"
#include "obliterator/path.hpp"

#include <windows.h>
#include <wincrypt.h>

#include <algorithm>
#include <cwctype>
#include <iomanip>
#include <sstream>
#include <vector>

namespace obliterator {

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

static std::wstring get_cert_name(PCCERT_CONTEXT pCert, DWORD type_flags) {
    DWORD chars = CertGetNameStringW(pCert, CERT_NAME_SIMPLE_DISPLAY_TYPE, type_flags, nullptr, nullptr, 0);
    if (chars <= 1) {
        return {};
    }
    std::vector<wchar_t> buf(chars + 1, L'\0');
    CertGetNameStringW(pCert, CERT_NAME_SIMPLE_DISPLAY_TYPE, type_flags, nullptr, buf.data(), chars);
    return buf.data();
}

static std::wstring get_cert_thumbprint_hex(PCCERT_CONTEXT pCert, std::vector<BYTE>& out_raw) {
    BYTE hash[20] = {0};
    DWORD len = sizeof(hash);
    if (!CertGetCertificateContextProperty(pCert, CERT_SHA1_HASH_PROP_ID, hash, &len)) {
        return {};
    }

    out_raw.assign(hash, hash + len);

    std::wostringstream oss;
    oss << std::hex << std::uppercase << std::setfill(L'0');
    for (DWORD i = 0; i < len; ++i) {
        oss << std::setw(2) << static_cast<int>(hash[i]);
    }
    return oss.str();
}

static std::vector<BYTE> parse_hex_thumbprint(std::wstring_view hex) {
    std::vector<BYTE> bytes;
    if (hex.size() % 2 != 0) {
        return bytes;
    }
    bytes.reserve(hex.size() / 2);
    for (size_t i = 0; i < hex.size(); i += 2) {
        wchar_t buf[3] = { hex[i], hex[i + 1], L'\0' };
        wchar_t* end = nullptr;
        unsigned long val = wcstoul(buf, &end, 16);
        bytes.push_back(static_cast<BYTE>(val));
    }
    return bytes;
}

bool CertificateCleaner::is_protected_root_ca(std::wstring_view name) {
    static const wchar_t* const protected_cas[] = {
        L"Microsoft",
        L"Windows",
        L"DigiCert",
        L"VeriSign",
        L"GlobalSign",
        L"Let's Encrypt",
        L"Baltimore CyberTrust",
        L"Sectigo",
        L"USERTrust",
        L"Google Trust Services",
        L"Amazon Root",
        L"Entrust",
        L"Thawte",
        L"GeoTrust",
        L"AAA Certificate Services"
    };

    for (const auto* ca : protected_cas) {
        if (string_contains_ignore_case(name, ca)) {
            return true;
        }
    }
    return false;
}

static void scan_store(
    const wchar_t* store_name,
    DWORD store_location,
    const Target& target,
    std::vector<DiscoveredCertificate>& out_certs
) {
    HCERTSTORE hStore = CertOpenStore(
        CERT_STORE_PROV_SYSTEM_W,
        0,
        0,
        store_location | CERT_STORE_OPEN_EXISTING_FLAG | CERT_STORE_READONLY_FLAG,
        store_name
    );

    if (!hStore) {
        return;
    }

    const bool is_lm = (store_location == CERT_SYSTEM_STORE_LOCAL_MACHINE);
    PCCERT_CONTEXT pCert = nullptr;

    while ((pCert = CertEnumCertificatesInStore(hStore, pCert)) != nullptr) {
        std::wstring subject = get_cert_name(pCert, 0);
        std::wstring issuer = get_cert_name(pCert, CERT_NAME_ISSUER_FLAG);

        if (CertificateCleaner::is_protected_root_ca(subject) ||
            CertificateCleaner::is_protected_root_ca(issuer)) {
            continue;
        }

        bool matched = false;
        std::wstring reason;

        if (!target.publisher.empty()) {
            if (string_equals_ignore_case(subject, target.publisher) ||
                string_equals_ignore_case(issuer, target.publisher)) {
                matched = true;
                reason = L"certificate subject or issuer matches target publisher: " + target.publisher;
            } else if (string_contains_ignore_case(subject, target.publisher) ||
                       string_contains_ignore_case(issuer, target.publisher)) {
                matched = true;
                reason = L"certificate subject or issuer contains target publisher: " + target.publisher;
            }
        }

        if (!matched && !target.name.empty()) {
            if (string_equals_ignore_case(subject, target.name) ||
                string_equals_ignore_case(issuer, target.name)) {
                matched = true;
                reason = L"certificate subject or issuer exact match to product name: " + target.name;
            } else if (string_contains_ignore_case(subject, target.name) ||
                       string_contains_ignore_case(issuer, target.name)) {
                matched = true;
                reason = L"certificate subject or issuer contains product name: " + target.name;
            }
        }

        if (matched) {
            std::vector<BYTE> raw_hash;
            std::wstring hex_hash = get_cert_thumbprint_hex(pCert, raw_hash);

            DiscoveredCertificate item;
            item.store_name = store_name;
            item.is_local_machine = is_lm;
            item.subject_name = subject;
            item.issuer_name = issuer;
            item.sha1_thumbprint = hex_hash;
            item.match_reason = reason;
            out_certs.push_back(std::move(item));
        }
    }

    CertCloseStore(hStore, 0);
}

std::vector<DiscoveredCertificate> CertificateCleaner::discover_target_certificates(const Target& target) {
    std::vector<DiscoveredCertificate> discovered;
    if (target.name.empty() && target.publisher.empty()) {
        return discovered;
    }

    static const wchar_t* const stores[] = {
        L"ROOT",
        L"CA",
        L"TrustedPublisher",
        L"MY"
    };

    for (const auto* s : stores) {
        scan_store(s, CERT_SYSTEM_STORE_LOCAL_MACHINE, target, discovered);
        scan_store(s, CERT_SYSTEM_STORE_CURRENT_USER, target, discovered);
    }

    return discovered;
}

size_t CertificateCleaner::purge_certificate(const DiscoveredCertificate& cert, bool dry_run) {
    if (dry_run) {
        Logger::info(L"[DRY-RUN] Would remove certificate: " + cert.subject_name +
                     L" from store " + cert.store_name +
                     (cert.is_local_machine ? L" (LocalMachine)" : L" (CurrentUser)"));
        return 1;
    }

    DWORD loc = cert.is_local_machine ? CERT_SYSTEM_STORE_LOCAL_MACHINE : CERT_SYSTEM_STORE_CURRENT_USER;
    HCERTSTORE hStore = CertOpenStore(
        CERT_STORE_PROV_SYSTEM_W,
        0,
        0,
        loc | CERT_STORE_OPEN_EXISTING_FLAG,
        cert.store_name.c_str()
    );

    if (!hStore) {
        Logger::warn(L"Could not open certificate store for deletion: " + cert.store_name);
        return 0;
    }

    std::vector<BYTE> raw_hash = parse_hex_thumbprint(cert.sha1_thumbprint);
    if (raw_hash.empty()) {
        CertCloseStore(hStore, 0);
        return 0;
    }

    CRYPT_HASH_BLOB blob{};
    blob.cbData = static_cast<DWORD>(raw_hash.size());
    blob.pbData = raw_hash.data();

    PCCERT_CONTEXT pFound = CertFindCertificateInStore(
        hStore,
        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
        0,
        CERT_FIND_SHA1_HASH,
        &blob,
        nullptr
    );

    size_t removed = 0;
    if (pFound) {
        if (CertDeleteCertificateFromStore(pFound)) {
            Logger::info(L"Purged certificate from store " + cert.store_name + L": " + cert.subject_name);
            removed = 1;
        } else {
            Logger::warn(L"Failed to delete certificate: " + cert.subject_name);
        }
    }

    CertCloseStore(hStore, 0);
    return removed;
}

CertCleanReport CertificateCleaner::clean_certificates(const Target& target, bool dry_run) {
    CertCleanReport report;
    auto certs = discover_target_certificates(target);
    for (const auto& c : certs) {
        size_t r = purge_certificate(c, dry_run);
        if (r > 0) {
            report.certificates_removed++;
            report.removed_certificates.push_back(c);
        }
    }
    return report;
}

} // namespace obliterator
