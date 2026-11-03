#pragma once

#include <array>
#include <string>
#include <string_view>
#include <vector>

namespace obliterator {

struct ConfidenceWeights {
    // High weight: Direct reference to installation path in value or executable
    static constexpr int kDirectPathReference = 100;

    // High weight: CLSID and TypeLib whose InprocServer32 / LocalServer32 point into target folder
    static constexpr int kClsidOrTypeLib = 90;

    // High weight: Matching product GUID from Uninstall or MSI
    static constexpr int kProductGuidMatch = 85;

    // High weight: App Paths, file associations (ProgID, OpenWithList), MUICache, ShimCache
    static constexpr int kAppPathsOrFileAssociations = 80;

    // Medium-high weight: Product folder inside publisher directory (e.g. Vendor\Product)
    static constexpr int kPublisherSubfolderProduct = 60;

    // Medium weight: Match of publisher or product name with folder or key name
    static constexpr int kExactProductOrPublisherMatch = 50;

    // Low weight: Partial product name match
    static constexpr int kPartialNameMatch = 20;

    // Zero weight for generic names without other proof
    static constexpr int kGenericNameWithoutProof = 0;

    // Thresholds
    static constexpr int kSafeThreshold = 75;
    static constexpr int kReviewThreshold = 40;
};

// Generic names that receive zero weight unless backed by direct path, CLSID, or GUID evidence
inline const std::vector<std::wstring>& get_generic_names() {
    static const std::vector<std::wstring> kGenerics = {
        L"common",
        L"common files",
        L"data",
        L"cache",
        L"config",
        L"configuration",
        L"shared",
        L"temp",
        L"tmp",
        L"logs",
        L"log",
        L"plugins",
        L"updates",
        L"settings"
    };
    return kGenerics;
}

} // namespace obliterator
