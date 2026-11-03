#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include "obliterator/confidence_config.hpp"
#include "obliterator/target.hpp"
#include "obliterator/ui.hpp"

#include <string>
#include <string_view>
#include <vector>

namespace obliterator {

enum class ArtifactKind {
    File,
    Folder,
    RegistryKey,
    RegistryValue,
    Service,
    Task,
    FirewallRule,
    Shortcut
};

enum class ArtifactConfidenceCategory {
    Safe,
    Review,
    Skip
};

struct ArtifactEvidence {
    std::wstring rule_id;
    int weight{0};
    std::wstring description;
};

struct ScoredArtifact {
    std::wstring identifier;
    ArtifactKind kind{ArtifactKind::Folder};
    int score{0};
    ArtifactConfidenceCategory category{ArtifactConfidenceCategory::Skip};
    std::vector<ArtifactEvidence> reasons;
    bool is_protected{false};
    bool referenced_by_other_app{false};
    std::wstring conflicting_app_name;
    bool generic_name_zeroed{false};

    std::wstring category_string() const;
    std::wstring kind_string() const;
};

struct ArtifactCandidate {
    std::wstring identifier;
    ArtifactKind kind{ArtifactKind::Folder};
    std::wstring referenced_path;
    std::wstring guid;
    bool is_clsid{false};
    bool is_typelib{false};
    bool is_app_path{false};
    bool is_association_or_cache{false};
    bool is_guid_match{false};
};

class ConfidenceEngine {
public:
    static bool is_generic_name(std::wstring_view name);

    static ScoredArtifact evaluate(
        const ArtifactCandidate& candidate,
        const Target& target,
        const std::vector<InstalledAppInfo>& other_installed_apps = {}
    );

    static ScoredArtifact evaluate(
        const std::wstring& identifier,
        ArtifactKind kind,
        const Target& target,
        const std::vector<InstalledAppInfo>& other_installed_apps = {},
        const std::wstring& referenced_path = {}
    );

    static std::vector<ScoredArtifact> discover_artifacts(
        const Target& target,
        const std::vector<InstalledAppInfo>& other_installed_apps = {}
    );

    static void explain(
        const std::wstring& artifact_id,
        const std::vector<InstalledAppInfo>& installed_apps
    );
};

} // namespace obliterator
