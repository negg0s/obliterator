#include "obliterator/confidence_engine.hpp"
#include "obliterator/handles.hpp"
#include "obliterator/leftovers.hpp"
#include "obliterator/log.hpp"
#include "obliterator/path.hpp"
#include "obliterator/profile.hpp"
#include "obliterator/registry_cleaner.hpp"
#include "obliterator/safety.hpp"
#include "obliterator/uninstaller.hpp"

#include <algorithm>
#include <cwctype>
#include <filesystem>
#include <iostream>

namespace obliterator {

static std::wstring to_lower_str(std::wstring_view sv) {
    return PathHelper::to_lower_unicode(sv);
}

static bool equals_ignore_case(std::wstring_view a, std::wstring_view b) {
    return to_lower_str(a) == to_lower_str(b);
}

static bool contains_ignore_case(std::wstring_view text, std::wstring_view pattern) {
    if (pattern.empty() || text.empty()) {
        return false;
    }
    return to_lower_str(text).find(to_lower_str(pattern)) != std::wstring_view::npos;
}

static std::wstring trim_spaces_and_slashes(std::wstring_view s) {
    size_t start = 0;
    while (start < s.size() && (s[start] == L' ' || s[start] == L'\t' ||
                                s[start] == L'\\' || s[start] == L'/')) {
        start++;
    }
    size_t end = s.size();
    while (end > start && (s[end - 1] == L' ' || s[end - 1] == L'\t' ||
                           s[end - 1] == L'\\' || s[end - 1] == L'/')) {
        end--;
    }
    return std::wstring(s.substr(start, end - start));
}

static std::wstring extract_leaf_name(std::wstring_view path) {
    std::wstring trimmed = trim_spaces_and_slashes(path);
    if (trimmed.empty()) {
        return {};
    }
    size_t pos = trimmed.find_last_of(L"\\/");
    if (pos == std::wstring::npos) {
        return trimmed;
    }
    return trimmed.substr(pos + 1);
}

static std::wstring extract_parent_name(std::wstring_view path) {
    std::wstring trimmed = trim_spaces_and_slashes(path);
    if (trimmed.empty()) {
        return {};
    }
    size_t pos = trimmed.find_last_of(L"\\/");
    if (pos == std::wstring::npos || pos == 0) {
        return {};
    }
    std::wstring parent_sub = trimmed.substr(0, pos);
    return extract_leaf_name(parent_sub);
}

std::wstring ScoredArtifact::category_string() const {
    switch (category) {
    case ArtifactConfidenceCategory::Safe:
        return L"safe";
    case ArtifactConfidenceCategory::Review:
        return L"review";
    case ArtifactConfidenceCategory::Skip:
    default:
        return L"skip";
    }
}

std::wstring ScoredArtifact::kind_string() const {
    switch (kind) {
    case ArtifactKind::File:
        return L"file";
    case ArtifactKind::Folder:
        return L"folder";
    case ArtifactKind::RegistryKey:
        return L"registry_key";
    case ArtifactKind::RegistryValue:
        return L"registry_value";
    case ArtifactKind::Service:
        return L"service";
    case ArtifactKind::Task:
        return L"task";
    case ArtifactKind::FirewallRule:
        return L"firewall_rule";
    case ArtifactKind::Shortcut:
        return L"shortcut";
    default:
        return L"unknown";
    }
}

bool ConfidenceEngine::is_generic_name(std::wstring_view name) {
    std::wstring leaf = to_lower_str(extract_leaf_name(name));
    if (leaf.empty()) {
        return false;
    }
    const auto& generics = get_generic_names();
    for (const auto& g : generics) {
        if (leaf == g) {
            return true;
        }
    }
    return false;
}

ScoredArtifact ConfidenceEngine::evaluate(
    const ArtifactCandidate& candidate,
    const Target& target,
    const std::vector<InstalledAppInfo>& other_installed_apps
) {
    ScoredArtifact result;
    result.identifier = candidate.identifier;
    result.kind = candidate.kind;

    const std::wstring leaf = extract_leaf_name(candidate.identifier);
    const std::wstring parent = extract_parent_name(candidate.identifier);
    const bool is_generic = is_generic_name(candidate.identifier);

    bool has_high_confidence_evidence = false;

    // 1. Direct installation path reference
    bool direct_path_match = false;
    if (!target.root_path.empty()) {
        if (!candidate.referenced_path.empty()) {
            if (PathHelper::is_same_or_subpath(target.root_path, candidate.referenced_path) ||
                PathHelper::contains_path_reference(candidate.referenced_path, target.root_path)) {
                direct_path_match = true;
            }
        }
        if (!direct_path_match) {
            if (PathHelper::is_same_or_subpath(target.root_path, candidate.identifier) ||
                PathHelper::contains_path_reference(candidate.identifier, target.root_path)) {
                direct_path_match = true;
            }
        }
    }

    if (direct_path_match) {
        result.reasons.push_back({
            L"DIRECT_INSTALL_PATH",
            ConfidenceWeights::kDirectPathReference,
            L"Direct reference to installation path: " + target.root_path
        });
        has_high_confidence_evidence = true;
    }

    // 2. COM CLSID or TypeLib server reference
    if (candidate.is_clsid || candidate.is_typelib) {
        result.reasons.push_back({
            L"CLSID_OR_TYPELIB_REFERENCE",
            ConfidenceWeights::kClsidOrTypeLib,
            candidate.is_clsid ? L"CLSID InprocServer32/LocalServer32 points to target path"
                               : L"TypeLib win32/win64 points to target path"
        });
        has_high_confidence_evidence = true;
    }

    // 3. Product GUID match from MSI or Uninstall
    bool guid_match = candidate.is_guid_match;
    if (!guid_match && !target.product_code.empty()) {
        if (!candidate.guid.empty() && equals_ignore_case(candidate.guid, target.product_code)) {
            guid_match = true;
        } else if (contains_ignore_case(candidate.identifier, target.product_code)) {
            guid_match = true;
        }
    }
    if (guid_match) {
        result.reasons.push_back({
            L"PRODUCT_GUID_MATCH",
            ConfidenceWeights::kProductGuidMatch,
            L"Matches product GUID: " + target.product_code
        });
        has_high_confidence_evidence = true;
    }

    // 4. App Paths, file associations, MUICache, ShimCache
    if (candidate.is_app_path || candidate.is_association_or_cache) {
        result.reasons.push_back({
            L"APP_PATHS_OR_FILE_ASSOCIATION",
            ConfidenceWeights::kAppPathsOrFileAssociations,
            candidate.is_app_path ? L"Executable registered in Windows App Paths"
                                  : L"File association, MUICache, or ShimCache entry referencing target"
        });
        has_high_confidence_evidence = true;
    }

    // 5. Name and publisher matches (only if direct path was not already given)
    if (!direct_path_match) {
        bool name_matched = false;

        // Check if product folder is inside publisher folder (e.g. Vendor\Product)
        if (!target.name.empty() && !target.publisher.empty() &&
            equals_ignore_case(leaf, target.name) &&
            equals_ignore_case(parent, target.publisher)) {
            result.reasons.push_back({
                L"PUBLISHER_SUBFOLDER_PRODUCT",
                ConfidenceWeights::kPublisherSubfolderProduct,
                L"Product folder inside publisher directory: " + target.publisher + L"\\" + target.name
            });
            name_matched = true;
        } else if (!target.name.empty() && equals_ignore_case(leaf, target.name)) {
            result.reasons.push_back({
                L"EXACT_PRODUCT_NAME_MATCH",
                ConfidenceWeights::kExactProductOrPublisherMatch,
                L"Exact match with product name: " + target.name
            });
            name_matched = true;
        } else if (!target.publisher.empty() && equals_ignore_case(leaf, target.publisher)) {
            result.reasons.push_back({
                L"EXACT_PUBLISHER_NAME_MATCH",
                ConfidenceWeights::kExactProductOrPublisherMatch,
                L"Exact match with publisher name: " + target.publisher
            });
            name_matched = true;
        }

        // Check partial name match if exact name didn't match
        if (!name_matched && !target.name.empty() && contains_ignore_case(leaf, target.name)) {
            result.reasons.push_back({
                L"PARTIAL_PRODUCT_NAME_MATCH",
                ConfidenceWeights::kPartialNameMatch,
                L"Partial name match with product: " + target.name
            });
        }
    }

    // 6. Generic names zeroing: generic names receive 0 weight unless supported by high-confidence proof
    if (is_generic) {
        if (!has_high_confidence_evidence) {
            result.reasons.clear();
            result.reasons.push_back({
                L"GENERIC_NAME_ZEROED",
                ConfidenceWeights::kGenericNameWithoutProof,
                L"Generic name '" + leaf + L"' without independent proof receives zero weight"
            });
            result.generic_name_zeroed = true;
        }
    }

    // Compute total score
    int total_score = 0;
    for (const auto& r : result.reasons) {
        total_score += r.weight;
    }
    result.score = total_score;

    // 7. Safety check: Nothing inside protected paths can be marked safe
    bool path_is_protected = false;
    if (candidate.kind == ArtifactKind::Folder || candidate.kind == ArtifactKind::File ||
        candidate.kind == ArtifactKind::Shortcut) {
        if (SafetyValidator::is_protected_path(candidate.identifier)) {
            path_is_protected = true;
        }
    }

    if (path_is_protected) {
        result.is_protected = true;
        result.reasons.push_back({
            L"PROTECTED_PATH_DISQUALIFICATION",
            0,
            L"Artifact resides within a protected system directory; cannot be marked safe"
        });
    }

    // 8. Conflict check: If another installed application also references this artifact, demote to review
    bool has_conflict = false;
    std::wstring conflicting_name;

    for (const auto& other : other_installed_apps) {
        if (equals_ignore_case(other.name, target.name)) {
            continue;
        }
        if (!target.root_path.empty() && !other.root_path.empty() &&
            equals_ignore_case(other.root_path, target.root_path)) {
            continue;
        }

        // Does the other app also reference the same path?
        if (!candidate.referenced_path.empty() && !other.root_path.empty()) {
            if (PathHelper::is_same_or_subpath(other.root_path, candidate.referenced_path)) {
                has_conflict = true;
                conflicting_name = other.name;
                break;
            }
        }

        // Does the artifact match the other app's name?
        if (!other.name.empty() && equals_ignore_case(leaf, other.name)) {
            has_conflict = true;
            conflicting_name = other.name;
            break;
        }

        // Is this a publisher folder shared with the other app?
        if (!target.publisher.empty() && equals_ignore_case(leaf, target.publisher)) {
            if (contains_ignore_case(other.name, target.publisher) ||
                contains_ignore_case(other.install_location, target.publisher)) {
                has_conflict = true;
                conflicting_name = other.name;
                break;
            }
        }
    }

    if (has_conflict) {
        result.referenced_by_other_app = true;
        result.conflicting_app_name = conflicting_name;
        result.reasons.push_back({
            L"REFERENCED_BY_OTHER_APP",
            0,
            L"Referenced by another installed program: " + conflicting_name + L"; demoted to review"
        });
    }

    // 9. Assign category based on score and disqualifications
    if (result.score >= ConfidenceWeights::kSafeThreshold) {
        if (result.is_protected || result.referenced_by_other_app) {
            result.category = ArtifactConfidenceCategory::Review;
        } else {
            result.category = ArtifactConfidenceCategory::Safe;
        }
    } else if (result.score >= ConfidenceWeights::kReviewThreshold) {
        result.category = ArtifactConfidenceCategory::Review;
    } else {
        result.category = ArtifactConfidenceCategory::Skip;
    }

    return result;
}

ScoredArtifact ConfidenceEngine::evaluate(
    const std::wstring& identifier,
    ArtifactKind kind,
    const Target& target,
    const std::vector<InstalledAppInfo>& other_installed_apps,
    const std::wstring& referenced_path
) {
    ArtifactCandidate cand;
    cand.identifier = identifier;
    cand.kind = kind;
    cand.referenced_path = referenced_path;

    // Detect GUID in identifier if present
    std::wstring code = NativeUninstaller::extract_product_code(identifier);
    if (!code.empty()) {
        cand.guid = code;
        if (!target.product_code.empty() && equals_ignore_case(code, target.product_code)) {
            cand.is_guid_match = true;
        }
    }

    // Detect CLSID / TypeLib from identifier
    if (kind == ArtifactKind::RegistryKey || kind == ArtifactKind::RegistryValue) {
        if (contains_ignore_case(identifier, L"CLSID") &&
            (contains_ignore_case(identifier, L"InprocServer32") || contains_ignore_case(identifier, L"LocalServer32"))) {
            cand.is_clsid = true;
        } else if (contains_ignore_case(identifier, L"TypeLib") &&
                   (contains_ignore_case(identifier, L"win32") || contains_ignore_case(identifier, L"win64"))) {
            cand.is_typelib = true;
        } else if (contains_ignore_case(identifier, L"App Paths")) {
            cand.is_app_path = true;
        } else if (contains_ignore_case(identifier, L"MuiCache") ||
                   contains_ignore_case(identifier, L"FileExts") ||
                   contains_ignore_case(identifier, L"AppCompatFlags")) {
            cand.is_association_or_cache = true;
        }
    }

    return evaluate(cand, target, other_installed_apps);
}

std::vector<ScoredArtifact> ConfidenceEngine::discover_artifacts(
    const Target& target,
    const std::vector<InstalledAppInfo>& other_installed_apps,
    const std::vector<UserProfileInfo>& profiles
) {
    std::vector<ScoredArtifact> results;

    auto add_if_not_skip = [&](const ScoredArtifact& art) {
        for (const auto& existing : results) {
            if (equals_ignore_case(existing.identifier, art.identifier)) {
                return;
            }
        }
        results.push_back(art);
    };

    // 1. Filesystem leftovers (AppData, Start Menu, Desktop)
    const auto leftover_items = LeftoversCleaner::find_leftovers(target);
    for (const auto& item : leftover_items) {
        ArtifactKind k = ArtifactKind::Folder;
        std::wstring ref_path;
        if (item.kind == LeftoverKind::Shortcut) {
            k = ArtifactKind::Shortcut;
            ref_path = LeftoversCleaner::resolve_shortcut_target(item.path_or_name);
        } else if (item.kind == LeftoverKind::FirewallRule) {
            k = ArtifactKind::FirewallRule;
            ref_path = target.root_path;
        }

        ScoredArtifact scored = evaluate(item.path_or_name, k, target, other_installed_apps, ref_path);
        add_if_not_skip(scored);
    }

    // 1b. Multi-profile file leftovers
    for (const auto& prof : profiles) {
        const auto prof_items = ProfileManager::find_profile_file_leftovers(prof, target);
        for (const auto& item : prof_items) {
            ArtifactKind k = (item.kind == LeftoverKind::Shortcut) ? ArtifactKind::Shortcut : ArtifactKind::Folder;
            std::wstring ref_path;
            if (item.kind == LeftoverKind::Shortcut) {
                ref_path = LeftoversCleaner::resolve_shortcut_target(item.path_or_name);
            }
            ScoredArtifact scored = evaluate(item.path_or_name, k, target, other_installed_apps, ref_path);
            add_if_not_skip(scored);
        }
    }

    // 2. Registry autorun entries
    if (!target.root_path.empty()) {
        const auto autoruns = RegistryCleaner::find_autorun_entries(target.root_path);
        for (const auto& ar : autoruns) {
            std::wstring id = ar.subkey_path + L" [" + ar.value_name + L"]";
            ScoredArtifact scored = evaluate(id, ArtifactKind::RegistryValue, target,
                                             other_installed_apps, ar.command);
            add_if_not_skip(scored);
        }
    }

    // 3. Registry shell verb and context menu entries
    if (!target.root_path.empty()) {
        const auto shells = RegistryCleaner::find_shell_entries(target.root_path);
        for (const auto& sh : shells) {
            ScoredArtifact scored = evaluate(sh.subkey_path, ArtifactKind::RegistryKey, target,
                                             other_installed_apps, sh.command_or_server);
            if (sh.is_clsid) {
                ArtifactCandidate cand;
                cand.identifier = sh.subkey_path;
                cand.kind = ArtifactKind::RegistryKey;
                cand.referenced_path = sh.command_or_server;
                cand.is_clsid = true;
                scored = evaluate(cand, target, other_installed_apps);
            }
            add_if_not_skip(scored);
        }
    }

    // 4. Registry product and vendor keys
    const auto prod_keys = RegistryCleaner::find_product_keys(target);
    for (const auto& pk : prod_keys) {
        ScoredArtifact scored = evaluate(pk.subkey_path, ArtifactKind::RegistryKey, target,
                                         other_installed_apps);
        add_if_not_skip(scored);
    }

    // 5. Registry COM CLSID & TypeLib scanning
    if (!target.root_path.empty()) {
        struct ComRoot {
            HKEY root;
            const wchar_t* base;
        };
        const ComRoot com_roots[] = {
            {HKEY_CLASSES_ROOT, L"CLSID"},
            {HKEY_CURRENT_USER, L"Software\\Classes\\CLSID"}
        };

        for (const auto& cr : com_roots) {
            UniqueHKey key;
            if (RegOpenKeyExW(cr.root, cr.base, 0, KEY_READ, key.put()) != ERROR_SUCCESS) {
                continue;
            }

            DWORD index = 0;
            wchar_t clsid_buf[256];
            DWORD clsid_len = 256;

            while (true) {
                clsid_len = 256;
                LSTATUS st = RegEnumKeyExW(key.get(), index++, clsid_buf, &clsid_len,
                                           nullptr, nullptr, nullptr, nullptr);
                if (st == ERROR_NO_MORE_ITEMS) {
                    break;
                }
                if (st != ERROR_SUCCESS) {
                    continue;
                }

                // Check InprocServer32 and LocalServer32
                const wchar_t* sub_servers[] = {L"InprocServer32", L"LocalServer32"};
                for (const auto* server_name : sub_servers) {
                    std::wstring full_sub = std::wstring(cr.base) + L"\\" + clsid_buf + L"\\" + server_name;
                    UniqueHKey server_key;
                    if (RegOpenKeyExW(cr.root, full_sub.c_str(), 0, KEY_READ, server_key.put()) == ERROR_SUCCESS) {
                        wchar_t path_val[MAX_PATH * 2]{};
                        DWORD path_bytes = sizeof(path_val);
                        if (RegQueryValueExW(server_key.get(), nullptr, nullptr, nullptr,
                                             reinterpret_cast<LPBYTE>(path_val), &path_bytes) == ERROR_SUCCESS) {
                            std::wstring server_path = path_val;
                            if (PathHelper::contains_path_reference(server_path, target.root_path)) {
                                ArtifactCandidate cand;
                                cand.identifier = full_sub;
                                cand.kind = ArtifactKind::RegistryKey;
                                cand.referenced_path = server_path;
                                cand.is_clsid = true;
                                add_if_not_skip(evaluate(cand, target, other_installed_apps));
                            }
                        }
                    }
                }
            }
        }
    }

    // 6. Registry App Paths & MUICache
    if (!target.root_path.empty()) {
        const wchar_t* app_paths_sub = L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths";
        const HKEY roots[] = {HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER};
        for (HKEY root : roots) {
            UniqueHKey ap_key;
            if (RegOpenKeyExW(root, app_paths_sub, 0, KEY_READ, ap_key.put()) == ERROR_SUCCESS) {
                DWORD idx = 0;
                wchar_t ap_name[256];
                DWORD ap_len = 256;
                while (true) {
                    ap_len = 256;
                    if (RegEnumKeyExW(ap_key.get(), idx++, ap_name, &ap_len, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) {
                        break;
                    }
                    std::wstring subkey_full = std::wstring(app_paths_sub) + L"\\" + ap_name;
                    UniqueHKey sub_h;
                    if (RegOpenKeyExW(root, subkey_full.c_str(), 0, KEY_READ, sub_h.put()) == ERROR_SUCCESS) {
                        wchar_t p_val[MAX_PATH * 2]{};
                        DWORD p_bytes = sizeof(p_val);
                        if (RegQueryValueExW(sub_h.get(), nullptr, nullptr, nullptr,
                                             reinterpret_cast<LPBYTE>(p_val), &p_bytes) == ERROR_SUCCESS) {
                            if (PathHelper::contains_path_reference(p_val, target.root_path)) {
                                ArtifactCandidate cand;
                                cand.identifier = subkey_full;
                                cand.kind = ArtifactKind::RegistryKey;
                                cand.referenced_path = p_val;
                                cand.is_app_path = true;
                                add_if_not_skip(evaluate(cand, target, other_installed_apps));
                            }
                        }
                    }
                }
            }
        }

        // MUICache scan
        const wchar_t* mui_sub = L"Software\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\MuiCache";
        UniqueHKey mui_key;
        if (RegOpenKeyExW(HKEY_CURRENT_USER, mui_sub, 0, KEY_READ, mui_key.put()) == ERROR_SUCCESS) {
            DWORD idx = 0;
            wchar_t val_name[MAX_PATH * 2];
            DWORD val_len = MAX_PATH * 2;
            while (true) {
                val_len = MAX_PATH * 2;
                if (RegEnumValueW(mui_key.get(), idx++, val_name, &val_len, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) {
                    break;
                }
                std::wstring v_name = val_name;
                if (PathHelper::contains_path_reference(v_name, target.root_path)) {
                    ArtifactCandidate cand;
                    cand.identifier = std::wstring(mui_sub) + L" [" + v_name + L"]";
                    cand.kind = ArtifactKind::RegistryValue;
                    cand.referenced_path = v_name;
                    cand.is_association_or_cache = true;
                    add_if_not_skip(evaluate(cand, target, other_installed_apps));
                }
            }
        }
    }

    return results;
}

void ConfidenceEngine::explain(
    const std::wstring& artifact_id,
    const std::vector<InstalledAppInfo>& installed_apps
) {
    if (artifact_id.empty()) {
        std::wcout << L"No artifact identifier provided to explain.\n";
        return;
    }

    std::wcout << L"\n================================================================================\n";
    std::wcout << L" Artifact Confidence Explanation\n";
    std::wcout << L"================================================================================\n";
    std::wcout << L"Identifier: " << artifact_id << L"\n\n";

    ArtifactKind kind = ArtifactKind::Folder;
    if (artifact_id.find(L"HKLM") != std::wstring::npos ||
        artifact_id.find(L"HKCU") != std::wstring::npos ||
        artifact_id.find(L"HKEY_") != std::wstring::npos) {
        kind = (artifact_id.find(L"[") != std::wstring::npos) ? ArtifactKind::RegistryValue
                                                              : ArtifactKind::RegistryKey;
    } else if (artifact_id.ends_with(L".lnk")) {
        kind = ArtifactKind::Shortcut;
    } else if (artifact_id.ends_with(L".exe") || artifact_id.ends_with(L".dll") ||
               artifact_id.ends_with(L".sys")) {
        kind = ArtifactKind::File;
    }

    ScoredArtifact best_artifact;
    std::wstring best_target_name;
    int highest_score = -1;

    for (const auto& app : installed_apps) {
        Target t;
        t.name = app.name;
        t.root_path = app.root_path.empty() ? app.install_location : app.root_path;

        ScoredArtifact scored = evaluate(artifact_id, kind, t, installed_apps);
        if (scored.score > highest_score) {
            highest_score = scored.score;
            best_artifact = scored;
            best_target_name = app.name;
        }
    }

    if (highest_score < 0 || best_artifact.reasons.empty()) {
        Target fallback;
        fallback.name = extract_leaf_name(artifact_id);
        best_artifact = evaluate(artifact_id, kind, fallback, installed_apps);
        best_target_name = fallback.name;
    }

    std::wcout << L"Matched Application: " << (best_target_name.empty() ? L"(None)" : best_target_name) << L"\n";
    std::wcout << L"Artifact Kind:       " << best_artifact.kind_string() << L"\n";
    std::wcout << L"Confidence Score:    " << best_artifact.score << L" / 100\n";
    std::wcout << L"Category:            " << best_artifact.category_string() << L"\n\n";

    std::wcout << L"Evidence & Reasons:\n";
    for (const auto& r : best_artifact.reasons) {
        std::wcout << L"  [+" << r.weight << L"] " << r.rule_id << L": " << r.description << L"\n";
    }

    std::wcout << L"\nAssessment:\n";
    if (best_artifact.category == ArtifactConfidenceCategory::Safe) {
        std::wcout << L"  SAFE: High confidence match (score >= " << ConfidenceWeights::kSafeThreshold
                   << L"). Item will be removed automatically.\n";
    } else if (best_artifact.category == ArtifactConfidenceCategory::Review) {
        std::wcout << L"  REVIEW: Moderate confidence or conflict detected. Requires manual review or --aggressive.\n";
    } else {
        std::wcout << L"  SKIP: Insufficient evidence or generic artifact (score < "
                   << ConfidenceWeights::kReviewThreshold << L"). Item will not be modified.\n";
    }
    std::wcout << L"================================================================================\n\n";
}

} // namespace obliterator
