#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include "obliterator/result.hpp"
#include "obliterator/target.hpp"
#include "obliterator/ui.hpp"

#include <string>
#include <vector>

namespace obliterator {

enum class LeftoverKind {
    Folder,
    Shortcut,
    FirewallRule
};

enum class LeftoverConfidence {
    Definite,
    Possible
};

struct LeftoverItem {
    std::wstring path_or_name;
    LeftoverKind kind{LeftoverKind::Folder};
    LeftoverConfidence confidence{LeftoverConfidence::Definite};
    std::wstring detail;
};

struct LeftoversReport {
    size_t folders_deleted{0};
    size_t shortcuts_deleted{0};
    size_t firewall_rules_deleted{0};
    size_t possible_leftovers_skipped{0};
    std::vector<std::wstring> failed_paths;
};

class LeftoversCleaner {
public:
    static std::vector<LeftoverItem> find_leftovers(const Target& target);
    static LeftoversReport clean_leftovers(
        const Target& target,
        bool aggressive = false,
        const std::vector<InstalledAppInfo>& other_apps = {}
    );

    static std::vector<std::wstring> find_firewall_rules(const std::wstring& target_root);
    static size_t remove_firewall_rules(const std::vector<std::wstring>& rule_names);

    static std::wstring resolve_shortcut_target(const std::wstring& lnk_path);
};

} // namespace obliterator
