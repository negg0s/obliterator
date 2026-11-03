#include "obliterator/leftovers.hpp"
#include "obliterator/log.hpp"
#include "obliterator/safety.hpp"
#include "obliterator/wiper.hpp"

#include <netfw.h>
#include <shlguid.h>
#include <shobjidl.h>

#include <algorithm>
#include <cwctype>
#include <filesystem>
#include <vector>

namespace obliterator {

static std::wstring to_lower_str(std::wstring_view input) {
    std::wstring result(input);
    std::transform(result.begin(), result.end(), result.begin(), [](wchar_t c) {
        return static_cast<wchar_t>(std::towlower(c));
    });
    return result;
}

static bool contains_str_ignore_case(std::wstring_view text, std::wstring_view pattern) {
    if (pattern.empty() || text.empty()) {
        return false;
    }
    return to_lower_str(text).find(to_lower_str(pattern)) != std::wstring_view::npos;
}

static bool equals_str_ignore_case(std::wstring_view a, std::wstring_view b) {
    return to_lower_str(a) == to_lower_str(b);
}

static std::wstring expand_env_path(const wchar_t* var) {
    wchar_t buf[MAX_PATH]{};
    DWORD len = ExpandEnvironmentStringsW(var, buf, MAX_PATH);
    if (len > 0 && len <= MAX_PATH) {
        return SafetyValidator::normalize_path(buf);
    }
    return {};
}

std::wstring LeftoversCleaner::resolve_shortcut_target(const std::wstring& lnk_path) {
    std::wstring result;
    IShellLinkW* shell_link = nullptr;
    HRESULT hr = CoCreateInstance(CLSID_ShellLink, nullptr, CLSCTX_INPROC_SERVER,
                                  IID_IShellLinkW, reinterpret_cast<void**>(&shell_link));
    if (SUCCEEDED(hr)) {
        IPersistFile* persist_file = nullptr;
        hr = shell_link->QueryInterface(IID_IPersistFile, reinterpret_cast<void**>(&persist_file));
        if (SUCCEEDED(hr)) {
            hr = persist_file->Load(lnk_path.c_str(), STGM_READ);
            if (SUCCEEDED(hr)) {
                wchar_t target_buf[MAX_PATH]{};
                WIN32_FIND_DATAW wfd{};
                hr = shell_link->GetPath(target_buf, MAX_PATH, &wfd, SLGP_RAWPATH);
                if (SUCCEEDED(hr)) {
                    result = target_buf;
                }
            }
            persist_file->Release();
        }
        shell_link->Release();
    }
    return result;
}

std::vector<std::wstring> LeftoversCleaner::find_firewall_rules(const std::wstring& target_root) {
    std::vector<std::wstring> matched_rules;
    if (target_root.empty()) {
        return matched_rules;
    }

    INetFwPolicy2* policy = nullptr;
    HRESULT hr = CoCreateInstance(__uuidof(NetFwPolicy2), nullptr, CLSCTX_INPROC_SERVER,
                                  __uuidof(INetFwPolicy2), reinterpret_cast<void**>(&policy));
    if (SUCCEEDED(hr) && policy) {
        INetFwRules* rules = nullptr;
        hr = policy->get_Rules(&rules);
        if (SUCCEEDED(hr) && rules) {
            IUnknown* enumerator_unk = nullptr;
            hr = rules->get__NewEnum(&enumerator_unk);
            if (SUCCEEDED(hr) && enumerator_unk) {
                IEnumVARIANT* variant_enum = nullptr;
                hr = enumerator_unk->QueryInterface(IID_IEnumVARIANT,
                                                    reinterpret_cast<void**>(&variant_enum));
                if (SUCCEEDED(hr) && variant_enum) {
                    VARIANT var;
                    VariantInit(&var);
                    while (variant_enum->Next(1, &var, nullptr) == S_OK) {
                        if (var.vt == VT_DISPATCH && var.pdispVal) {
                            INetFwRule* rule = nullptr;
                            if (SUCCEEDED(var.pdispVal->QueryInterface(__uuidof(INetFwRule),
                                                                       reinterpret_cast<void**>(&rule)))) {
                                BSTR app_bstr = nullptr;
                                rule->get_ApplicationName(&app_bstr);
                                if (app_bstr) {
                                    std::wstring app(app_bstr, SysStringLen(app_bstr));
                                    SysFreeString(app_bstr);
                                    if (contains_str_ignore_case(app, target_root)) {
                                        BSTR name_bstr = nullptr;
                                        rule->get_Name(&name_bstr);
                                        if (name_bstr) {
                                            matched_rules.emplace_back(name_bstr, SysStringLen(name_bstr));
                                            SysFreeString(name_bstr);
                                        }
                                    }
                                }
                                rule->Release();
                            }
                        }
                        VariantClear(&var);
                    }
                    variant_enum->Release();
                }
                enumerator_unk->Release();
            }
            rules->Release();
        }
        policy->Release();
    }

    return matched_rules;
}

size_t LeftoversCleaner::remove_firewall_rules(const std::vector<std::wstring>& rule_names) {
    if (rule_names.empty()) {
        return 0;
    }

    size_t removed = 0;
    INetFwPolicy2* policy = nullptr;
    HRESULT hr = CoCreateInstance(__uuidof(NetFwPolicy2), nullptr, CLSCTX_INPROC_SERVER,
                                  __uuidof(INetFwPolicy2), reinterpret_cast<void**>(&policy));
    if (SUCCEEDED(hr) && policy) {
        INetFwRules* rules = nullptr;
        hr = policy->get_Rules(&rules);
        if (SUCCEEDED(hr) && rules) {
            for (const auto& name : rule_names) {
                BSTR name_bstr = SysAllocString(name.c_str());
                if (SUCCEEDED(rules->Remove(name_bstr))) {
                    removed++;
                }
                SysFreeString(name_bstr);
            }
            rules->Release();
        }
        policy->Release();
    }

    return removed;
}

std::vector<LeftoverItem> LeftoversCleaner::find_leftovers(const Target& target) {
    namespace fs = std::filesystem;
    std::vector<LeftoverItem> items;

    if (target.name.empty() && target.root_path.empty()) {
        return items;
    }

    const std::wstring base_app_data_dirs[] = {
        expand_env_path(L"%ProgramData%"),
        expand_env_path(L"%LocalAppData%"),
        expand_env_path(L"%AppData%")
    };

    auto add_item_unique = [&](const LeftoverItem& item) {
        for (const auto& existing : items) {
            if (equals_str_ignore_case(existing.path_or_name, item.path_or_name)) {
                return;
            }
        }
        items.push_back(item);
    };

    // 1. AppData and ProgramData folders
    for (const auto& base_dir : base_app_data_dirs) {
        if (base_dir.empty()) {
            continue;
        }

        std::error_code ec;
        fs::path base_path(base_dir);
        if (!fs::exists(base_path, ec) || !fs::is_directory(base_path, ec)) {
            continue;
        }

        for (const auto& entry : fs::directory_iterator(base_path, ec)) {
            if (!entry.is_directory(ec)) {
                continue;
            }

            const std::wstring dir_name = entry.path().filename().wstring();
            const std::wstring full_path = entry.path().wstring();

            // Refuse to touch base paths themselves or system paths
            if (!SafetyValidator::validate_path(full_path)) {
                continue;
            }

            // Definite match on target name
            if (!target.name.empty() && equals_str_ignore_case(dir_name, target.name)) {
                add_item_unique({full_path, LeftoverKind::Folder, LeftoverConfidence::Definite, L"exact product name"});
                continue;
            }

            // Match on publisher
            if (!target.publisher.empty() && equals_str_ignore_case(dir_name, target.publisher)) {
                // Inspect child folders inside publisher
                bool has_target_child = false;
                for (const auto& sub_entry : fs::directory_iterator(entry.path(), ec)) {
                    if (sub_entry.is_directory(ec) &&
                        !target.name.empty() &&
                        equals_str_ignore_case(sub_entry.path().filename().wstring(), target.name)) {
                        add_item_unique({sub_entry.path().wstring(), LeftoverKind::Folder,
                                         LeftoverConfidence::Definite, L"product inside publisher folder"});
                        has_target_child = true;
                    }
                }
                if (has_target_child) {
                    continue;
                }
                add_item_unique({full_path, LeftoverKind::Folder, LeftoverConfidence::Definite, L"exact publisher folder"});
                continue;
            }

            // Possible match: directory name contains target.name
            if (!target.name.empty() && contains_str_ignore_case(dir_name, target.name)) {
                add_item_unique({full_path, LeftoverKind::Folder, LeftoverConfidence::Possible, L"partial name match"});
            }
        }
    }

    // 2. Start Menu items
    const std::wstring start_menu_dirs[] = {
        expand_env_path(L"%ProgramData%") + L"\\Microsoft\\Windows\\Start Menu\\Programs",
        expand_env_path(L"%AppData%") + L"\\Microsoft\\Windows\\Start Menu\\Programs"
    };

    for (const auto& sm_base : start_menu_dirs) {
        if (sm_base.empty()) {
            continue;
        }

        std::error_code ec;
        fs::path sm_path(sm_base);
        if (!fs::exists(sm_path, ec)) {
            continue;
        }

        for (const auto& entry : fs::recursive_directory_iterator(sm_path, ec)) {
            const std::wstring item_path = entry.path().wstring();
            if (!SafetyValidator::validate_path(item_path)) {
                continue;
            }

            if (entry.is_directory(ec)) {
                const std::wstring dir_name = entry.path().filename().wstring();
                if (!target.name.empty() && equals_str_ignore_case(dir_name, target.name)) {
                    add_item_unique({item_path, LeftoverKind::Folder, LeftoverConfidence::Definite, L"Start Menu folder"});
                } else if (!target.publisher.empty() && equals_str_ignore_case(dir_name, target.publisher)) {
                    add_item_unique({item_path, LeftoverKind::Folder, LeftoverConfidence::Definite, L"Start Menu publisher folder"});
                } else if (!target.name.empty() && contains_str_ignore_case(dir_name, target.name)) {
                    add_item_unique({item_path, LeftoverKind::Folder, LeftoverConfidence::Possible, L"Start Menu partial folder"});
                }
            } else if (entry.is_regular_file(ec) && entry.path().extension() == L".lnk") {
                const std::wstring stem = entry.path().stem().wstring();
                const std::wstring target_exe = resolve_shortcut_target(item_path);

                if (!target.root_path.empty() && contains_str_ignore_case(target_exe, target.root_path)) {
                    add_item_unique({item_path, LeftoverKind::Shortcut, LeftoverConfidence::Definite, L"points to target directory"});
                } else if (!target.name.empty() && equals_str_ignore_case(stem, target.name)) {
                    add_item_unique({item_path, LeftoverKind::Shortcut, LeftoverConfidence::Definite, L"shortcut name match"});
                } else if (!target.name.empty() && contains_str_ignore_case(stem, target.name)) {
                    add_item_unique({item_path, LeftoverKind::Shortcut, LeftoverConfidence::Possible, L"shortcut partial name"});
                }
            }
        }
    }

    // 3. Desktop shortcuts
    const std::wstring desktop_dirs[] = {
        expand_env_path(L"%Public%") + L"\\Desktop",
        expand_env_path(L"%UserProfile%") + L"\\Desktop"
    };

    for (const auto& desk_dir : desktop_dirs) {
        if (desk_dir.empty()) {
            continue;
        }

        std::error_code ec;
        fs::path desk_path(desk_dir);
        if (!fs::exists(desk_path, ec)) {
            continue;
        }

        for (const auto& entry : fs::directory_iterator(desk_path, ec)) {
            if (!entry.is_regular_file(ec) || entry.path().extension() != L".lnk") {
                continue;
            }

            const std::wstring item_path = entry.path().wstring();
            if (!SafetyValidator::validate_path(item_path)) {
                continue;
            }

            const std::wstring stem = entry.path().stem().wstring();
            const std::wstring target_exe = resolve_shortcut_target(item_path);

            if (!target.root_path.empty() && contains_str_ignore_case(target_exe, target.root_path)) {
                add_item_unique({item_path, LeftoverKind::Shortcut, LeftoverConfidence::Definite, L"desktop shortcut to target"});
            } else if (!target.name.empty() && equals_str_ignore_case(stem, target.name)) {
                add_item_unique({item_path, LeftoverKind::Shortcut, LeftoverConfidence::Definite, L"desktop shortcut name match"});
            } else if (!target.name.empty() && contains_str_ignore_case(stem, target.name)) {
                add_item_unique({item_path, LeftoverKind::Shortcut, LeftoverConfidence::Possible, L"desktop shortcut partial name"});
            }
        }
    }

    // 4. Firewall rules
    if (!target.root_path.empty()) {
        const auto fw_rules = find_firewall_rules(target.root_path);
        for (const auto& rule : fw_rules) {
            add_item_unique({rule, LeftoverKind::FirewallRule, LeftoverConfidence::Definite, L"firewall rule for target"});
        }
    }

    return items;
}

LeftoversReport LeftoversCleaner::clean_leftovers(const Target& target, bool aggressive) {
    namespace fs = std::filesystem;
    LeftoversReport report;

    const auto items = find_leftovers(target);
    std::vector<std::wstring> firewall_rules_to_remove;

    for (const auto& item : items) {
        if (item.confidence == LeftoverConfidence::Possible && !aggressive) {
            report.possible_leftovers_skipped++;
            Logger::warn(L"Possible leftover: " + item.path_or_name +
                         L" (" + item.detail + L") - skipped (use --aggressive to remove)");
            continue;
        }

        if (item.kind == LeftoverKind::FirewallRule) {
            firewall_rules_to_remove.push_back(item.path_or_name);
            continue;
        }

        if (item.kind == LeftoverKind::Folder) {
            PhysicalWipeReport wipe_rep;
            auto wipe_res = FileWiper::wipe_physical_tree(item.path_or_name, wipe_rep);
            if (wipe_res && !fs::exists(item.path_or_name)) {
                report.folders_deleted++;
            } else {
                report.failed_paths.push_back(item.path_or_name);
            }
        } else if (item.kind == LeftoverKind::Shortcut) {
            WipeReport wipe_rep;
            auto del_res = FileWiper::delete_file_lazy(item.path_or_name, wipe_rep);
            if (del_res && !fs::exists(item.path_or_name)) {
                report.shortcuts_deleted++;
            } else {
                report.failed_paths.push_back(item.path_or_name);
            }
        }
    }

    if (!firewall_rules_to_remove.empty()) {
        report.firewall_rules_deleted = remove_firewall_rules(firewall_rules_to_remove);
    }

    return report;
}

} // namespace obliterator
