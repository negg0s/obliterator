#include "obliterator/profile.hpp"
#include "obliterator/handles.hpp"
#include "obliterator/log.hpp"
#include "obliterator/path.hpp"
#include "obliterator/privileges.hpp"
#include "obliterator/safety.hpp"

#include <sddl.h>

#include <algorithm>
#include <cwctype>
#include <filesystem>
#include <vector>

namespace obliterator {

static std::wstring to_lower_str(std::wstring_view sv) {
    return PathHelper::to_lower_unicode(sv);
}

static bool equals_ignore_case(std::wstring_view a, std::wstring_view b) {
    return to_lower_str(a) == to_lower_str(b);
}

static std::wstring sanitize_sid(std::wstring_view sid) {
    std::wstring result;
    result.reserve(sid.size());
    for (wchar_t c : sid) {
        if (c == L'-' || (c >= L'0' && c <= L'9') || (c >= L'A' && c <= L'Z') || (c >= L'a' && c <= L'z')) {
            result.push_back(c);
        } else {
            result.push_back(L'_');
        }
    }
    return result;
}

LoadedHiveGuard::LoadedHiveGuard(HKEY root, std::wstring subkey_name, std::wstring hive_file_path)
    : root_(root), subkey_name_(std::move(subkey_name)), hive_file_path_(std::move(hive_file_path)) {}

LoadedHiveGuard::~LoadedHiveGuard() {
    unload();
}

LoadedHiveGuard::LoadedHiveGuard(LoadedHiveGuard&& other) noexcept
    : root_(other.root_),
      subkey_name_(std::move(other.subkey_name_)),
      hive_file_path_(std::move(other.hive_file_path_)),
      is_loaded_(other.is_loaded_) {
    other.is_loaded_ = false;
}

LoadedHiveGuard& LoadedHiveGuard::operator=(LoadedHiveGuard&& other) noexcept {
    if (this != &other) {
        unload();
        root_ = other.root_;
        subkey_name_ = std::move(other.subkey_name_);
        hive_file_path_ = std::move(other.hive_file_path_);
        is_loaded_ = other.is_loaded_;
        other.is_loaded_ = false;
    }
    return *this;
}

Result<void> LoadedHiveGuard::load() {
    if (is_loaded_) {
        return Result<void>::success();
    }

    if (hive_file_path_.empty() || subkey_name_.empty()) {
        return Win32Error::from_code(ERROR_INVALID_PARAMETER);
    }

    enable_privilege(L"SeRestorePrivilege");
    enable_privilege(L"SeBackupPrivilege");

    LSTATUS st = RegLoadKeyW(root_, subkey_name_.c_str(), hive_file_path_.c_str());
    if (st == ERROR_SHARING_VIOLATION) {
        return Win32Error::from_code(ERROR_SHARING_VIOLATION);
    }
    if (st != ERROR_SUCCESS) {
        return Win32Error::from_code(st);
    }

    is_loaded_ = true;
    return Result<void>::success();
}

Result<void> LoadedHiveGuard::unload() {
    if (!is_loaded_) {
        return Result<void>::success();
    }

    enable_privilege(L"SeRestorePrivilege");
    enable_privilege(L"SeBackupPrivilege");

    LSTATUS st = ERROR_SUCCESS;
    // Retry unloading in case background handles are closing
    for (int attempt = 0; attempt < 5; ++attempt) {
        st = RegUnLoadKeyW(root_, subkey_name_.c_str());
        if (st == ERROR_SUCCESS || st == ERROR_FILE_NOT_FOUND || st == ERROR_KEY_DELETED) {
            is_loaded_ = false;
            return Result<void>::success();
        }
        Sleep(50);
    }

    is_loaded_ = false;
    return Win32Error::from_code(st);
}

std::wstring ProfileManager::get_current_user_sid() {
    UniqueHandle token;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, token.put())) {
        return {};
    }

    DWORD needed = 0;
    GetTokenInformation(token.get(), TokenUser, nullptr, 0, &needed);
    if (needed == 0) {
        return {};
    }

    std::vector<BYTE> buffer(needed);
    if (!GetTokenInformation(token.get(), TokenUser, buffer.data(), needed, &needed)) {
        return {};
    }

    auto* token_user = reinterpret_cast<TOKEN_USER*>(buffer.data());
    LPWSTR str_sid = nullptr;
    if (!ConvertSidToStringSidW(token_user->User.Sid, &str_sid) || str_sid == nullptr) {
        return {};
    }

    std::wstring sid = str_sid;
    LocalFree(str_sid);
    return sid;
}

bool ProfileManager::is_service_sid(std::wstring_view sid) {
    if (sid == L"S-1-5-18" || // Local System
        sid == L"S-1-5-19" || // Local Service
        sid == L"S-1-5-20" || // Network Service
        sid == L".DEFAULT") {
        return true;
    }
    if (sid.starts_with(L"S-1-5-80-") || sid.starts_with(L"S-1-5-82-") ||
        sid.starts_with(L"S-1-5-90-") || sid.starts_with(L"S-1-5-96-")) {
        return true;
    }
    return false;
}

std::vector<UserProfileInfo> ProfileManager::enumerate_profiles(
    bool include_system_profiles,
    const std::wstring& user_filter
) {
    std::vector<UserProfileInfo> profiles;
    namespace fs = std::filesystem;

    const std::wstring prof_list_key = L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList";
    UniqueHKey hList;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, prof_list_key.c_str(), 0,
                      KEY_READ | KEY_WOW64_64KEY, hList.put()) != ERROR_SUCCESS) {
        return profiles;
    }

    DWORD idx = 0;
    wchar_t sid_buf[256];
    DWORD sid_len = 256;

    while (true) {
        sid_len = 256;
        LSTATUS st = RegEnumKeyExW(hList.get(), idx++, sid_buf, &sid_len,
                                   nullptr, nullptr, nullptr, nullptr);
        if (st == ERROR_NO_MORE_ITEMS) {
            break;
        }
        if (st != ERROR_SUCCESS) {
            continue;
        }

        std::wstring sid = sid_buf;
        bool is_service = is_service_sid(sid);
        if (is_service && !include_system_profiles) {
            continue;
        }

        std::wstring subkey_path = prof_list_key + L"\\" + sid;
        UniqueHKey hProf;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, subkey_path.c_str(), 0,
                          KEY_READ | KEY_WOW64_64KEY, hProf.put()) != ERROR_SUCCESS) {
            continue;
        }

        wchar_t raw_img[MAX_PATH * 2]{};
        DWORD img_bytes = sizeof(raw_img);
        if (RegQueryValueExW(hProf.get(), L"ProfileImagePath", nullptr, nullptr,
                             reinterpret_cast<LPBYTE>(raw_img), &img_bytes) != ERROR_SUCCESS) {
            continue;
        }

        wchar_t exp_img[MAX_PATH * 2]{};
        if (ExpandEnvironmentStringsW(raw_img, exp_img, MAX_PATH * 2) == 0) {
            continue;
        }

        std::wstring profile_path = SafetyValidator::normalize_path(exp_img);
        if (profile_path.empty()) {
            continue;
        }

        // Resolve username
        std::wstring username;
        PSID pSid = nullptr;
        if (ConvertStringSidToSidW(sid.c_str(), &pSid)) {
            wchar_t acct_name[256]{};
            DWORD acct_len = 256;
            wchar_t dom_name[256]{};
            DWORD dom_len = 256;
            SID_NAME_USE use;
            if (LookupAccountSidW(nullptr, pSid, acct_name, &acct_len, dom_name, &dom_len, &use)) {
                username = acct_name;
            }
            LocalFree(pSid);
        }
        if (username.empty()) {
            username = fs::path(profile_path).filename().wstring();
        }

        // Filter by user if specified
        if (!user_filter.empty()) {
            if (!equals_ignore_case(sid, user_filter) && !equals_ignore_case(username, user_filter)) {
                continue;
            }
        }

        UserProfileInfo info;
        info.sid = sid;
        info.username = username;
        info.profile_path = profile_path;
        info.is_service_profile = is_service;
        info.ntuser_dat_path = profile_path + L"\\NTUSER.DAT";
        info.usrclass_dat_path = profile_path + L"\\AppData\\Local\\Microsoft\\Windows\\UsrClass.dat";

        // Check if currently loaded in HKEY_USERS
        UniqueHKey hLoaded;
        if (RegOpenKeyExW(HKEY_USERS, sid.c_str(), 0, KEY_READ, hLoaded.put()) == ERROR_SUCCESS) {
            info.is_loaded = true;
        }

        profiles.push_back(info);
    }

    return profiles;
}

Result<void> ProfileManager::clean_profile_registry(
    const UserProfileInfo& profile,
    const Target& target,
    RegistryCleanReport& report,
    bool no_backup
) {
    (void)no_backup;
    namespace fs = std::filesystem;

    std::wstring user_sub;
    LoadedHiveGuard ntuser_guard;

    if (profile.is_loaded) {
        user_sub = profile.sid;
    } else {
        if (!fs::exists(profile.ntuser_dat_path)) {
            return Result<void>::success();
        }

        std::wstring temp_sub = L"obliterator_" + sanitize_sid(profile.sid);
        ntuser_guard = LoadedHiveGuard(HKEY_USERS, temp_sub, profile.ntuser_dat_path);
        auto load_res = ntuser_guard.load();
        if (!load_res) {
            if (load_res.error().code() == ERROR_SHARING_VIOLATION) {
                Logger::warn(L"Profile hive is in use by another session (ERROR_SHARING_VIOLATION); skipping: " +
                             profile.username + L" (" + profile.sid + L")");
                return Result<void>::success();
            }
            Logger::warn(L"Could not load hive for " + profile.username + L": " + load_res.error().message());
            return load_res;
        }
        user_sub = temp_sub;
    }

    const REGSAM views[] = {KEY_WOW64_64KEY, KEY_WOW64_32KEY};

    for (REGSAM view : views) {
        // 1. Clean product and publisher keys
        if (!target.name.empty()) {
            std::wstring prod_sub = user_sub + L"\\Software\\" + target.name;
            if (RegistryCleaner::delete_key_tree(HKEY_USERS, prod_sub, view)) {
                report.product_keys_deleted++;
                report.total_keys_deleted++;
            }

            if (!target.publisher.empty()) {
                std::wstring pub_prod_sub = user_sub + L"\\Software\\" + target.publisher + L"\\" + target.name;
                if (RegistryCleaner::delete_key_tree(HKEY_USERS, pub_prod_sub, view)) {
                    report.product_keys_deleted++;
                    report.total_keys_deleted++;
                }
            }
        }

        // 2. Clean autoruns
        const wchar_t* autorun_subs[] = {
            L"\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            L"\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce"
        };

        for (const auto* ar_sub : autorun_subs) {
            std::wstring full_ar = user_sub + ar_sub;
            UniqueHKey hAr;
            if (RegOpenKeyExW(HKEY_USERS, full_ar.c_str(), 0, KEY_READ | KEY_WRITE | view, hAr.put()) != ERROR_SUCCESS) {
                continue;
            }

            DWORD val_idx = 0;
            wchar_t val_name[256];
            DWORD val_len = 256;
            std::vector<std::wstring> vals_to_delete;

            while (true) {
                val_len = 256;
                LSTATUS st = RegEnumValueW(hAr.get(), val_idx++, val_name, &val_len,
                                           nullptr, nullptr, nullptr, nullptr);
                if (st == ERROR_NO_MORE_ITEMS) {
                    break;
                }
                if (st != ERROR_SUCCESS) {
                    continue;
                }

                wchar_t cmd_buf[MAX_PATH * 2]{};
                DWORD cmd_bytes = sizeof(cmd_buf);
                if (RegQueryValueExW(hAr.get(), val_name, nullptr, nullptr,
                                     reinterpret_cast<LPBYTE>(cmd_buf), &cmd_bytes) == ERROR_SUCCESS) {
                    if (PathHelper::contains_path_reference(cmd_buf, target.root_path)) {
                        vals_to_delete.push_back(val_name);
                    }
                }
            }

            for (const auto& v : vals_to_delete) {
                if (RegDeleteValueW(hAr.get(), v.c_str()) == ERROR_SUCCESS) {
                    report.autorun_values_deleted++;
                    report.total_values_deleted++;
                }
            }
        }

        // 3. Clean user uninstall entries
        std::wstring uninst_sub = user_sub + L"\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall";
        UniqueHKey hUninst;
        if (RegOpenKeyExW(HKEY_USERS, uninst_sub.c_str(), 0, KEY_READ | view, hUninst.put()) == ERROR_SUCCESS) {
            DWORD sub_idx = 0;
            wchar_t sub_name[256];
            DWORD sub_len = 256;
            std::vector<std::wstring> keys_to_delete;

            while (true) {
                sub_len = 256;
                LSTATUS st = RegEnumKeyExW(hUninst.get(), sub_idx++, sub_name, &sub_len,
                                           nullptr, nullptr, nullptr, nullptr);
                if (st == ERROR_NO_MORE_ITEMS) {
                    break;
                }
                if (st != ERROR_SUCCESS) {
                    continue;
                }

                bool match = false;
                if (!target.name.empty() && equals_ignore_case(sub_name, target.name)) {
                    match = true;
                } else if (!target.product_code.empty() && equals_ignore_case(sub_name, target.product_code)) {
                    match = true;
                } else {
                    std::wstring full_entry = uninst_sub + L"\\" + sub_name;
                    UniqueHKey hItem;
                    if (RegOpenKeyExW(HKEY_USERS, full_entry.c_str(), 0, KEY_READ | view, hItem.put()) == ERROR_SUCCESS) {
                        wchar_t str_buf[MAX_PATH * 2]{};
                        DWORD str_bytes = sizeof(str_buf);
                        if (RegQueryValueExW(hItem.get(), L"InstallLocation", nullptr, nullptr,
                                             reinterpret_cast<LPBYTE>(str_buf), &str_bytes) == ERROR_SUCCESS) {
                            if (PathHelper::contains_path_reference(str_buf, target.root_path)) {
                                match = true;
                            }
                        }
                    }
                }

                if (match) {
                    keys_to_delete.push_back(sub_name);
                }
            }

            hUninst.reset();
            for (const auto& k : keys_to_delete) {
                std::wstring full_entry = uninst_sub + L"\\" + k;
                if (RegistryCleaner::delete_key_tree(HKEY_USERS, full_entry, view)) {
                    report.uninstall_keys_deleted++;
                    report.total_keys_deleted++;
                }
            }
        }

        // 4. Clean user App Paths
        std::wstring app_paths_sub = user_sub + L"\\Software\\Microsoft\\Windows\\CurrentVersion\\App Paths";
        UniqueHKey hAppPaths;
        if (RegOpenKeyExW(HKEY_USERS, app_paths_sub.c_str(), 0, KEY_READ | view, hAppPaths.put()) == ERROR_SUCCESS) {
            DWORD sub_idx = 0;
            wchar_t sub_name[256];
            DWORD sub_len = 256;
            std::vector<std::wstring> keys_to_delete;

            while (true) {
                sub_len = 256;
                LSTATUS st = RegEnumKeyExW(hAppPaths.get(), sub_idx++, sub_name, &sub_len,
                                           nullptr, nullptr, nullptr, nullptr);
                if (st == ERROR_NO_MORE_ITEMS) {
                    break;
                }
                if (st != ERROR_SUCCESS) {
                    continue;
                }

                std::wstring full_ap = app_paths_sub + L"\\" + sub_name;
                UniqueHKey hItem;
                if (RegOpenKeyExW(HKEY_USERS, full_ap.c_str(), 0, KEY_READ | view, hItem.put()) == ERROR_SUCCESS) {
                    wchar_t str_buf[MAX_PATH * 2]{};
                    DWORD str_bytes = sizeof(str_buf);
                    if (RegQueryValueExW(hItem.get(), nullptr, nullptr, nullptr,
                                         reinterpret_cast<LPBYTE>(str_buf), &str_bytes) == ERROR_SUCCESS) {
                        if (PathHelper::contains_path_reference(str_buf, target.root_path)) {
                            keys_to_delete.push_back(sub_name);
                        }
                    }
                }
            }

            hAppPaths.reset();
            for (const auto& k : keys_to_delete) {
                std::wstring full_ap = app_paths_sub + L"\\" + k;
                RegistryCleaner::delete_key_tree(HKEY_USERS, full_ap, view);
            }
        }
    }

    // 5. Clean MUICache in user hive
    std::wstring mui_sub = user_sub + L"\\Software\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\MuiCache";
    UniqueHKey hMui;
    if (RegOpenKeyExW(HKEY_USERS, mui_sub.c_str(), 0, KEY_READ | KEY_WRITE, hMui.put()) == ERROR_SUCCESS) {
        DWORD v_idx = 0;
        wchar_t v_name[MAX_PATH * 2];
        DWORD v_len = MAX_PATH * 2;
        std::vector<std::wstring> mui_to_delete;

        while (true) {
            v_len = MAX_PATH * 2;
            LSTATUS st = RegEnumValueW(hMui.get(), v_idx++, v_name, &v_len, nullptr, nullptr, nullptr, nullptr);
            if (st == ERROR_NO_MORE_ITEMS) {
                break;
            }
            if (st != ERROR_SUCCESS) {
                continue;
            }
            if (PathHelper::contains_path_reference(v_name, target.root_path)) {
                mui_to_delete.push_back(v_name);
            }
        }

        for (const auto& v : mui_to_delete) {
            RegDeleteValueW(hMui.get(), v.c_str());
        }
    }

    // 6. Clean classes hive (UsrClass.dat) if not loaded
    if (!profile.is_loaded && fs::exists(profile.usrclass_dat_path)) {
        std::wstring temp_classes_sub = L"obliterator_" + sanitize_sid(profile.sid) + L"_classes";
        LoadedHiveGuard classes_guard(HKEY_USERS, temp_classes_sub, profile.usrclass_dat_path);
        if (classes_guard.load()) {
            std::wstring mui_cls = temp_classes_sub + L"\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\MuiCache";
            UniqueHKey hClsMui;
            if (RegOpenKeyExW(HKEY_USERS, mui_cls.c_str(), 0, KEY_READ | KEY_WRITE, hClsMui.put()) == ERROR_SUCCESS) {
                DWORD v_idx = 0;
                wchar_t v_name[MAX_PATH * 2];
                DWORD v_len = MAX_PATH * 2;
                std::vector<std::wstring> cls_mui_to_delete;
                while (true) {
                    v_len = MAX_PATH * 2;
                    LSTATUS st = RegEnumValueW(hClsMui.get(), v_idx++, v_name, &v_len, nullptr, nullptr, nullptr, nullptr);
                    if (st == ERROR_NO_MORE_ITEMS) {
                        break;
                    }
                    if (st != ERROR_SUCCESS) {
                        continue;
                    }
                    if (PathHelper::contains_path_reference(v_name, target.root_path)) {
                        cls_mui_to_delete.push_back(v_name);
                    }
                }
                for (const auto& v : cls_mui_to_delete) {
                    RegDeleteValueW(hClsMui.get(), v.c_str());
                }
            }
            classes_guard.unload();
        }
    }

    return Result<void>::success();
}

std::vector<LeftoverItem> ProfileManager::find_profile_file_leftovers(
    const UserProfileInfo& profile,
    const Target& target
) {
    std::vector<LeftoverItem> items;
    namespace fs = std::filesystem;

    if (profile.profile_path.empty() || (target.name.empty() && target.root_path.empty())) {
        return items;
    }

    std::error_code ec;

    // 1. AppData Roaming and Local
    const std::wstring appdata_dirs[] = {
        profile.profile_path + L"\\AppData\\Roaming",
        profile.profile_path + L"\\AppData\\Local"
    };

    for (const auto& base_dir : appdata_dirs) {
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

            if (!SafetyValidator::validate_path(full_path)) {
                continue;
            }

            if (!target.name.empty() && equals_ignore_case(dir_name, target.name)) {
                items.push_back({full_path, LeftoverKind::Folder, LeftoverConfidence::Definite,
                                 L"AppData folder (" + profile.username + L")"});
            } else if (!target.publisher.empty() && equals_ignore_case(dir_name, target.publisher)) {
                bool found_child = false;
                for (const auto& sub_entry : fs::directory_iterator(entry.path(), ec)) {
                    if (sub_entry.is_directory(ec) && !target.name.empty() &&
                        equals_ignore_case(sub_entry.path().filename().wstring(), target.name)) {
                        items.push_back({sub_entry.path().wstring(), LeftoverKind::Folder,
                                         LeftoverConfidence::Definite,
                                         L"Product inside publisher folder (" + profile.username + L")"});
                        found_child = true;
                    }
                }
                if (!found_child) {
                    items.push_back({full_path, LeftoverKind::Folder, LeftoverConfidence::Definite,
                                     L"Publisher folder (" + profile.username + L")"});
                }
            } else if (!target.name.empty() && to_lower_str(dir_name).find(to_lower_str(target.name)) != std::wstring::npos) {
                items.push_back({full_path, LeftoverKind::Folder, LeftoverConfidence::Possible,
                                 L"Partial name match (" + profile.username + L")"});
            }
        }
    }

    // 2. Documents (only known application data directories matching target name/publisher)
    fs::path docs_path(profile.profile_path + L"\\Documents");
    if (fs::exists(docs_path, ec) && fs::is_directory(docs_path, ec)) {
        for (const auto& entry : fs::directory_iterator(docs_path, ec)) {
            if (!entry.is_directory(ec)) {
                continue;
            }

            const std::wstring dir_name = entry.path().filename().wstring();
            const std::wstring full_path = entry.path().wstring();

            if (!SafetyValidator::validate_path(full_path)) {
                continue;
            }

            if (!target.name.empty() && equals_ignore_case(dir_name, target.name)) {
                items.push_back({full_path, LeftoverKind::Folder, LeftoverConfidence::Definite,
                                 L"Documents data directory (" + profile.username + L")"});
            } else if (!target.publisher.empty() && equals_ignore_case(dir_name, target.publisher)) {
                for (const auto& sub : fs::directory_iterator(entry.path(), ec)) {
                    if (sub.is_directory(ec) && !target.name.empty() &&
                        equals_ignore_case(sub.path().filename().wstring(), target.name)) {
                        items.push_back({sub.path().wstring(), LeftoverKind::Folder,
                                         LeftoverConfidence::Definite,
                                         L"Documents publisher data directory (" + profile.username + L")"});
                    }
                }
            }
        }
    }

    // 3. Temp directory
    fs::path temp_path(profile.profile_path + L"\\AppData\\Local\\Temp");
    if (fs::exists(temp_path, ec) && fs::is_directory(temp_path, ec)) {
        for (const auto& entry : fs::directory_iterator(temp_path, ec)) {
            const std::wstring item_name = entry.path().filename().wstring();
            const std::wstring full_path = entry.path().wstring();

            if (!target.name.empty() &&
                (equals_ignore_case(item_name, target.name) ||
                 to_lower_str(item_name).starts_with(to_lower_str(target.name)))) {
                items.push_back({full_path, entry.is_directory(ec) ? LeftoverKind::Folder : LeftoverKind::Shortcut,
                                 LeftoverConfidence::Definite,
                                 L"Temp file/directory (" + profile.username + L")"});
            }
        }
    }

    // 4. Desktop and Start Menu shortcuts
    const std::wstring shortcut_bases[] = {
        profile.profile_path + L"\\Desktop",
        profile.profile_path + L"\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs"
    };

    for (const auto& sc_base : shortcut_bases) {
        fs::path sc_path(sc_base);
        if (!fs::exists(sc_path, ec)) {
            continue;
        }

        for (const auto& entry : fs::recursive_directory_iterator(sc_path, ec)) {
            if (!entry.is_regular_file(ec) || entry.path().extension() != L".lnk") {
                continue;
            }

            const std::wstring lnk_path = entry.path().wstring();
            if (!SafetyValidator::validate_path(lnk_path)) {
                continue;
            }

            const std::wstring target_exe = LeftoversCleaner::resolve_shortcut_target(lnk_path);
            const std::wstring stem = entry.path().stem().wstring();

            if (!target.root_path.empty() && PathHelper::is_same_or_subpath(target.root_path, target_exe)) {
                items.push_back({lnk_path, LeftoverKind::Shortcut, LeftoverConfidence::Definite,
                                 L"Shortcut points to target (" + profile.username + L")"});
            } else if (!target.name.empty() && equals_ignore_case(stem, target.name)) {
                items.push_back({lnk_path, LeftoverKind::Shortcut, LeftoverConfidence::Definite,
                                 L"Shortcut name match (" + profile.username + L")"});
            }
        }
    }

    return items;
}

} // namespace obliterator
