#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include "obliterator/handles.hpp"
#include "obliterator/leftovers.hpp"
#include "obliterator/registry_cleaner.hpp"
#include "obliterator/result.hpp"
#include "obliterator/target.hpp"

#include <string>
#include <string_view>
#include <vector>

namespace obliterator {

struct UserProfileInfo {
    std::wstring sid;
    std::wstring username;
    std::wstring profile_path;
    std::wstring ntuser_dat_path;
    std::wstring usrclass_dat_path;
    bool is_service_profile{false};
    bool is_loaded{false};
};

class LoadedHiveGuard {
public:
    LoadedHiveGuard() = default;
    LoadedHiveGuard(HKEY root, std::wstring subkey_name, std::wstring hive_file_path);
    ~LoadedHiveGuard();

    LoadedHiveGuard(const LoadedHiveGuard&) = delete;
    LoadedHiveGuard& operator=(const LoadedHiveGuard&) = delete;

    LoadedHiveGuard(LoadedHiveGuard&& other) noexcept;
    LoadedHiveGuard& operator=(LoadedHiveGuard&& other) noexcept;

    Result<void> load();
    Result<void> unload();

    [[nodiscard]] bool is_loaded() const noexcept { return is_loaded_; }
    [[nodiscard]] HKEY root() const noexcept { return root_; }
    [[nodiscard]] const std::wstring& subkey_name() const noexcept { return subkey_name_; }
    [[nodiscard]] const std::wstring& file_path() const noexcept { return hive_file_path_; }

private:
    HKEY root_{HKEY_USERS};
    std::wstring subkey_name_;
    std::wstring hive_file_path_;
    bool is_loaded_{false};
};

class ProfileManager {
public:
    static std::wstring get_current_user_sid();
    static bool is_service_sid(std::wstring_view sid);

    static std::vector<UserProfileInfo> enumerate_profiles(
        bool include_system_profiles = false,
        const std::wstring& user_filter = {}
    );

    static Result<void> clean_profile_registry(
        const UserProfileInfo& profile,
        const Target& target,
        RegistryCleanReport& report,
        bool no_backup = false
    );

    static std::vector<LeftoverItem> find_profile_file_leftovers(
        const UserProfileInfo& profile,
        const Target& target
    );
};

} // namespace obliterator
