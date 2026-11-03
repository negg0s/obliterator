#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include "obliterator/handles.hpp"
#include "obliterator/result.hpp"
#include "obliterator/target.hpp"

#include <string>
#include <vector>

namespace obliterator {

struct RegistryCleanReport {
    size_t uninstall_keys_deleted{0};
    size_t autorun_values_deleted{0};
    size_t shell_entries_deleted{0};
    size_t product_keys_deleted{0};
    size_t total_keys_deleted{0};
    size_t total_values_deleted{0};
    size_t items_backed_up{0};
    std::wstring backup_directory;
    std::vector<std::wstring> failed_items;
};

struct AutorunEntry {
    HKEY root_key{nullptr};
    std::wstring subkey_path;
    std::wstring value_name;
    std::wstring command;
    REGSAM sam_view{0};
};

struct ShellVerbEntry {
    HKEY root_key{nullptr};
    std::wstring subkey_path;
    std::wstring command_or_server;
    bool is_clsid{false};
};

struct ProductKeyEntry {
    HKEY root_key{nullptr};
    std::wstring subkey_path;
    REGSAM sam_view{0};
};

class RegistryBackup {
public:
    static void set_enabled(bool enabled);
    static bool is_enabled();
    static void set_custom_backup_directory(const std::wstring& dir);
    static std::wstring get_backup_directory();
    static Result<std::wstring> export_key(HKEY root, const std::wstring& subkey, REGSAM sam = 0);
    static Result<std::wstring> export_value(HKEY root, const std::wstring& subkey,
                                             const std::wstring& value_name, REGSAM sam = 0);
};

class RegistryCleaner {
public:
    static std::vector<AutorunEntry> find_autorun_entries(const std::wstring& target_root);
    static std::vector<ShellVerbEntry> find_shell_entries(const std::wstring& target_root);
    static std::vector<ProductKeyEntry> find_product_keys(const Target& target);

    static Result<void> delete_key_tree(HKEY root, const std::wstring& subkey, REGSAM sam = 0);
    static Result<void> clean(const Target& target, RegistryCleanReport& report,
                              bool no_backup = false);
};

} // namespace obliterator
