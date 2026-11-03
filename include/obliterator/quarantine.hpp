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

#include <cstdint>
#include <string>
#include <vector>

namespace obliterator {

struct QuarantineFileEntry {
    std::wstring original_path;
    std::wstring relative_path;
    uint64_t size{0};
    std::wstring sha256;
    std::wstring sddl;
    DWORD attributes{FILE_ATTRIBUTE_NORMAL};
    uint64_t creation_time{0};
    uint64_t last_write_time{0};
};

struct QuarantineSessionInfo {
    std::wstring session_id;
    std::wstring timestamp;
    std::wstring target_name;
    std::wstring target_root;
    size_t files_count{0};
    uint64_t total_bytes{0};
    size_t registry_keys_count{0};
};

struct QuarantineReport {
    bool success{false};
    std::wstring session_id;
    std::wstring session_directory;
    size_t files_quarantined{0};
    uint64_t bytes_quarantined{0};
    size_t registry_keys_saved{0};
    std::vector<std::wstring> warnings;
};

struct RestoreReport {
    bool success{false};
    std::wstring session_id;
    size_t files_restored{0};
    size_t acls_restored{0};
    size_t timestamps_restored{0};
    size_t registry_keys_restored{0};
    std::vector<std::wstring> warnings;
};

class QuarantineManager {
public:
    static std::wstring get_quarantine_base_dir();

    // Verifies free disk space on quarantine volume before moving files
    static Result<void> check_free_space(uint64_t required_bytes);

    // Executes quarantine for target directory and registry entries
    static Result<QuarantineReport> quarantine_target(const Target& target);

    // Lists all stored quarantine sessions
    static std::vector<QuarantineSessionInfo> list_sessions();

    // Restores files, ACLs, and registry keys from a quarantine session
    static Result<RestoreReport> restore_session(const std::wstring& session_id);

    // Purges a specific quarantine session by id
    static Result<void> purge_session(const std::wstring& session_id);

    // Purges quarantine sessions older than specified days
    static Result<size_t> purge_older_than(uint32_t days);

    // Captures ACL in SDDL format for a given path
    static std::wstring get_path_sddl(const std::wstring& path);

    // Applies SDDL string to a path
    static bool apply_path_sddl(const std::wstring& path, const std::wstring& sddl);

    // Binary registry save helper using RegSaveKeyExW
    static bool save_registry_binary_hive(HKEY hKey, const std::wstring& destination_file);
};

} // namespace obliterator
