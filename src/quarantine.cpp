#include "obliterator/quarantine.hpp"
#include "obliterator/audit.hpp"
#include "obliterator/crypto.hpp"
#include "obliterator/handles.hpp"
#include "obliterator/log.hpp"
#include "obliterator/path.hpp"
#include "obliterator/registry_cleaner.hpp"
#include "obliterator/volume.hpp"
#include "obliterator/wiper.hpp"

#include <aclapi.h>
#include <cwctype>
#include <sddl.h>

#include <chrono>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <vector>

namespace obliterator {

namespace fs = std::filesystem;

static std::wstring s_custom_quarantine_base;

void QuarantineManager::set_custom_quarantine_base_dir(const std::wstring& dir) {
    s_custom_quarantine_base = dir;
}

std::wstring QuarantineManager::get_quarantine_base_dir() {
    if (!s_custom_quarantine_base.empty()) {
        return s_custom_quarantine_base;
    }
    wchar_t buf[MAX_PATH]{};
    if (GetEnvironmentVariableW(L"ProgramData", buf, MAX_PATH) > 0) {
        return std::wstring(buf) + L"\\obliterator\\quarantine";
    }
    return L"C:\\ProgramData\\obliterator\\quarantine";
}

std::wstring QuarantineManager::get_quarantine_base_dir_for_path(const std::wstring& target_path) {
    if (!s_custom_quarantine_base.empty()) {
        return s_custom_quarantine_base;
    }

    if (!target_path.empty()) {
        const std::wstring drive = VolumeManager::get_path_drive(target_path);
        if (!drive.empty()) {
            std::wstring candidate = drive + L"\\$obliterator_quarantine";
            std::error_code ec;
            fs::create_directories(candidate, ec);
            if (!ec && fs::exists(candidate, ec)) {
                SetFileAttributesW(candidate.c_str(), FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM);
                return candidate;
            }
        }
    }

    return get_quarantine_base_dir();
}

std::vector<std::wstring> QuarantineManager::get_all_quarantine_roots() {
    std::vector<std::wstring> roots;
    std::vector<std::wstring> seen;

    auto add_unique = [&](const std::wstring& p) {
        if (p.empty()) return;
        for (const auto& s : seen) {
            if (_wcsicmp(s.c_str(), p.c_str()) == 0) return;
        }
        seen.push_back(p);
        roots.push_back(p);
    };

    if (!s_custom_quarantine_base.empty()) {
        add_unique(s_custom_quarantine_base);
    }
    add_unique(get_quarantine_base_dir());

    for (const auto& d : VolumeManager::get_fixed_drives()) {
        std::wstring per_vol = d + L"\\$obliterator_quarantine";
        std::error_code ec;
        if (fs::exists(per_vol, ec)) {
            add_unique(per_vol);
        }
    }
    return roots;
}

std::wstring QuarantineManager::find_session_dir(const std::wstring& session_id) {
    if (session_id.empty()) {
        return {};
    }

    std::error_code ec;
    if (fs::exists(session_id, ec) && fs::is_directory(session_id, ec)) {
        return session_id;
    }

    for (const auto& root : get_all_quarantine_roots()) {
        std::wstring candidate = root + L"\\" + session_id;
        if (fs::exists(candidate, ec) && fs::is_directory(candidate, ec)) {
            return candidate;
        }
    }
    return {};
}

static std::wstring escape_json(std::wstring_view input) {
    std::wstring out;
    out.reserve(input.size() + 16);
    for (wchar_t c : input) {
        if (c == L'\\') {
            out += L"\\\\";
        } else if (c == L'\"') {
            out += L"\\\"";
        } else if (c == L'\n') {
            out += L"\\n";
        } else if (c == L'\r') {
            out += L"\\r";
        } else if (c == L'\t') {
            out += L"\\t";
        } else {
            out += c;
        }
    }
    return out;
}

static std::wstring generate_session_id(std::wstring_view target_name) {
    SYSTEMTIME st{};
    GetLocalTime(&st);
    wchar_t buf[64]{};
    swprintf_s(buf, L"%04u%02u%02u_%02u%02u%02u",
               st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);

    std::wstring clean_name;
    clean_name.reserve(target_name.size());
    for (wchar_t c : target_name) {
        if (iswalnum(c) || c == L'_' || c == L'-') {
            clean_name.push_back(c);
        } else if (c == L' ') {
            clean_name.push_back(L'_');
        }
    }
    if (clean_name.empty()) {
        clean_name = L"target";
    }
    return std::wstring(buf) + L"_" + clean_name;
}

static std::wstring make_quarantine_relative_path(const std::wstring& full_path) {
    std::wstring p = full_path;
    if (p.starts_with(L"\\\\?\\")) {
        p.erase(0, 4);
    }
    if (p.starts_with(L"\\??\\")) {
        p.erase(0, 4);
    }

    if (p.size() >= 2 && p[1] == L':') {
        wchar_t drive = p[0];
        std::wstring rest = (p.size() > 3) ? p.substr(3) : L"";
        return std::wstring(L"drive_") + drive + L"\\" + rest;
    }

    if (p.starts_with(L"\\\\") || p.starts_with(L"UNC\\")) {
        size_t offset = p.starts_with(L"UNC\\") ? 4 : 2;
        return L"unc\\" + p.substr(offset);
    }

    return p;
}

std::wstring QuarantineManager::get_path_sddl(const std::wstring& path) {
    const std::wstring ext_path = FileWiper::ensure_extended_path(path);
    PSECURITY_DESCRIPTOR pSD = nullptr;
    DWORD res = GetNamedSecurityInfoW(
        ext_path.c_str(),
        SE_FILE_OBJECT,
        DACL_SECURITY_INFORMATION | OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION,
        nullptr, nullptr, nullptr, nullptr, &pSD
    );
    if (res != ERROR_SUCCESS || !pSD) {
        return {};
    }

    LPWSTR sddl = nullptr;
    if (!ConvertSecurityDescriptorToStringSecurityDescriptorW(
            pSD, SDDL_REVISION_1,
            DACL_SECURITY_INFORMATION | OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION,
            &sddl, nullptr)) {
        LocalFree(pSD);
        return {};
    }

    std::wstring result(sddl);
    LocalFree(sddl);
    LocalFree(pSD);
    return result;
}

bool QuarantineManager::apply_path_sddl(const std::wstring& path, const std::wstring& sddl) {
    if (sddl.empty()) {
        return false;
    }

    PSECURITY_DESCRIPTOR pSD = nullptr;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.c_str(), SDDL_REVISION_1, &pSD, nullptr)) {
        return false;
    }

    PACL pDacl = nullptr;
    PSID pOwner = nullptr;
    PSID pGroup = nullptr;
    BOOL dacl_present = FALSE;
    BOOL dacl_defaulted = FALSE;
    GetSecurityDescriptorDacl(pSD, &dacl_present, &pDacl, &dacl_defaulted);

    BOOL owner_defaulted = FALSE;
    GetSecurityDescriptorOwner(pSD, &pOwner, &owner_defaulted);

    BOOL group_defaulted = FALSE;
    GetSecurityDescriptorGroup(pSD, &pGroup, &group_defaulted);

    DWORD sec_info = 0;
    if (dacl_present && pDacl) sec_info |= DACL_SECURITY_INFORMATION;
    if (pOwner) sec_info |= OWNER_SECURITY_INFORMATION;
    if (pGroup) sec_info |= GROUP_SECURITY_INFORMATION;

    const std::wstring ext_path = FileWiper::ensure_extended_path(path);
    DWORD res = SetNamedSecurityInfoW(
        const_cast<LPWSTR>(ext_path.c_str()),
        SE_FILE_OBJECT,
        sec_info,
        pOwner,
        pGroup,
        pDacl,
        nullptr
    );

    LocalFree(pSD);
    return res == ERROR_SUCCESS;
}

bool QuarantineManager::save_registry_binary_hive(HKEY hKey, const std::wstring& destination_file) {
    std::error_code ec;
    fs::remove(destination_file, ec);
    LSTATUS st = RegSaveKeyExW(hKey, destination_file.c_str(), nullptr, REG_LATEST_FORMAT);
    return st == ERROR_SUCCESS;
}

Result<void> QuarantineManager::check_free_space(uint64_t required_bytes, const std::wstring& target_quarantine_dir) {
    const std::wstring base_dir = target_quarantine_dir.empty() ? get_quarantine_base_dir() : target_quarantine_dir;
    std::error_code ec;
    fs::create_directories(base_dir, ec);

    ULARGE_INTEGER free_bytes_available{};
    ULARGE_INTEGER total_bytes{};
    ULARGE_INTEGER total_free_bytes{};

    if (!GetDiskFreeSpaceExW(base_dir.c_str(), &free_bytes_available, &total_bytes, &total_free_bytes)) {
        return Win32Error::from_code(GetLastError());
    }

    constexpr uint64_t kSafetyBuffer = 50ULL * 1024ULL * 1024ULL; // 50 MB buffer
    const uint64_t total_needed = required_bytes + kSafetyBuffer;

    if (free_bytes_available.QuadPart < total_needed) {
        Logger::error(L"Insufficient free disk space on quarantine volume. Required: " +
                      FileWiper::format_bytes(total_needed) + L", Available: " +
                      FileWiper::format_bytes(free_bytes_available.QuadPart));
        return Win32Error::from_code(ERROR_DISK_FULL);
    }

    return Result<void>::success();
}

static void collect_files_recursive(const fs::path& dir, std::vector<fs::path>& out_files, uint64_t& out_total_bytes) {
    std::error_code ec;
    if (!fs::exists(dir, ec)) {
        return;
    }

    for (const auto& entry : fs::recursive_directory_iterator(dir, fs::directory_options::skip_permission_denied, ec)) {
        if (ec) {
            continue;
        }
        if (entry.is_regular_file(ec)) {
            out_files.push_back(entry.path());
            out_total_bytes += entry.file_size(ec);
        }
    }
}

Result<QuarantineReport> QuarantineManager::quarantine_target(const Target& target, const std::wstring& custom_quarantine_dir) {
    QuarantineReport report;
    if (target.root_path.empty()) {
        return report;
    }

    std::vector<fs::path> files_to_quarantine;
    uint64_t total_bytes = 0;
    collect_files_recursive(target.root_path, files_to_quarantine, total_bytes);

    std::wstring base_dir = custom_quarantine_dir;
    if (base_dir.empty()) {
        base_dir = get_quarantine_base_dir_for_path(target.root_path);
    }

    const bool is_intra_volume = VolumeManager::is_same_volume(target.root_path, base_dir);
    // On the same volume, file moves do not allocate physical payload space (instant MFT rename)
    const uint64_t needed_space = is_intra_volume ? (50ULL * 1024ULL * 1024ULL) : total_bytes;
    auto space_res = check_free_space(needed_space, base_dir);
    if (!space_res) {
        return space_res.error();
    }

    const std::wstring session_id = generate_session_id(target.name);
    const std::wstring session_dir = base_dir + L"\\" + session_id;
    const std::wstring files_dir = session_dir + L"\\files";
    const std::wstring reg_dir = session_dir + L"\\registry";

    std::error_code ec;
    fs::create_directories(files_dir, ec);
    fs::create_directories(reg_dir, ec);

    report.session_id = session_id;
    report.session_directory = session_dir;

    std::vector<QuarantineFileEntry> manifest_entries;
    manifest_entries.reserve(files_to_quarantine.size());

    for (const auto& f : files_to_quarantine) {
        std::wstring orig_path = f.wstring();
        std::wstring rel_path = make_quarantine_relative_path(orig_path);
        std::wstring dest_path = files_dir + L"\\" + rel_path;

        fs::create_directories(fs::path(dest_path).parent_path(), ec);

        QuarantineFileEntry entry;
        entry.original_path = orig_path;
        entry.relative_path = rel_path;
        entry.size = fs::file_size(f, ec);
        entry.sha256 = CryptoHelper::compute_sha256_file(orig_path);
        entry.sddl = get_path_sddl(orig_path);
        entry.attributes = GetFileAttributesW(orig_path.c_str());

        const std::wstring ext_orig = FileWiper::ensure_extended_path(orig_path);
        UniqueHandle hOrig(CreateFileW(
            ext_orig.c_str(),
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            nullptr,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS,
            nullptr
        ));
        if (hOrig) {
            FILETIME ftCreate{}, ftAccess{}, ftWrite{};
            if (GetFileTime(hOrig.get(), &ftCreate, &ftAccess, &ftWrite)) {
                entry.creation_time = (static_cast<uint64_t>(ftCreate.dwHighDateTime) << 32) | ftCreate.dwLowDateTime;
                entry.last_write_time = (static_cast<uint64_t>(ftWrite.dwHighDateTime) << 32) | ftWrite.dwLowDateTime;
            }
        }
        hOrig.reset();

        AuditJournal::log_before(L"file_quarantine", orig_path, dest_path);

        const std::wstring ext_dest = FileWiper::ensure_extended_path(dest_path);
        FileWiper::strip_file_attributes(orig_path);

        bool moved = false;
        if (is_intra_volume) {
            // Fast atomic intra-volume move
            moved = MoveFileExW(ext_orig.c_str(), ext_dest.c_str(), MOVEFILE_REPLACE_EXISTING);
        }
        if (!moved) {
            moved = MoveFileExW(ext_orig.c_str(), ext_dest.c_str(),
                                MOVEFILE_COPY_ALLOWED | MOVEFILE_REPLACE_EXISTING);
        }

        if (moved) {
            report.files_quarantined++;
            report.bytes_quarantined += entry.size;
            manifest_entries.push_back(std::move(entry));
            AuditJournal::log_after(L"file_quarantine", orig_path, true, 0, dest_path);
        } else {
            DWORD err = GetLastError();
            AuditJournal::log_after(L"file_quarantine", orig_path, false, err);
            report.warnings.push_back(L"Failed to move file to quarantine: " + orig_path);
        }
    }

    // Save binary and text registry backups
    struct RegBackupInfo {
        std::wstring root_name;
        std::wstring subkey;
        std::wstring reg_file;
        std::wstring hive_file;
    };
    std::vector<RegBackupInfo> saved_registry_keys;

    size_t key_idx = 0;
    for (const auto& reg_entry : target.registry_entries) {
        key_idx++;
        std::wstring safe_name = L"key_" + std::to_wstring(key_idx);
        std::wstring reg_file = reg_dir + L"\\" + safe_name + L".reg";
        std::wstring hive_file = reg_dir + L"\\" + safe_name + L".hive";

        UniqueHKey key;
        if (RegOpenKeyExW(reg_entry.root_key, reg_entry.subkey_path.c_str(), 0,
                          KEY_READ | reg_entry.sam_view, key.put()) == ERROR_SUCCESS) {
            bool bin_ok = save_registry_binary_hive(key.get(), hive_file);
            AuditJournal::log_after(L"registry_binary_backup", reg_entry.subkey_path, bin_ok);

            std::wstring root_str = (reg_entry.root_key == HKEY_LOCAL_MACHINE) ? L"HKLM" :
                                    (reg_entry.root_key == HKEY_CURRENT_USER) ? L"HKCU" : L"HKCR";
            saved_registry_keys.push_back({
                root_str,
                reg_entry.subkey_path,
                bin_ok ? safe_name + L".hive" : L"",
                safe_name + L".reg"
            });
            report.registry_keys_saved++;
        }
    }

    // Write manifest.json
    std::wofstream mf(session_dir + L"\\manifest.json");
    if (mf.is_open()) {
        mf << L"[\n";
        for (size_t i = 0; i < manifest_entries.size(); ++i) {
            const auto& m = manifest_entries[i];
            mf << L"  {\n"
               << L"    \"original_path\": \"" << escape_json(m.original_path) << L"\",\n"
               << L"    \"relative_path\": \"" << escape_json(m.relative_path) << L"\",\n"
               << L"    \"size\": " << m.size << L",\n"
               << L"    \"sha256\": \"" << m.sha256 << L"\",\n"
               << L"    \"sddl\": \"" << escape_json(m.sddl) << L"\",\n"
               << L"    \"attributes\": " << m.attributes << L",\n"
               << L"    \"creation_time\": " << m.creation_time << L",\n"
               << L"    \"last_write_time\": " << m.last_write_time << L"\n"
               << L"  }" << (i + 1 < manifest_entries.size() ? L"," : L"") << L"\n";
        }
        mf << L"]\n";
        mf.close();
    }

    // Write registry_manifest.json
    std::wofstream rmf(session_dir + L"\\registry_manifest.json");
    if (rmf.is_open()) {
        rmf << L"[\n";
        for (size_t i = 0; i < saved_registry_keys.size(); ++i) {
            const auto& r = saved_registry_keys[i];
            rmf << L"  {\n"
                << L"    \"root\": \"" << escape_json(r.root_name) << L"\",\n"
                << L"    \"subkey\": \"" << escape_json(r.subkey) << L"\",\n"
                << L"    \"hive_file\": \"" << escape_json(r.hive_file) << L"\",\n"
                << L"    \"reg_file\": \"" << escape_json(r.reg_file) << L"\"\n"
                << L"  }" << (i + 1 < saved_registry_keys.size() ? L"," : L"") << L"\n";
        }
        rmf << L"]\n";
        rmf.close();
    }

    // Write session.json
    SYSTEMTIME now_st{};
    GetLocalTime(&now_st);
    wchar_t time_str[64]{};
    swprintf_s(time_str, L"%04u-%02u-%02u %02u:%02u:%02u",
               now_st.wYear, now_st.wMonth, now_st.wDay,
               now_st.wHour, now_st.wMinute, now_st.wSecond);

    std::wofstream sf(session_dir + L"\\session.json");
    if (sf.is_open()) {
        sf << L"{\n"
           << L"  \"session_id\": \"" << escape_json(session_id) << L"\",\n"
           << L"  \"timestamp\": \"" << escape_json(time_str) << L"\",\n"
           << L"  \"target_name\": \"" << escape_json(target.name) << L"\",\n"
           << L"  \"target_root\": \"" << escape_json(target.root_path) << L"\",\n"
           << L"  \"files_count\": " << report.files_quarantined << L",\n"
           << L"  \"total_bytes\": " << report.bytes_quarantined << L",\n"
           << L"  \"registry_keys_count\": " << report.registry_keys_saved << L"\n"
           << L"}\n";
        sf.close();
    }

    report.success = true;
    Logger::info(L"Quarantined " + std::to_wstring(report.files_quarantined) +
                 L" files (" + FileWiper::format_bytes(report.bytes_quarantined) +
                 L") to " + session_dir);

    // After files are quarantined, wipe any remaining empty directory hierarchy
    PhysicalWipeReport wipe_rep;
    FileWiper::wipe_physical_tree(target.root_path, wipe_rep);

    return report;
}

static std::wstring extract_json_field(const std::wstring& content, std::wstring_view key) {
    const std::wstring search = L"\"" + std::wstring(key) + L"\"";
    size_t pos = content.find(search);
    if (pos == std::wstring::npos) {
        return {};
    }

    size_t colon = content.find(L':', pos);
    if (colon == std::wstring::npos) {
        return {};
    }

    size_t start = content.find_first_not_of(L" \t\r\n", colon + 1);
    if (start == std::wstring::npos) {
        return {};
    }

    if (content[start] == L'\"') {
        std::wstring str;
        size_t i = start + 1;
        while (i < content.size()) {
            if (content[i] == L'\\') {
                if (i + 1 < content.size()) {
                    if (content[i + 1] == L'\\') str += L'\\';
                    else if (content[i + 1] == L'\"') str += L'\"';
                    else if (content[i + 1] == L'n') str += L'\n';
                    else if (content[i + 1] == L'r') str += L'\r';
                    else if (content[i + 1] == L't') str += L'\t';
                    else str += content[i + 1];
                    i += 2;
                    continue;
                }
            } else if (content[i] == L'\"') {
                break;
            } else {
                str += content[i];
            }
            i++;
        }
        return str;
    }

    size_t end = content.find_first_of(L",}\r\n", start);
    if (end == std::wstring::npos) {
        end = content.size();
    }
    return content.substr(start, end - start);
}

std::vector<QuarantineSessionInfo> QuarantineManager::list_sessions() {
    std::vector<QuarantineSessionInfo> sessions;
    const auto roots = get_all_quarantine_roots();
    std::error_code ec;

    for (const auto& base_dir : roots) {
        if (!fs::exists(base_dir, ec)) {
            continue;
        }

        for (const auto& entry : fs::directory_iterator(base_dir, ec)) {
            if (entry.is_directory(ec)) {
                std::wstring session_file = entry.path().wstring() + L"\\session.json";
                std::wifstream in(session_file);
                if (in.is_open()) {
                    std::wstringstream ss;
                    ss << in.rdbuf();
                    std::wstring content = ss.str();

                    QuarantineSessionInfo info;
                    info.session_id = extract_json_field(content, L"session_id");
                    info.timestamp = extract_json_field(content, L"timestamp");
                    info.target_name = extract_json_field(content, L"target_name");
                    info.target_root = extract_json_field(content, L"target_root");
                    try {
                        info.files_count = std::stoull(extract_json_field(content, L"files_count"));
                        info.total_bytes = std::stoull(extract_json_field(content, L"total_bytes"));
                        info.registry_keys_count = std::stoull(extract_json_field(content, L"registry_keys_count"));
                    } catch (...) {}

                    if (info.session_id.empty()) {
                        info.session_id = entry.path().filename().wstring();
                    }

                    // Avoid duplicate session IDs across roots
                    bool already_present = false;
                    for (const auto& existing : sessions) {
                        if (existing.session_id == info.session_id) {
                            already_present = true;
                            break;
                        }
                    }
                    if (!already_present) {
                        sessions.push_back(std::move(info));
                    }
                }
            }
        }
    }

    std::sort(sessions.begin(), sessions.end(), [](const auto& a, const auto& b) {
        return a.session_id > b.session_id;
    });

    return sessions;
}

static std::vector<QuarantineFileEntry> parse_manifest(const std::wstring& manifest_file) {
    std::vector<QuarantineFileEntry> entries;
    std::wifstream in(manifest_file);
    if (!in.is_open()) {
        return entries;
    }

    std::wstringstream ss;
    ss << in.rdbuf();
    std::wstring content = ss.str();

    size_t curr = 0;
    while ((curr = content.find(L'{', curr)) != std::wstring::npos) {
        size_t close_brace = content.find(L'}', curr);
        if (close_brace == std::wstring::npos) {
            break;
        }

        std::wstring item = content.substr(curr, close_brace - curr + 1);
        QuarantineFileEntry e;
        e.original_path = extract_json_field(item, L"original_path");
        e.relative_path = extract_json_field(item, L"relative_path");
        e.sha256 = extract_json_field(item, L"sha256");
        e.sddl = extract_json_field(item, L"sddl");

        try {
            e.size = std::stoull(extract_json_field(item, L"size"));
            e.attributes = static_cast<DWORD>(std::stoul(extract_json_field(item, L"attributes")));
            e.creation_time = std::stoull(extract_json_field(item, L"creation_time"));
            e.last_write_time = std::stoull(extract_json_field(item, L"last_write_time"));
        } catch (...) {}

        if (!e.original_path.empty()) {
            entries.push_back(std::move(e));
        }
        curr = close_brace + 1;
    }

    return entries;
}

Result<RestoreReport> QuarantineManager::restore_session(const std::wstring& session_id) {
    RestoreReport report;
    report.session_id = session_id;

    const std::wstring session_dir = find_session_dir(session_id);
    std::error_code ec;
    if (session_dir.empty() || !fs::exists(session_dir, ec)) {
        Logger::error(L"Quarantine session not found: " + session_id);
        return Win32Error::from_code(ERROR_FILE_NOT_FOUND);
    }

    std::wcout << L"\nRestoring files, permissions, and registry keys for session: " << session_id << L"\n"
               << L"Notice: Terminated processes, services, and drivers will NOT be resurrected.\n\n";

    const std::wstring manifest_file = session_dir + L"\\manifest.json";
    const auto manifest = parse_manifest(manifest_file);

    const std::wstring files_dir = session_dir + L"\\files";

    for (const auto& entry : manifest) {
        std::wstring quarantined_file = files_dir + L"\\" + entry.relative_path;
        if (!fs::exists(quarantined_file, ec)) {
            report.warnings.push_back(L"Quarantined file missing from archive: " + quarantined_file);
            continue;
        }

        fs::create_directories(fs::path(entry.original_path).parent_path(), ec);

        AuditJournal::log_before(L"file_restore", quarantined_file, entry.original_path);

        const std::wstring ext_src = FileWiper::ensure_extended_path(quarantined_file);
        const std::wstring ext_dst = FileWiper::ensure_extended_path(entry.original_path);

        if (MoveFileExW(ext_src.c_str(), ext_dst.c_str(),
                        MOVEFILE_COPY_ALLOWED | MOVEFILE_REPLACE_EXISTING)) {
            report.files_restored++;
            AuditJournal::log_after(L"file_restore", entry.original_path, true, 0, quarantined_file);

            // Restore timestamps
            if (entry.last_write_time != 0) {
                UniqueHandle hFile(CreateFileW(
                    ext_dst.c_str(),
                    FILE_WRITE_ATTRIBUTES,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    nullptr,
                    OPEN_EXISTING,
                    FILE_FLAG_BACKUP_SEMANTICS,
                    nullptr
                ));
                if (hFile) {
                    FILETIME ftCreate{};
                    ftCreate.dwLowDateTime = static_cast<DWORD>(entry.creation_time & 0xFFFFFFFF);
                    ftCreate.dwHighDateTime = static_cast<DWORD>(entry.creation_time >> 32);

                    FILETIME ftWrite{};
                    ftWrite.dwLowDateTime = static_cast<DWORD>(entry.last_write_time & 0xFFFFFFFF);
                    ftWrite.dwHighDateTime = static_cast<DWORD>(entry.last_write_time >> 32);

                    if (SetFileTime(hFile.get(), &ftCreate, nullptr, &ftWrite)) {
                        report.timestamps_restored++;
                    }
                }
            }

            // Restore SDDL security descriptor
            if (!entry.sddl.empty()) {
                if (apply_path_sddl(entry.original_path, entry.sddl)) {
                    report.acls_restored++;
                }
            }

            // Restore attributes
            if (entry.attributes != 0 && entry.attributes != INVALID_FILE_ATTRIBUTES) {
                SetFileAttributesW(ext_dst.c_str(), entry.attributes);
            }
        } else {
            DWORD err = GetLastError();
            AuditJournal::log_after(L"file_restore", entry.original_path, false, err);
            report.warnings.push_back(L"Failed to restore file to original path: " + entry.original_path);
        }
    }

    // Restore registry keys from registry_manifest.json
    const std::wstring reg_manifest_file = session_dir + L"\\registry_manifest.json";
    if (fs::exists(reg_manifest_file, ec)) {
        std::wifstream rin(reg_manifest_file);
        if (rin.is_open()) {
            std::wstringstream ss;
            ss << rin.rdbuf();
            std::wstring content = ss.str();

            size_t curr = 0;
            while ((curr = content.find(L'{', curr)) != std::wstring::npos) {
                size_t close_brace = content.find(L'}', curr);
                if (close_brace == std::wstring::npos) {
                    break;
                }

                std::wstring item = content.substr(curr, close_brace - curr + 1);
                std::wstring root_name = extract_json_field(item, L"root");
                std::wstring subkey = extract_json_field(item, L"subkey");
                std::wstring hive_rel = extract_json_field(item, L"hive_file");

                HKEY root_key = (root_name == L"HKLM") ? HKEY_LOCAL_MACHINE :
                                (root_name == L"HKCU") ? HKEY_CURRENT_USER : HKEY_CLASSES_ROOT;

                if (!hive_rel.empty()) {
                    std::wstring hive_path = session_dir + L"\\registry\\" + hive_rel;
                    if (fs::exists(hive_path, ec)) {
                        UniqueHKey key;
                        if (RegCreateKeyExW(root_key, subkey.c_str(), 0, nullptr,
                                            REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS,
                                            nullptr, key.put(), nullptr) == ERROR_SUCCESS) {
                            if (RegRestoreKeyW(key.get(), hive_path.c_str(), 0) == ERROR_SUCCESS) {
                                report.registry_keys_restored++;
                                AuditJournal::log_after(L"registry_restore", subkey, true);
                            }
                        }
                    }
                }

                curr = close_brace + 1;
            }
        }
    }

    report.success = (report.files_restored > 0 || manifest.empty());
    Logger::info(L"Restored " + std::to_wstring(report.files_restored) +
                 L" files and " + std::to_wstring(report.registry_keys_restored) +
                 L" registry keys from session: " + session_id);

    return report;
}

Result<void> QuarantineManager::purge_session(const std::wstring& session_id) {
    const std::wstring session_dir = find_session_dir(session_id);
    std::error_code ec;
    if (session_dir.empty() || !fs::exists(session_dir, ec)) {
        return Win32Error::from_code(ERROR_FILE_NOT_FOUND);
    }

    AuditJournal::log_before(L"quarantine_purge", session_dir);

    PhysicalWipeReport rep;
    auto res = FileWiper::wipe_physical_tree(session_dir, rep);
    if (!res || fs::exists(session_dir, ec)) {
        AuditJournal::log_after(L"quarantine_purge", session_dir, false, GetLastError());
        return Win32Error::from_code(ERROR_CAN_NOT_COMPLETE);
    }

    AuditJournal::log_after(L"quarantine_purge", session_dir, true);
    Logger::info(L"Purged quarantine session: " + session_id);
    return Result<void>::success();
}

Result<size_t> QuarantineManager::purge_older_than(uint32_t days) {
    const auto roots = get_all_quarantine_roots();
    std::error_code ec;

    const auto now = fs::file_time_type::clock::now();
    const auto cutoff = now - std::chrono::hours(24 * days);
    size_t purged_count = 0;

    for (const auto& base_dir : roots) {
        if (!fs::exists(base_dir, ec)) {
            continue;
        }

        for (const auto& entry : fs::directory_iterator(base_dir, ec)) {
            if (entry.is_directory(ec)) {
                auto lwt = entry.last_write_time(ec);
                if (!ec && lwt < cutoff) {
                    std::wstring sid = entry.path().filename().wstring();
                    if (purge_session(sid)) {
                        purged_count++;
                    }
                }
            }
        }
    }

    Logger::info(L"Purged " + std::to_wstring(purged_count) + L" quarantine sessions older than " +
                 std::to_wstring(days) + L" days");
    return purged_count;
}

} // namespace obliterator
