#include "obliterator/pending_rename.hpp"
#include "obliterator/handles.hpp"
#include "obliterator/log.hpp"
#include "obliterator/path.hpp"

#include <algorithm>
#include <cwctype>

namespace obliterator {

static constexpr const wchar_t* kSessionManagerKey =
    L"SYSTEM\\CurrentControlSet\\Control\\Session Manager";
static constexpr const wchar_t* kValueName = L"PendingFileRenameOperations";

std::wstring PendingRenameManager::to_nt_path(const std::wstring& path) {
    if (path.empty()) {
        return {};
    }

    if (path.starts_with(L"\\??\\")) {
        return path;
    }

    if (path.starts_with(L"\\\\?\\UNC\\")) {
        return L"\\??\\UNC\\" + path.substr(8);
    }

    if (path.starts_with(L"\\\\?\\")) {
        return L"\\??\\" + path.substr(4);
    }

    if (path.starts_with(L"\\\\")) {
        return L"\\??\\UNC\\" + path.substr(2);
    }

    return L"\\??\\" + path;
}

std::vector<PendingRenameEntry> PendingRenameManager::parse_multi_sz(const wchar_t* buffer,
                                                                   size_t wchar_count) {
    std::vector<PendingRenameEntry> entries;
    if (buffer == nullptr || wchar_count == 0) {
        return entries;
    }

    std::vector<std::wstring> raw_strings;
    size_t start = 0;
    for (size_t i = 0; i < wchar_count; ++i) {
        if (buffer[i] == L'\0') {
            if (i == start) {
                // Consecutive null terminator marks end of multi_sz or empty string
                raw_strings.emplace_back();
            } else {
                raw_strings.emplace_back(buffer + start, i - start);
            }
            start = i + 1;
        }
    }

    // While last string is empty and not part of an odd-length pair, pop trailing terminator
    while (raw_strings.size() > 1 && raw_strings.back().empty() && (raw_strings.size() % 2 != 0)) {
        raw_strings.pop_back();
    }

    for (size_t i = 0; i + 1 < raw_strings.size(); i += 2) {
        entries.push_back({raw_strings[i], raw_strings[i + 1]});
    }

    return entries;
}

std::vector<wchar_t> PendingRenameManager::serialize_multi_sz(
    const std::vector<PendingRenameEntry>& entries) {
    std::vector<wchar_t> buffer;
    for (const auto& entry : entries) {
        buffer.insert(buffer.end(), entry.source_nt_path.begin(), entry.source_nt_path.end());
        buffer.push_back(L'\0');

        buffer.insert(buffer.end(), entry.destination_nt_path.begin(), entry.destination_nt_path.end());
        buffer.push_back(L'\0');
    }

    // Multi-SZ requires an additional final null terminator
    buffer.push_back(L'\0');
    return buffer;
}

std::vector<PendingRenameEntry> PendingRenameManager::read_entries() {
    UniqueHKey key;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, kSessionManagerKey, 0, KEY_QUERY_VALUE, key.put()) != ERROR_SUCCESS) {
        return {};
    }

    DWORD type = 0;
    DWORD bytes = 0;
    if (RegQueryValueExW(key.get(), kValueName, nullptr, &type, nullptr, &bytes) != ERROR_SUCCESS ||
        type != REG_MULTI_SZ || bytes < sizeof(wchar_t)) {
        return {};
    }

    std::vector<wchar_t> buffer(bytes / sizeof(wchar_t));
    if (RegQueryValueExW(key.get(), kValueName, nullptr, &type,
                         reinterpret_cast<LPBYTE>(buffer.data()), &bytes) != ERROR_SUCCESS) {
        return {};
    }

    return parse_multi_sz(buffer.data(), buffer.size());
}

bool PendingRenameManager::schedule_deletions(const std::vector<std::wstring>& file_or_dir_paths) {
    if (file_or_dir_paths.empty()) {
        return true;
    }

    UniqueHKey key;
    LSTATUS st = RegCreateKeyExW(HKEY_LOCAL_MACHINE, kSessionManagerKey, 0, nullptr,
                                 REG_OPTION_NON_VOLATILE, KEY_QUERY_VALUE | KEY_SET_VALUE,
                                 nullptr, key.put(), nullptr);
    if (st != ERROR_SUCCESS) {
        Logger::warn(L"Could not open Session Manager key to schedule pending renames: " +
                     std::to_wstring(st));
        return false;
    }

    auto entries = read_entries();

    for (const auto& raw_path : file_or_dir_paths) {
        std::wstring nt_src = to_nt_path(raw_path);
        std::wstring nt_src_lower = PathHelper::to_lower_unicode(nt_src);

        bool already_scheduled = false;
        for (const auto& existing : entries) {
            if (PathHelper::to_lower_unicode(existing.source_nt_path) == nt_src_lower &&
                existing.destination_nt_path.empty()) {
                already_scheduled = true;
                break;
            }
        }

        if (!already_scheduled) {
            entries.push_back({nt_src, L""});
            Logger::debug(L"Scheduled reboot deletion in PendingFileRenameOperations: " + nt_src);
        }
    }

    const auto buffer = serialize_multi_sz(entries);
    st = RegSetValueExW(key.get(), kValueName, 0, REG_MULTI_SZ,
                        reinterpret_cast<const BYTE*>(buffer.data()),
                        static_cast<DWORD>(buffer.size() * sizeof(wchar_t)));

    if (st != ERROR_SUCCESS) {
        Logger::warn(L"Failed to write PendingFileRenameOperations: " + std::to_wstring(st));
        return false;
    }

    return true;
}

bool PendingRenameManager::schedule_deletion(const std::wstring& file_or_dir_path) {
    return schedule_deletions({file_or_dir_path});
}

} // namespace obliterator
