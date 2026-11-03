#include "obliterator/safety.hpp"
#include "obliterator/log.hpp"
#include "obliterator/path.hpp"

#include <algorithm>
#include <cwctype>
#include <filesystem>
#include <vector>

namespace obliterator {

static std::wstring query_environment(const wchar_t* name) {
    const DWORD needed = GetEnvironmentVariableW(name, nullptr, 0);
    if (needed == 0) {
        return {};
    }
    std::wstring value(static_cast<size_t>(needed), L'\0');
    const DWORD written = GetEnvironmentVariableW(name, value.data(), needed);
    if (written == 0 || written >= needed) {
        return {};
    }
    value.resize(written);
    return value;
}

static std::wstring get_current_executable_directory() {
    std::wstring buffer(MAX_PATH, L'\0');
    DWORD len = GetModuleFileNameW(nullptr, buffer.data(), static_cast<DWORD>(buffer.size()));
    if (len >= buffer.size()) {
        buffer.resize(32768);
        len = GetModuleFileNameW(nullptr, buffer.data(), static_cast<DWORD>(buffer.size()));
    }
    if (len == 0) {
        return {};
    }
    buffer.resize(len);

    std::filesystem::path p(buffer);
    return p.parent_path().wstring();
}

std::wstring SafetyValidator::normalize_path(const std::wstring& raw_path) {
    if (raw_path.empty()) {
        return {};
    }

    std::wstring input = raw_path;
    // Treat raw drive specifiers like "C:" as drive roots ("C:\") to prevent
    // resolving to the process's hidden per-drive working directory.
    if (input.size() == 2 && std::iswalpha(input[0]) && input[1] == L':') {
        input.push_back(L'\\');
    }

    const DWORD expanded_len = ExpandEnvironmentStringsW(input.c_str(), nullptr, 0);
    if (expanded_len == 0) {
        return {};
    }
    std::wstring expanded(static_cast<size_t>(expanded_len), L'\0');
    ExpandEnvironmentStringsW(input.c_str(), expanded.data(), expanded_len);
    expanded.resize(expanded_len - 1);

    const DWORD full_len = GetFullPathNameW(expanded.c_str(), 0, nullptr, nullptr);
    if (full_len == 0) {
        return {};
    }
    std::wstring full(static_cast<size_t>(full_len), L'\0');
    GetFullPathNameW(expanded.c_str(), full_len, full.data(), nullptr);
    full.resize(full_len - 1);

    std::replace(full.begin(), full.end(), L'/', L'\\');

    // Canonicalize drive letter to uppercase
    if (full.size() >= 2 && full[1] == L':' && full[0] >= L'a' && full[0] <= L'z') {
        full[0] = static_cast<wchar_t>(full[0] - L'a' + L'A');
    }

    // Strip extended length prefix for uniform comparison.
    if (full.starts_with(L"\\\\?\\")) {
        full.erase(0, 4);
    }

    while (full.size() > 3 && full.back() == L'\\') {
        full.pop_back();
    }

    if (full.size() == 2 && full[1] == L':') {
        full.push_back(L'\\');
    }

    return full;
}

bool SafetyValidator::is_drive_root(const std::wstring& normalized_path) {
    if (normalized_path.size() == 3 &&
        std::iswalpha(normalized_path[0]) &&
        normalized_path[1] == L':' &&
        normalized_path[2] == L'\\') {
        return true;
    }
    if (normalized_path.size() == 2 &&
        std::iswalpha(normalized_path[0]) &&
        normalized_path[1] == L':') {
        return true;
    }
    return false;
}

std::vector<ProtectedPath> SafetyValidator::get_protected_paths() {
    std::vector<ProtectedPath> list;

    wchar_t win_dir[MAX_PATH]{};
    if (GetWindowsDirectoryW(win_dir, MAX_PATH) > 0) {
        list.push_back({normalize_path(win_dir), L"Windows directory"});
    }

    wchar_t sys_dir[MAX_PATH]{};
    if (GetSystemDirectoryW(sys_dir, MAX_PATH) > 0) {
        list.push_back({normalize_path(sys_dir), L"System32 directory"});
    }

    const std::wstring user_profile = query_environment(L"USERPROFILE");
    if (!user_profile.empty()) {
        const std::wstring norm_profile = normalize_path(user_profile);
        list.push_back({norm_profile, L"User profile directory"});

        std::filesystem::path p(norm_profile);
        if (p.has_parent_path()) {
            list.push_back({normalize_path(p.parent_path().wstring()), L"Users directory"});
        }
    }

    const std::wstring prog_files = query_environment(L"ProgramFiles");
    if (!prog_files.empty()) {
        list.push_back({normalize_path(prog_files), L"Program Files directory"});
    }

    const std::wstring prog_files_x86 = query_environment(L"ProgramFiles(x86)");
    if (!prog_files_x86.empty()) {
        list.push_back({normalize_path(prog_files_x86), L"Program Files (x86) directory"});
    }

    const std::wstring prog_data = query_environment(L"ProgramData");
    if (!prog_data.empty()) {
        list.push_back({normalize_path(prog_data), L"ProgramData directory"});
    }

    const std::wstring exe_dir = get_current_executable_directory();
    if (!exe_dir.empty()) {
        list.push_back({normalize_path(exe_dir), L"Obliterator self directory"});
    }

    return list;
}

Result<void> SafetyValidator::validate_path(const std::wstring& raw_path) {
    const std::wstring normalized = normalize_path(raw_path);
    if (normalized.empty()) {
        return Win32Error::from_code(ERROR_PATH_NOT_FOUND);
    }

    if (is_drive_root(normalized)) {
        Logger::error(L"Safety check failed: cannot wipe drive root: " + normalized);
        return Win32Error::from_code(ERROR_ACCESS_DENIED);
    }

    const auto protected_list = get_protected_paths();

    for (const auto& item : protected_list) {
        if (item.path.empty()) {
            continue;
        }

        // Direct exact match
        if (PathHelper::is_same_or_subpath(item.path, normalized) &&
            PathHelper::is_same_or_subpath(normalized, item.path)) {
            Logger::error(L"Safety check failed: target matches protected " +
                          item.description + L": " + normalized);
            return Win32Error::from_code(ERROR_ACCESS_DENIED);
        }

        // Target is an ancestor of a protected path (e.g. C:\ containing C:\Windows)
        if (PathHelper::is_same_or_subpath(normalized, item.path)) {
            Logger::error(L"Safety check failed: target is parent of protected " +
                          item.description + L": " + normalized);
            return Win32Error::from_code(ERROR_ACCESS_DENIED);
        }

        // Target is inside the Windows directory (system files)
        if (item.description == L"Windows directory") {
            if (PathHelper::is_same_or_subpath(item.path, normalized)) {
                Logger::error(L"Safety check failed: target is inside Windows directory: " +
                              normalized);
                return Win32Error::from_code(ERROR_ACCESS_DENIED);
            }
        }

        // Target is obliterator's directory or contains obliterator
        if (item.description == L"Obliterator self directory") {
            if (PathHelper::is_same_or_subpath(item.path, normalized)) {
                Logger::error(L"Safety check failed: target contains obliterator binary: " +
                              normalized);
                return Win32Error::from_code(ERROR_ACCESS_DENIED);
            }
        }
    }

    return Result<void>::success();
}

} // namespace obliterator
