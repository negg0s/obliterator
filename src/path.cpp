#include "obliterator/path.hpp"
#include "obliterator/handles.hpp"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include <algorithm>
#include <cwctype>
#include <vector>

namespace obliterator {

std::wstring PathHelper::to_lower_unicode(std::wstring_view input) {
    std::wstring result(input);
    if (!result.empty()) {
        CharLowerBuffW(result.data(), static_cast<DWORD>(result.size()));
    }
    return result;
}

std::wstring PathHelper::normalize(std::wstring_view path) {
    if (path.empty()) {
        return {};
    }

    std::wstring input(path);
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

    if (full.starts_with(L"\\\\?\\UNC\\")) {
        full = L"\\\\" + full.substr(8);
    } else if (full.starts_with(L"\\\\?\\") || full.starts_with(L"\\??\\")) {
        full.erase(0, 4);
    }

    if (full.size() >= 2 && full[1] == L':' && full[0] >= L'a' && full[0] <= L'z') {
        full[0] = static_cast<wchar_t>(full[0] - L'a' + L'A');
    }

    while (full.size() > 3 && full.back() == L'\\') {
        full.pop_back();
    }

    if (full.size() == 2 && full[1] == L':') {
        full.push_back(L'\\');
    }

    return full;
}

static std::wstring query_final_path(const std::wstring& norm) {
    UniqueHandle h(CreateFileW(
        norm.c_str(),
        FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS,
        nullptr
    ));
    if (!h) {
        return {};
    }

    std::wstring buf(MAX_PATH, L'\0');
    DWORD len = GetFinalPathNameByHandleW(h.get(), buf.data(), static_cast<DWORD>(buf.size()), FILE_NAME_NORMALIZED);
    if (len >= buf.size()) {
        buf.resize(static_cast<size_t>(len) + 1);
        len = GetFinalPathNameByHandleW(h.get(), buf.data(), static_cast<DWORD>(buf.size()), FILE_NAME_NORMALIZED);
    }
    if (len == 0 || len >= buf.size()) {
        return {};
    }
    buf.resize(len);

    if (buf.starts_with(L"\\\\?\\UNC\\")) {
        buf = L"\\\\" + buf.substr(8);
    } else if (buf.starts_with(L"\\\\?\\") || buf.starts_with(L"\\??\\")) {
        buf.erase(0, 4);
    }
    return PathHelper::normalize(buf);
}

std::wstring PathHelper::canonicalize(std::wstring_view path) {
    const std::wstring norm = normalize(path);
    if (norm.empty()) {
        return {};
    }

    // Try resolving symlinks and normalized casing directly via file handle
    std::wstring final_path = query_final_path(norm);
    if (!final_path.empty()) {
        return final_path;
    }

    // If path does not exist on disk, attempt GetLongPathNameW
    std::wstring long_buf(MAX_PATH, L'\0');
    DWORD long_len = GetLongPathNameW(norm.c_str(), long_buf.data(), static_cast<DWORD>(long_buf.size()));
    if (long_len >= long_buf.size()) {
        long_buf.resize(static_cast<size_t>(long_len) + 1);
        long_len = GetLongPathNameW(norm.c_str(), long_buf.data(), static_cast<DWORD>(long_buf.size()));
    }
    if (long_len > 0 && long_len < long_buf.size()) {
        long_buf.resize(long_len);
        return normalize(long_buf);
    }

    // For uncreated paths, find existing ancestor and canonicalize it
    size_t last_slash = norm.rfind(L'\\');
    if (last_slash != std::wstring::npos && last_slash > 2) {
        std::wstring parent = norm.substr(0, last_slash);
        std::wstring rest = norm.substr(last_slash);
        std::wstring canon_parent = canonicalize(parent);
        if (!canon_parent.empty()) {
            return normalize(canon_parent + rest);
        }
    }

    return norm;
}

std::vector<std::wstring> PathHelper::split_components(std::wstring_view path) {
    std::vector<std::wstring> components;
    size_t start = 0;
    while (start < path.size()) {
        while (start < path.size() && (path[start] == L'\\' || path[start] == L'/')) {
            start++;
        }
        if (start >= path.size()) {
            break;
        }
        size_t end = path.find_first_of(L"\\/", start);
        if (end == std::wstring_view::npos) {
            end = path.size();
        }
        components.emplace_back(path.substr(start, end - start));
        start = end;
    }
    return components;
}

static bool compare_component(std::wstring_view a, std::wstring_view b) noexcept {
    return CompareStringOrdinal(a.data(), static_cast<int>(a.size()),
                                b.data(), static_cast<int>(b.size()),
                                TRUE) == CSTR_EQUAL;
}

bool PathHelper::is_same_or_subpath(std::wstring_view parent_root, std::wstring_view candidate) {
    if (parent_root.empty() || candidate.empty()) {
        return false;
    }

    const std::wstring canon_parent = canonicalize(parent_root);
    const std::wstring canon_cand = canonicalize(candidate);

    if (canon_parent.empty() || canon_cand.empty()) {
        return false;
    }

    const auto p_comps = split_components(canon_parent);
    const auto c_comps = split_components(canon_cand);

    if (p_comps.empty() || p_comps.size() > c_comps.size()) {
        return false;
    }

    for (size_t i = 0; i < p_comps.size(); ++i) {
        if (!compare_component(p_comps[i], c_comps[i])) {
            return false;
        }
    }

    return true;
}

static bool is_path_boundary_char(wchar_t c) noexcept {
    return c == L'\"' || c == L'\'' || c == L' ' || c == L'\t' ||
           c == L',' || c == L';' || c == L'=' || c == L'\0' || c == L'\r' || c == L'\n';
}

static bool check_match_at_pos(std::wstring_view text, size_t pos, size_t target_len) {
    if (pos > 0) {
        const wchar_t prev = text[pos - 1];
        if (!is_path_boundary_char(prev)) {
            return false;
        }
    }

    const size_t end_pos = pos + target_len;
    if (end_pos == text.size()) {
        return true;
    }

    const wchar_t next = text[end_pos];
    if (next == L'\\' || next == L'/' || is_path_boundary_char(next)) {
        return true;
    }

    return false;
}

bool PathHelper::contains_path_reference(std::wstring_view text, std::wstring_view parent_root) {
    if (text.empty() || parent_root.empty()) {
        return false;
    }

    const std::wstring lower_text = to_lower_unicode(text);
    const std::wstring canon_parent = canonicalize(parent_root);
    const std::wstring lower_canon = to_lower_unicode(canon_parent);

    // Search for canonical long path occurrences
    size_t pos = lower_text.find(lower_canon);
    while (pos != std::wstring::npos) {
        if (check_match_at_pos(lower_text, pos, lower_canon.size())) {
            return true;
        }
        pos = lower_text.find(lower_canon, pos + 1);
    }

    // Also search normalized raw path if different
    const std::wstring norm_parent = normalize(parent_root);
    const std::wstring lower_norm = to_lower_unicode(norm_parent);
    if (lower_norm != lower_canon) {
        pos = lower_text.find(lower_norm);
        while (pos != std::wstring::npos) {
            if (check_match_at_pos(lower_text, pos, lower_norm.size())) {
                return true;
            }
            pos = lower_text.find(lower_norm, pos + 1);
        }
    }

    // Check 8.3 short path if available
    wchar_t short_buf[MAX_PATH]{};
    DWORD short_len = GetShortPathNameW(canon_parent.c_str(), short_buf, MAX_PATH);
    if (short_len > 0 && short_len < MAX_PATH) {
        const std::wstring lower_short = to_lower_unicode(short_buf);
        if (lower_short != lower_canon && lower_short != lower_norm) {
            pos = lower_text.find(lower_short);
            while (pos != std::wstring::npos) {
                if (check_match_at_pos(lower_text, pos, lower_short.size())) {
                    return true;
                }
                pos = lower_text.find(lower_short, pos + 1);
            }
        }
    }

    return false;
}

} // namespace obliterator
