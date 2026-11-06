#include "obliterator/terminal_cleaner.hpp"

#include "obliterator/path.hpp"
#include "obliterator/safety.hpp"

#include <algorithm>
#include <cwctype>
#include <filesystem>
#include <fstream>
#include <vector>

namespace obliterator {

static bool string_contains_ignore_case(std::wstring_view text, std::wstring_view needle) {
    if (needle.empty() || text.empty()) {
        return false;
    }
    const std::wstring t_lower = PathHelper::to_lower_unicode(text);
    const std::wstring n_lower = PathHelper::to_lower_unicode(needle);
    return t_lower.find(n_lower) != std::wstring::npos;
}

bool TerminalCleaner::matches_target(const std::wstring& name, const Target& target) {
    if (name.empty()) {
        return false;
    }

    if (!target.name.empty() && target.name.length() >= 3) {
        if (string_contains_ignore_case(name, target.name)) {
            return true;
        }
        if (name.length() >= 4 && string_contains_ignore_case(target.name, name)) {
            return true;
        }
    }

    if (!target.root_path.empty()) {
        const std::wstring norm_root = SafetyValidator::normalize_path(target.root_path);
        const auto last_slash = norm_root.find_last_of(L"\\/");
        if (last_slash != std::wstring::npos && last_slash + 1 < norm_root.length()) {
            const std::wstring folder = norm_root.substr(last_slash + 1);
            if (folder.length() >= 3 && string_contains_ignore_case(name, folder)) {
                return true;
            }
        }
    }

    return false;
}

bool TerminalCleaner::path_references_target(const std::wstring& path, const Target& target) {
    if (path.empty()) {
        return false;
    }

    if (!target.root_path.empty()) {
        if (PathHelper::contains_path_reference(path, target.root_path)) {
            return true;
        }
        const std::wstring norm_path = SafetyValidator::normalize_path(path);
        if (PathHelper::is_same_or_subpath(target.root_path, norm_path)) {
            return true;
        }
    }

    if (!target.name.empty() && target.name.length() >= 3) {
        if (string_contains_ignore_case(path, target.name)) {
            return true;
        }
    }

    return false;
}

bool TerminalCleaner::file_references_target(const std::wstring& file_path, const Target& target) {
    std::ifstream file(file_path, std::ios::binary);
    if (!file.is_open()) {
        return false;
    }

    std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    file.close();

    if (content.empty()) {
        return false;
    }

    std::wstring wide_content;
    wide_content.resize(content.size());
    for (size_t i = 0; i < content.size(); ++i) {
        wide_content[i] = static_cast<wchar_t>(static_cast<unsigned char>(content[i]));
    }

    if (path_references_target(wide_content, target)) {
        return true;
    }

    return false;
}

TerminalCleanReport TerminalCleaner::clean_terminal_fragments(const Target& target, bool dry_run) {
    TerminalCleanReport report;
    namespace fs = std::filesystem;

    std::vector<fs::path> search_dirs;

    wchar_t local_app_data[MAX_PATH] = { 0 };
    if (GetEnvironmentVariableW(L"LOCALAPPDATA", local_app_data, MAX_PATH) > 0) {
        search_dirs.push_back(fs::path(local_app_data) / L"Microsoft" / L"Windows Terminal" / L"Fragments");
    }

    wchar_t program_data[MAX_PATH] = { 0 };
    if (GetEnvironmentVariableW(L"ProgramData", program_data, MAX_PATH) > 0) {
        search_dirs.push_back(fs::path(program_data) / L"Microsoft" / L"Windows Terminal" / L"Fragments");
    }

    for (const auto& base_dir : search_dirs) {
        std::error_code ec;
        if (!fs::exists(base_dir, ec) || !fs::is_directory(base_dir, ec)) {
            continue;
        }

        for (const auto& entry : fs::directory_iterator(base_dir, ec)) {
            if (ec) {
                break;
            }

            if (!entry.is_directory(ec)) {
                continue;
            }

            const std::wstring folder_name = entry.path().filename().wstring();
            bool matched = matches_target(folder_name, target);

            if (!matched) {
                // Inspect files inside for path references
                for (const auto& sub_entry : fs::directory_iterator(entry.path(), ec)) {
                    if (ec) {
                        break;
                    }
                    if (sub_entry.is_regular_file(ec)) {
                        if (file_references_target(sub_entry.path().wstring(), target)) {
                            matched = true;
                            break;
                        }
                    }
                }
            }

            if (matched) {
                if (!dry_run) {
                    fs::remove_all(entry.path(), ec);
                }
                ++report.fragment_folders_removed;
                report.details.push_back(L"Windows Terminal Fragment: " + folder_name);
            }
        }
    }

    return report;
}

} // namespace obliterator
