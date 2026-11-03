#include "obliterator/portable.hpp"
#include "obliterator/handles.hpp"
#include "obliterator/path.hpp"
#include "obliterator/safety.hpp"
#include "obliterator/ui.hpp"
#include "obliterator/wiper.hpp"

#include <algorithm>
#include <cwctype>
#include <filesystem>
#include <iomanip>
#include <iostream>
#include <vector>

namespace fs = std::filesystem;

namespace obliterator {

static std::wstring to_lower(std::wstring_view sv) {
    std::wstring s(sv);
    std::transform(s.begin(), s.end(), s.begin(), [](wchar_t c) {
        return static_cast<wchar_t>(std::towlower(c));
    });
    return s;
}

std::vector<PortableAppCandidate> PortableScanner::scan(const std::wstring& root_folder) {
    std::vector<PortableAppCandidate> candidates;

    const std::wstring norm_root = SafetyValidator::normalize_path(root_folder);
    if (norm_root.empty() || !SafetyValidator::validate_path(norm_root)) {
        return candidates;
    }

    std::error_code ec;
    fs::path root_fs(norm_root);
    if (!fs::exists(root_fs, ec) || !fs::is_directory(root_fs, ec)) {
        return candidates;
    }

    // 1. Gather all installed program directories from registry and UWP
    const auto installed_apps = UserInterface::enumerate_installed_apps();
    std::vector<std::wstring> known_installed_roots;
    known_installed_roots.reserve(installed_apps.size());
    for (const auto& app : installed_apps) {
        if (!app.root_path.empty()) {
            known_installed_roots.push_back(app.root_path);
        }
    }

    auto is_registered_app = [&](const std::wstring& dir_path) -> bool {
        for (const auto& installed : known_installed_roots) {
            if (PathHelper::is_same_or_subpath(installed, dir_path) ||
                PathHelper::is_same_or_subpath(dir_path, installed)) {
                return true;
            }
        }
        return false;
    };

    std::vector<fs::path> subdirs;
    for (const auto& entry : fs::directory_iterator(root_fs, fs::directory_options::skip_permission_denied, ec)) {
        if (entry.is_directory(ec)) {
            subdirs.push_back(entry.path());
        }
    }

    // Also consider the root folder itself if it contains an executable
    subdirs.push_back(root_fs);

    for (const auto& dir : subdirs) {
        const std::wstring dir_str = dir.wstring();
        if (is_registered_app(dir_str)) {
            continue;
        }

        struct ExeFile {
            std::wstring path;
            std::wstring name;
            uint64_t size{0};
            bool in_root{false};
        };

        std::vector<ExeFile> exe_files;
        uint64_t total_size = 0;
        size_t total_files = 0;

        for (const auto& file_entry : fs::recursive_directory_iterator(dir, fs::directory_options::skip_permission_denied, ec)) {
            if (ec) break;
            if (file_entry.is_regular_file(ec)) {
                total_files++;
                auto file_sz = file_entry.file_size(ec);
                if (!ec) {
                    total_size += file_sz;
                }

                auto ext = to_lower(file_entry.path().extension().wstring());
                if (ext == L".exe") {
                    bool in_root = (file_entry.path().parent_path() == dir);
                    exe_files.push_back({
                        file_entry.path().wstring(),
                        file_entry.path().filename().wstring(),
                        file_sz,
                        in_root
                    });
                }
            }
        }

        if (exe_files.empty()) {
            continue;
        }

        // Determine most suitable main executable
        std::wstring dir_name = dir.filename().wstring();
        std::wstring lower_dir_name = to_lower(dir_name);

        ExeFile best_exe = exe_files[0];
        bool found_named_match = false;

        for (const auto& exe : exe_files) {
            std::wstring stem = to_lower(fs::path(exe.name).stem().wstring());
            if (stem == lower_dir_name) {
                best_exe = exe;
                found_named_match = true;
                break;
            }
        }

        if (!found_named_match) {
            // Prefer root-level exe with largest size
            for (const auto& exe : exe_files) {
                if (exe.in_root && (!best_exe.in_root || exe.size > best_exe.size)) {
                    best_exe = exe;
                }
            }
        }

        std::wstring last_mod = L"----";
        WIN32_FILE_ATTRIBUTE_DATA fad{};
        if (GetFileAttributesExW(dir_str.c_str(), GetFileExInfoStandard, &fad)) {
            SYSTEMTIME st{};
            if (FileTimeToSystemTime(&fad.ftLastWriteTime, &st)) {
                wchar_t buf[32];
                swprintf_s(buf, L"%04u-%02u-%02u", st.wYear, st.wMonth, st.wDay);
                last_mod = buf;
            }
        }

        candidates.push_back({
            dir_str,
            dir_name,
            best_exe.name,
            best_exe.path,
            total_size,
            total_files,
            last_mod
        });
    }

    std::sort(candidates.begin(), candidates.end(), [](const PortableAppCandidate& a, const PortableAppCandidate& b) {
        if (a.size_bytes != b.size_bytes) {
            return a.size_bytes > b.size_bytes;
        }
        return a.name < b.name;
    });

    return candidates;
}

void PortableScanner::print_report(const std::vector<PortableAppCandidate>& candidates, bool json_mode) {
    if (json_mode) {
        std::wcout << L"{\n  \"portable_candidates\": [\n";
        for (size_t i = 0; i < candidates.size(); ++i) {
            const auto& c = candidates[i];
            std::wcout << L"    {\n"
                       << L"      \"name\": \"" << c.name << L"\",\n"
                       << L"      \"main_executable\": \"" << c.main_exe_name << L"\",\n"
                       << L"      \"executable_path\": \"" << c.main_exe_path << L"\",\n"
                       << L"      \"folder_path\": \"" << c.folder_path << L"\",\n"
                       << L"      \"size_bytes\": " << c.size_bytes << L",\n"
                       << L"      \"file_count\": " << c.file_count << L",\n"
                       << L"      \"last_modified\": \"" << c.last_modified << L"\"\n"
                       << L"    }" << (i + 1 < candidates.size() ? L"," : L"") << L"\n";
        }
        std::wcout << L"  ]\n}\n";
        return;
    }

    if (candidates.empty()) {
        std::wcout << L"No unregistered portable applications discovered in the specified location.\n";
        return;
    }

    std::wcout << L"\nDiscovered Portable Application Candidates:\n";
    std::wcout << L"---------------------------------------------------------------------------------------------------------\n";
    std::wcout << std::left << std::setw(28) << L"Name"
               << std::setw(24) << L"Main Executable"
               << std::setw(10) << L"Files"
               << std::setw(14) << L"Size"
               << L"Path\n";
    std::wcout << L"---------------------------------------------------------------------------------------------------------\n";

    for (const auto& c : candidates) {
        std::wstring disp_name = c.name;
        if (disp_name.size() > 26) {
            disp_name = disp_name.substr(0, 23) + L"...";
        }
        std::wstring disp_exe = c.main_exe_name;
        if (disp_exe.size() > 22) {
            disp_exe = disp_exe.substr(0, 19) + L"...";
        }

        std::wcout << std::left << std::setw(28) << disp_name
                   << std::setw(24) << disp_exe
                   << std::setw(10) << c.file_count
                   << std::setw(14) << FileWiper::format_bytes(c.size_bytes)
                   << c.folder_path << L"\n";
    }
    std::wcout << L"---------------------------------------------------------------------------------------------------------\n";
    std::wcout << L"Total candidates found: " << candidates.size() << L"\n\n";
}

} // namespace obliterator
