#include "obliterator/resume.hpp"
#include "obliterator/handles.hpp"
#include "obliterator/log.hpp"
#include "obliterator/path.hpp"
#include "obliterator/service.hpp"
#include "obliterator/wiper.hpp"

#include <chrono>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <vector>

namespace obliterator {

static constexpr const wchar_t* kRunOnceKey =
    L"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce";
static constexpr const wchar_t* kRunOnceValue = L"ObliteratorResume";

std::wstring ResumeManager::get_resume_directory() {
    wchar_t buf[MAX_PATH]{};
    if (GetEnvironmentVariableW(L"ProgramData", buf, MAX_PATH) > 0) {
        return std::wstring(buf) + L"\\obliterator";
    }
    return L"C:\\ProgramData\\obliterator";
}

std::wstring ResumeManager::get_resume_file_path() {
    return get_resume_directory() + L"\\resume.json";
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

bool ResumeManager::save_resume_state(const ResumeState& state) {
    namespace fs = std::filesystem;
    const std::wstring dir = get_resume_directory();
    std::error_code ec;
    fs::create_directories(dir, ec);

    const std::wstring file_path = get_resume_file_path();
    std::wofstream out(file_path);
    if (!out.is_open()) {
        Logger::warn(L"Could not open resume state file for writing: " + file_path);
        return false;
    }

    out << L"{\n";
    out << L"  \"target_name\": \"" << escape_json(state.target_name) << L"\",\n";
    out << L"  \"target_root\": \"" << escape_json(state.target_root) << L"\",\n";
    out << L"  \"aggressive\": " << (state.aggressive ? L"true" : L"false") << L",\n";
    out << L"  \"created_at\": \"" << escape_json(state.created_at) << L"\",\n";

    auto write_array = [&](std::wstring_view key, const std::vector<std::wstring>& items, bool trailing_comma) {
        out << L"  \"" << key << L"\": [\n";
        for (size_t i = 0; i < items.size(); ++i) {
            out << L"    \"" << escape_json(items[i]) << L"\"" << (i + 1 < items.size() ? L"," : L"") << L"\n";
        }
        out << L"  ]" << (trailing_comma ? L"," : L"") << L"\n";
    };

    write_array(L"pending_files", state.pending_files, true);
    write_array(L"pending_directories", state.pending_directories, true);
    write_array(L"pending_services", state.pending_services, true);
    write_array(L"pending_drivers", state.pending_drivers, false);

    out << L"}\n";
    out.close();

    register_run_once();
    Logger::info(L"Saved resume state to " + file_path);
    return true;
}

bool ResumeManager::has_resume_state() {
    namespace fs = std::filesystem;
    std::error_code ec;
    return fs::exists(get_resume_file_path(), ec);
}

static std::vector<std::wstring> extract_json_array(const std::wstring& content, std::wstring_view key) {
    std::vector<std::wstring> result;
    const std::wstring search = L"\"" + std::wstring(key) + L"\"";
    size_t pos = content.find(search);
    if (pos == std::wstring::npos) {
        return result;
    }

    size_t open_bracket = content.find(L'[', pos);
    size_t close_bracket = content.find(L']', open_bracket);
    if (open_bracket == std::wstring::npos || close_bracket == std::wstring::npos) {
        return result;
    }

    size_t curr = open_bracket + 1;
    while (curr < close_bracket) {
        size_t first_quote = content.find(L'\"', curr);
        if (first_quote == std::wstring::npos || first_quote >= close_bracket) {
            break;
        }

        std::wstring str;
        size_t i = first_quote + 1;
        while (i < close_bracket) {
            if (content[i] == L'\\') {
                if (i + 1 < close_bracket) {
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
                curr = i + 1;
                break;
            } else {
                str += content[i];
            }
            i++;
        }
        result.push_back(std::move(str));
    }

    return result;
}

static std::wstring extract_json_string(const std::wstring& content, std::wstring_view key) {
    const std::wstring search = L"\"" + std::wstring(key) + L"\"";
    size_t pos = content.find(search);
    if (pos == std::wstring::npos) {
        return {};
    }

    size_t colon = content.find(L':', pos);
    if (colon == std::wstring::npos) {
        return {};
    }

    size_t first_quote = content.find(L'\"', colon);
    if (first_quote == std::wstring::npos) {
        return {};
    }

    std::wstring str;
    size_t i = first_quote + 1;
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

bool ResumeManager::load_resume_state(ResumeState& out_state) {
    const std::wstring file_path = get_resume_file_path();
    std::wifstream in(file_path);
    if (!in.is_open()) {
        return false;
    }

    std::wstringstream ss;
    ss << in.rdbuf();
    std::wstring content = ss.str();

    out_state.target_name = extract_json_string(content, L"target_name");
    out_state.target_root = extract_json_string(content, L"target_root");
    out_state.created_at = extract_json_string(content, L"created_at");

    size_t agg_pos = content.find(L"\"aggressive\"");
    if (agg_pos != std::wstring::npos) {
        size_t val_pos = content.find(L':', agg_pos);
        if (val_pos != std::wstring::npos) {
            std::wstring sub = content.substr(val_pos, 20);
            out_state.aggressive = (sub.find(L"true") != std::wstring::npos);
        }
    }

    out_state.pending_files = extract_json_array(content, L"pending_files");
    out_state.pending_directories = extract_json_array(content, L"pending_directories");
    out_state.pending_services = extract_json_array(content, L"pending_services");
    out_state.pending_drivers = extract_json_array(content, L"pending_drivers");

    return true;
}

bool ResumeManager::register_run_once() {
    wchar_t exe_path[MAX_PATH]{};
    if (GetModuleFileNameW(nullptr, exe_path, MAX_PATH) == 0) {
        return false;
    }

    const std::wstring cmd = L"\"" + std::wstring(exe_path) + L"\" --resume";

    UniqueHKey key;
    LSTATUS st = RegCreateKeyExW(HKEY_LOCAL_MACHINE, kRunOnceKey, 0, nullptr,
                                 REG_OPTION_NON_VOLATILE, KEY_SET_VALUE,
                                 nullptr, key.put(), nullptr);
    if (st == ERROR_SUCCESS) {
        RegSetValueExW(key.get(), kRunOnceValue, 0, REG_SZ,
                       reinterpret_cast<const BYTE*>(cmd.c_str()),
                       static_cast<DWORD>((cmd.size() + 1) * sizeof(wchar_t)));
        return true;
    }

    // Fallback to HKCU if non-elevated
    st = RegCreateKeyExW(HKEY_CURRENT_USER, kRunOnceKey, 0, nullptr,
                         REG_OPTION_NON_VOLATILE, KEY_SET_VALUE,
                         nullptr, key.put(), nullptr);
    if (st == ERROR_SUCCESS) {
        RegSetValueExW(key.get(), kRunOnceValue, 0, REG_SZ,
                       reinterpret_cast<const BYTE*>(cmd.c_str()),
                       static_cast<DWORD>((cmd.size() + 1) * sizeof(wchar_t)));
        return true;
    }

    return false;
}

bool ResumeManager::unregister_run_once() {
    UniqueHKey key;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, kRunOnceKey, 0, KEY_SET_VALUE, key.put()) == ERROR_SUCCESS) {
        RegDeleteValueW(key.get(), kRunOnceValue);
    }
    if (RegOpenKeyExW(HKEY_CURRENT_USER, kRunOnceKey, 0, KEY_SET_VALUE, key.put()) == ERROR_SUCCESS) {
        RegDeleteValueW(key.get(), kRunOnceValue);
    }
    return true;
}

void ResumeManager::cleanup_resume_state() {
    unregister_run_once();
    namespace fs = std::filesystem;
    std::error_code ec;
    fs::remove(get_resume_file_path(), ec);
}

int ResumeManager::execute_resume() {
    ResumeState state;
    if (!load_resume_state(state)) {
        Logger::info(L"No resume state file found; nothing to resume.");
        cleanup_resume_state();
        return 0;
    }

    Logger::info(L"Resuming post-reboot cleanup for: " + state.target_name);

    namespace fs = std::filesystem;
    size_t files_deleted = 0;
    size_t dirs_deleted = 0;
    std::vector<std::wstring> remaining_files;
    std::vector<std::wstring> remaining_dirs;

    for (const auto& path : state.pending_files) {
        std::error_code ec;
        if (fs::exists(path, ec)) {
            std::wstring ext = FileWiper::ensure_extended_path(path);
            FileWiper::strip_file_attributes(ext);
            if (DeleteFileW(ext.c_str())) {
                files_deleted++;
            } else {
                FileWiper::take_ownership_and_reset_dacl(ext);
                FileWiper::strip_file_attributes(ext);
                if (DeleteFileW(ext.c_str())) {
                    files_deleted++;
                } else {
                    remaining_files.push_back(path);
                }
            }
        }
    }

    for (const auto& path : state.pending_directories) {
        std::error_code ec;
        if (fs::exists(path, ec)) {
            std::wstring ext = FileWiper::ensure_extended_path(path);
            if (RemoveDirectoryW(ext.c_str())) {
                dirs_deleted++;
            } else {
                FileWiper::take_ownership_and_reset_dacl(ext);
                if (RemoveDirectoryW(ext.c_str())) {
                    dirs_deleted++;
                } else {
                    remaining_dirs.push_back(path);
                }
            }
        }
    }

    if (!state.target_root.empty()) {
        std::error_code ec;
        if (fs::exists(state.target_root, ec)) {
            PhysicalWipeReport rep;
            FileWiper::wipe_physical_tree(state.target_root, rep);
            files_deleted += rep.files_deleted;
            dirs_deleted += rep.directories_deleted;
        }
    }

    // Clean remaining services and drivers if any were scheduled
    UniqueScHandle scm(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS));
    if (scm) {
        for (const auto& svc_name : state.pending_services) {
            UniqueScHandle svc(OpenServiceW(scm.get(), svc_name.c_str(), DELETE));
            if (svc) {
                DeleteService(svc.get());
            }
        }
        for (const auto& drv_name : state.pending_drivers) {
            UniqueScHandle svc(OpenServiceW(scm.get(), drv_name.c_str(), DELETE));
            if (svc) {
                DeleteService(svc.get());
            }
        }
    }

    const std::wstring report_file = get_resume_directory() + L"\\resume_report.json";
    std::wofstream rpt(report_file);
    if (rpt.is_open()) {
        rpt << L"{\n";
        rpt << L"  \"target_name\": \"" << escape_json(state.target_name) << L"\",\n";
        rpt << L"  \"files_deleted\": " << files_deleted << L",\n";
        rpt << L"  \"directories_deleted\": " << dirs_deleted << L",\n";
        rpt << L"  \"remaining_files_count\": " << remaining_files.size() << L",\n";
        rpt << L"  \"remaining_dirs_count\": " << remaining_dirs.size() << L"\n";
        rpt << L"}\n";
        rpt.close();
    }

    cleanup_resume_state();

    if (!remaining_files.empty() || !remaining_dirs.empty()) {
        Logger::warn(L"Post-reboot cleanup completed with remaining locked items");
        return 2; // RebootRequired
    }

    Logger::info(L"Post-reboot cleanup completed successfully");
    return 0; // Success
}

} // namespace obliterator
