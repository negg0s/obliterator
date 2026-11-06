#include "obliterator/batch.hpp"

#include "obliterator/error.hpp"
#include "obliterator/executor.hpp"
#include "obliterator/log.hpp"
#include "obliterator/target.hpp"
#include "obliterator/wiper.hpp"

#include <cwctype>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>

namespace obliterator {

namespace fs = std::filesystem;

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

static std::wstring trim_string(const std::wstring& s) {
    size_t start = s.find_first_not_of(L" \t\r\n");
    if (start == std::wstring::npos) return {};
    size_t end = s.find_last_not_of(L" \t\r\n");
    return s.substr(start, end - start + 1);
}

Result<std::vector<std::wstring>> BatchProcessor::parse_batch_file(const std::wstring& file_path) {
    std::wifstream in(file_path);
    if (!in.is_open()) {
        return Win32Error::from_code(ERROR_FILE_NOT_FOUND);
    }

    std::vector<std::wstring> targets;
    std::wstring line;

    // Check if entire file is a JSON array
    std::wstringstream buffer;
    buffer << in.rdbuf();
    std::wstring content = buffer.str();

    std::wstring trimmed = trim_string(content);
    if (!trimmed.empty() && trimmed.front() == L'[' && trimmed.back() == L']') {
        // Parse JSON string array
        size_t idx = 1;
        while (idx < trimmed.size()) {
            size_t open_q = trimmed.find(L'\"', idx);
            if (open_q == std::wstring::npos) break;
            size_t close_q = trimmed.find(L'\"', open_q + 1);
            if (close_q == std::wstring::npos) break;

            std::wstring item;
            size_t cur = open_q + 1;
            while (cur < close_q) {
                if (trimmed[cur] == L'\\' && cur + 1 < close_q) {
                    if (trimmed[cur + 1] == L'\\') item += L'\\';
                    else if (trimmed[cur + 1] == L'\"') item += L'\"';
                    else item += trimmed[cur + 1];
                    cur += 2;
                } else {
                    item += trimmed[cur++];
                }
            }
            if (!item.empty()) {
                targets.push_back(std::move(item));
            }
            idx = close_q + 1;
        }
        return targets;
    }

    // Otherwise, parse plaintext line by line
    std::wstringstream line_stream(content);
    while (std::getline(line_stream, line)) {
        std::wstring t = trim_string(line);
        if (t.empty() || t.starts_with(L"#") || t.starts_with(L";") || t.starts_with(L"//")) {
            continue;
        }
        targets.push_back(std::move(t));
    }

    return targets;
}

void BatchSummary::print_text() const {
    std::wcout << L"\n================================================================================\n"
               << L" Batch Obliteration Summary\n"
               << L"================================================================================\n"
               << L" Total targets:     " << total_targets << L"\n"
               << L" Succeeded:         " << succeeded << L"\n"
               << L" Failed:            " << failed << L"\n"
               << L" Reboot required:   " << reboot_required << L"\n"
               << L" Total space freed: " << FileWiper::format_bytes(total_bytes_freed)
               << L" (" << total_bytes_freed << L" bytes)\n"
               << L"--------------------------------------------------------------------------------\n"
               << L" Target                          Status           Freed       Files   Keys\n"
               << L"--------------------------------------------------------------------------------\n";

    for (const auto& r : results) {
        std::wstring display_name = r.target_name;
        if (display_name.size() > 30) {
            display_name = display_name.substr(0, 27) + L"...";
        }

        std::wstring status_str = r.success ? (r.reboot_required ? L"Pending Reboot" : L"Success") : L"Failed";
        std::wstring freed_str = FileWiper::format_bytes(r.bytes_freed);

        std::wcout << L" " << std::left << std::setw(31) << display_name
                   << L" " << std::left << std::setw(16) << status_str
                   << L" " << std::left << std::setw(11) << freed_str
                   << L" " << std::left << std::setw(7) << r.files_deleted
                   << L" " << r.keys_deleted << L"\n";
    }

    std::wcout << L"================================================================================\n\n";
}

void BatchSummary::print_json() const {
    std::wcout << L"{\n"
               << L"  \"batch_summary\": {\n"
               << L"    \"total_targets\": " << total_targets << L",\n"
               << L"    \"succeeded\": " << succeeded << L",\n"
               << L"    \"failed\": " << failed << L",\n"
               << L"    \"reboot_required\": " << reboot_required << L",\n"
               << L"    \"total_bytes_freed\": " << total_bytes_freed << L",\n"
               << L"    \"total_freed_formatted\": \"" << escape_json(FileWiper::format_bytes(total_bytes_freed)) << L"\"\n"
               << L"  },\n"
               << L"  \"results\": [\n";

    for (size_t i = 0; i < results.size(); ++i) {
        const auto& r = results[i];
        std::wcout << L"    {\n"
                   << L"      \"target\": \"" << escape_json(r.target_name) << L"\",\n"
                   << L"      \"success\": " << (r.success ? L"true" : L"false") << L",\n"
                   << L"      \"reboot_required\": " << (r.reboot_required ? L"true" : L"false") << L",\n"
                   << L"      \"exit_code\": " << r.exit_code << L",\n"
                   << L"      \"bytes_freed\": " << r.bytes_freed << L",\n"
                   << L"      \"files_deleted\": " << r.files_deleted << L",\n"
                   << L"      \"keys_deleted\": " << r.keys_deleted << L",\n"
                   << L"      \"error_message\": \"" << escape_json(r.error_message) << L"\"\n"
                   << L"    }" << (i + 1 < results.size() ? L"," : L"") << L"\n";
    }

    std::wcout << L"  ]\n}\n";
}

int BatchProcessor::run(const CommandLineOptions& options) {
    auto parse_res = parse_batch_file(options.batch_file);
    if (!parse_res) {
        Logger::error(L"Failed to read batch file: " + options.batch_file);
        return ExitCode::Error;
    }

    const auto& targets = parse_res.value();
    if (targets.empty()) {
        Logger::error(L"Batch file contains no valid targets: " + options.batch_file);
        return ExitCode::Error;
    }

    if (!options.json) {
        std::wcout << L"\nStarting batch uninstallation of " << targets.size() << L" targets...\n\n";
    }

    BatchSummary summary;
    summary.total_targets = targets.size();

    for (size_t idx = 0; idx < targets.size(); ++idx) {
        const std::wstring& target_str = targets[idx];
        if (!options.json) {
            std::wcout << L"[" << (idx + 1) << L"/" << targets.size() << L"] Processing: " << target_str << L"\n";
        }

        BatchTargetResult item_res;
        item_res.target_name = target_str;

        auto resolved = TargetResolver::resolve(target_str);
        if (!resolved) {
            item_res.success = false;
            item_res.exit_code = ExitCode::Error;
            item_res.error_message = resolved.error().message();
            summary.failed++;
            summary.results.push_back(std::move(item_res));
            continue;
        }

        CommandLineOptions target_opts = options;
        target_opts.target = target_str;
        target_opts.yes = true; // non-interactive in batch mode

        FinalReport report = execute_obliteration(resolved.value(), target_opts, {});

        item_res.success = report.success;
        item_res.reboot_required = report.reboot_required;
        item_res.exit_code = report.exit_code;
        item_res.bytes_freed = report.bytes_freed;
        item_res.files_deleted = report.files_deleted;
        item_res.keys_deleted = report.total_reg_keys_deleted;

        if (report.success) {
            summary.succeeded++;
            if (report.reboot_required) {
                summary.reboot_required++;
            }
        } else {
            summary.failed++;
        }
        summary.total_bytes_freed += report.bytes_freed;
        summary.results.push_back(std::move(item_res));
    }

    if (options.json) {
        summary.print_json();
    } else {
        summary.print_text();
    }

    if (summary.failed > 0) {
        return ExitCode::Error;
    }
    if (summary.reboot_required > 0) {
        return ExitCode::SuccessRebootRequired;
    }
    return ExitCode::Success;
}

} // namespace obliterator
