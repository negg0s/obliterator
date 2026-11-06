#include "obliterator/rpc.hpp"

#include "obliterator/confidence_engine.hpp"
#include "obliterator/diagnose.hpp"
#include "obliterator/error.hpp"
#include "obliterator/executor.hpp"
#include "obliterator/log.hpp"
#include "obliterator/plan.hpp"
#include "obliterator/quarantine.hpp"
#include "obliterator/target.hpp"
#include "obliterator/ui.hpp"
#include "obliterator/uninstaller.hpp"
#include "obliterator/volume.hpp"
#include "obliterator/wiper.hpp"

#include <iostream>
#include <sstream>
#include <string>
#include <vector>

namespace obliterator {

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

static std::wstring extract_field(const std::wstring& content, std::wstring_view key) {
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

static bool extract_bool_field(const std::wstring& content, std::wstring_view key, bool default_val = false) {
    std::wstring raw = extract_field(content, key);
    if (raw == L"true" || raw == L"1") return true;
    if (raw == L"false" || raw == L"0") return false;
    return default_val;
}

static void send_event(const std::wstring& event_name, const std::wstring& params_json) {
    std::wcout << L"{\"event\":\"" << escape_json(event_name) << L"\",\"params\":" << params_json << L"}\n" << std::flush;
}

std::wstring RpcServer::handle_request_line(
    const std::wstring& line,
    const CommandLineOptions& base_options,
    bool& should_exit
) {
    should_exit = false;
    if (line.empty()) {
        return {};
    }

    std::wstring id_str = extract_field(line, L"id");
    if (id_str.empty()) {
        id_str = L"null";
    }

    std::wstring method = extract_field(line, L"method");
    if (method.empty()) {
        return L"{\"id\":" + id_str + L",\"error\":{\"code\":-32600,\"message\":\"Missing method\"}}\n";
    }

    if (method == L"ping") {
        return L"{\"id\":" + id_str + L",\"result\":{\"status\":\"ok\",\"version\":\"0.3.0\"}}\n";
    }

    if (method == L"exit") {
        should_exit = true;
        return L"{\"id\":" + id_str + L",\"result\":{\"status\":\"exiting\"}}\n";
    }

    if (method == L"list_installed") {
        auto apps = UserInterface::enumerate_installed_apps();
        std::wstringstream ss;
        ss << L"{\"id\":" << id_str << L",\"result\":[";
        for (size_t i = 0; i < apps.size(); ++i) {
            const auto& a = apps[i];
            ss << L"{"
               << L"\"name\":\"" << escape_json(a.name) << L"\","
               << L"\"publisher\":\"" << escape_json(a.publisher) << L"\","
               << L"\"install_location\":\"" << escape_json(a.install_location) << L"\","
               << L"\"uninstall_string\":\"" << escape_json(a.uninstall_string) << L"\","
               << L"\"is_uwp\":" << (a.is_uwp ? L"true" : L"false") << L","
               << L"\"is_portable\":" << (a.type == AppType::Portable ? L"true" : L"false") << L","
               << L"\"size_bytes\":" << a.size_bytes
               << L"}" << (i + 1 < apps.size() ? L"," : L"");
        }
        ss << L"]}\n";
        return ss.str();
    }

    if (method == L"list_sessions") {
        auto sessions = QuarantineManager::list_sessions();
        std::wstringstream ss;
        ss << L"{\"id\":" << id_str << L",\"result\":[";
        for (size_t i = 0; i < sessions.size(); ++i) {
            const auto& s = sessions[i];
            ss << L"{"
               << L"\"session_id\":\"" << escape_json(s.session_id) << L"\","
               << L"\"timestamp\":\"" << escape_json(s.timestamp) << L"\","
               << L"\"target_name\":\"" << escape_json(s.target_name) << L"\","
               << L"\"target_root\":\"" << escape_json(s.target_root) << L"\","
               << L"\"files_count\":" << s.files_count << L","
               << L"\"total_bytes\":" << s.total_bytes << L","
               << L"\"registry_keys_count\":" << s.registry_keys_count
               << L"}" << (i + 1 < sessions.size() ? L"," : L"");
        }
        ss << L"]}\n";
        return ss.str();
    }

    if (method == L"restore") {
        std::wstring session_id = extract_field(line, L"session_id");
        if (session_id.empty()) {
            return L"{\"id\":" + id_str + L",\"error\":{\"code\":-32602,\"message\":\"Missing session_id parameter\"}}\n";
        }
        auto res = QuarantineManager::restore_session(session_id);
        if (!res) {
            return L"{\"id\":" + id_str + L",\"error\":{\"code\":-32000,\"message\":\"" +
                   escape_json(res.error().message()) + L"\"}}\n";
        }
        const auto& rep = res.value();
        std::wstringstream ss;
        ss << L"{\"id\":" << id_str << L",\"result\":{"
           << L"\"session_id\":\"" << escape_json(rep.session_id) << L"\","
           << L"\"success\":" << (rep.success ? L"true" : L"false") << L","
           << L"\"files_restored\":" << rep.files_restored << L","
           << L"\"acls_restored\":" << rep.acls_restored << L","
           << L"\"timestamps_restored\":" << rep.timestamps_restored << L","
           << L"\"registry_keys_restored\":" << rep.registry_keys_restored
           << L"}}\n";
        return ss.str();
    }

    if (method == L"purge_quarantine") {
        std::wstring session_id = extract_field(line, L"session_id");
        if (session_id.empty()) {
            return L"{\"id\":" + id_str + L",\"error\":{\"code\":-32602,\"message\":\"Missing session_id parameter\"}}\n";
        }
        auto res = QuarantineManager::purge_session(session_id);
        if (!res) {
            return L"{\"id\":" + id_str + L",\"error\":{\"code\":-32000,\"message\":\"" +
                   escape_json(res.error().message()) + L"\"}}\n";
        }
        return L"{\"id\":" + id_str + L",\"result\":{\"purged\":true}}\n";
    }

    if (method == L"diagnose") {
        auto res = SystemDiagnostics::collect_report();
        if (!res) {
            return L"{\"id\":" + id_str + L",\"error\":{\"code\":-32000,\"message\":\"" +
                   escape_json(res.error().message()) + L"\"}}\n";
        }
        return L"{\"id\":" + id_str + L",\"result\":{\"report\":\"" + escape_json(res.value()) + L"\"}}\n";
    }

    if (method == L"scan" || method == L"execute") {
        std::wstring target_str = extract_field(line, L"target");
        if (target_str.empty()) {
            return L"{\"id\":" + id_str + L",\"error\":{\"code\":-32602,\"message\":\"Missing target parameter\"}}\n";
        }

        auto target_res = TargetResolver::resolve(target_str);
        if (!target_res) {
            return L"{\"id\":" + id_str + L",\"error\":{\"code\":-32001,\"message\":\"Target not found: " +
                   escape_json(target_str) + L"\"}}\n";
        }
        const auto& target = target_res.value();

        if (method == L"scan") {
            auto scored = ConfidenceEngine::discover_artifacts(target);
            std::wstringstream ss;
            ss << L"{\"id\":" << id_str << L",\"result\":{"
               << L"\"target_name\":\"" << escape_json(target.name) << L"\","
               << L"\"target_root\":\"" << escape_json(target.root_path) << L"\","
               << L"\"artifacts\":[";
            for (size_t i = 0; i < scored.size(); ++i) {
                const auto& a = scored[i];
                ss << L"{"
                   << L"\"identifier\":\"" << escape_json(a.identifier) << L"\","
                   << L"\"kind\":\"" << escape_json(a.kind_string()) << L"\","
                   << L"\"score\":" << a.score << L","
                   << L"\"category\":\"" << escape_json(a.category_string()) << L"\","
                   << L"\"is_protected\":" << (a.is_protected ? L"true" : L"false")
                   << L"}" << (i + 1 < scored.size() ? L"," : L"");
            }
            ss << L"]}}\n";
            return ss.str();
        }

        // execute method
        CommandLineOptions opts = base_options;
        opts.target = target_str;
        opts.quarantine = extract_bool_field(line, L"quarantine", opts.quarantine);
        std::wstring q_dir = extract_field(line, L"quarantine_dir");
        if (!q_dir.empty()) {
            opts.quarantine_dir = q_dir;
            opts.quarantine = true;
        }
        opts.dry_run = extract_bool_field(line, L"dry_run", opts.dry_run);
        opts.aggressive = extract_bool_field(line, L"aggressive", opts.aggressive);
        opts.all_users = extract_bool_field(line, L"all_users", opts.all_users);
        opts.no_backup = extract_bool_field(line, L"no_backup", opts.no_backup);
        opts.force = extract_bool_field(line, L"force", opts.force);

        auto on_phase = [](size_t phase, const std::wstring& name) {
            std::wstring params = L"{\"phase\":" + std::to_wstring(phase) +
                                  L",\"name\":\"" + escape_json(name) + L"\"}";
            send_event(L"phase", params);
        };

        auto on_log = [](const std::wstring& msg) {
            std::wstring params = L"{\"message\":\"" + escape_json(msg) + L"\"}";
            send_event(L"log", params);
        };

        FinalReport report = execute_obliteration(target, opts, {}, on_phase, on_log, nullptr);

        std::wstringstream ss;
        ss << L"{\"id\":" << id_str << L",\"result\":{"
           << L"\"success\":" << (report.success ? L"true" : L"false") << L","
           << L"\"reboot_required\":" << (report.reboot_required ? L"true" : L"false") << L","
           << L"\"exit_code\":" << report.exit_code << L","
           << L"\"processes_killed\":" << report.processes_killed << L","
           << L"\"handles_closed\":" << report.handles_closed << L","
           << L"\"services_stopped\":" << report.services_stopped << L","
           << L"\"services_deleted\":" << report.services_deleted << L","
           << L"\"tasks_deleted\":" << report.tasks_deleted << L","
           << L"\"files_deleted\":" << report.files_deleted << L","
           << L"\"directories_deleted\":" << report.directories_deleted << L","
           << L"\"bytes_freed\":" << report.bytes_freed << L","
           << L"\"total_reg_keys_deleted\":" << report.total_reg_keys_deleted << L","
           << L"\"volume_deltas\":[";
        for (size_t i = 0; i < report.volume_deltas.size(); ++i) {
            const auto& vd = report.volume_deltas[i];
            ss << L"{"
               << L"\"drive\":\"" << escape_json(vd.drive) << L"\","
               << L"\"freed_bytes\":" << vd.freed_bytes << L","
               << L"\"final_free_bytes\":" << vd.final_free_bytes << L","
               << L"\"total_bytes\":" << vd.total_bytes
               << L"}" << (i + 1 < report.volume_deltas.size() ? L"," : L"");
        }
        ss << L"]}}\n";
        return ss.str();
    }

    return L"{\"id\":" + id_str + L",\"error\":{\"code\":-32601,\"message\":\"Method not found\"}}\n";
}

int RpcServer::run(const CommandLineOptions& base_options) {
    Logger::set_json_mode(true);

    std::wstring line;
    while (std::getline(std::wcin, line)) {
        if (line.empty()) {
            continue;
        }

        bool should_exit = false;
        std::wstring resp = handle_request_line(line, base_options, should_exit);
        if (!resp.empty()) {
            std::wcout << resp << std::flush;
        }

        if (should_exit) {
            break;
        }
    }

    return 0;
}

} // namespace obliterator
