#include "obliterator/tui.hpp"
#include "obliterator/confidence_engine.hpp"
#include "obliterator/error.hpp"
#include "obliterator/executor.hpp"
#include "obliterator/leftovers.hpp"
#include "obliterator/process.hpp"
#include "obliterator/profile.hpp"
#include "obliterator/service.hpp"
#include "obliterator/target.hpp"
#include "obliterator/ui.hpp"
#include "obliterator/wiper.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cwctype>
#include <filesystem>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace obliterator {

bool is_wide_char(wchar_t ch) noexcept {
    if (ch >= 0xFF01 && ch <= 0xFF60) return true;
    if (ch >= 0xFFE0 && ch <= 0xFFE6) return true;
    if (ch >= 0x2E80 && ch <= 0x2FD5) return true;
    if (ch >= 0x3000 && ch <= 0x303F) return true;
    if (ch >= 0x3040 && ch <= 0x309F) return true;
    if (ch >= 0x30A0 && ch <= 0x30FF) return true;
    if (ch >= 0x3100 && ch <= 0x312F) return true;
    if (ch >= 0x31A0 && ch <= 0x31BF) return true;
    if (ch >= 0xAC00 && ch <= 0xD7A3) return true;
    if (ch >= 0x1100 && ch <= 0x115F) return true;
    if (ch >= 0x4E00 && ch <= 0x9FFF) return true;
    if (ch >= 0xF900 && ch <= 0xFAFF) return true;
    return false;
}

size_t display_width(std::wstring_view text) noexcept {
    size_t width = 0;
    for (size_t i = 0; i < text.size(); ++i) {
        wchar_t ch = text[i];
        if (ch >= 0xD800 && ch <= 0xDBFF) {
            if (i + 1 < text.size() && (text[i + 1] >= 0xDC00 && text[i + 1] <= 0xDFFF)) {
                uint32_t cp = 0x10000 + ((static_cast<uint32_t>(ch) - 0xD800) << 10) +
                              (static_cast<uint32_t>(text[i + 1]) - 0xDC00);
                if ((cp >= 0x1F300 && cp <= 0x1FAFF) || (cp >= 0x20000 && cp <= 0x2FA1F)) {
                    width += 2;
                } else {
                    width += 1;
                }
                ++i;
                continue;
            }
        }
        if (ch == L'\0' || ch == L'\r' || ch == L'\n') {
            continue;
        }
        if (is_wide_char(ch)) {
            width += 2;
        } else {
            width += 1;
        }
    }
    return width;
}

std::wstring truncate_to_width(std::wstring_view text, size_t max_width, std::wstring_view ellipsis) {
    if (max_width == 0) {
        return {};
    }
    size_t cur_w = display_width(text);
    if (cur_w <= max_width) {
        return std::wstring(text);
    }
    size_t ell_w = display_width(ellipsis);
    if (max_width <= ell_w) {
        return std::wstring(ellipsis.substr(0, std::min(ellipsis.size(), max_width)));
    }
    size_t target_w = max_width - ell_w;
    std::wstring result;
    size_t accumulated = 0;
    for (size_t i = 0; i < text.size(); ++i) {
        wchar_t ch = text[i];
        size_t char_w = 1;
        bool is_surrogate = false;
        if (ch >= 0xD800 && ch <= 0xDBFF && i + 1 < text.size() &&
            (text[i + 1] >= 0xDC00 && text[i + 1] <= 0xDFFF)) {
            is_surrogate = true;
            uint32_t cp = 0x10000 + ((static_cast<uint32_t>(ch) - 0xD800) << 10) +
                          (static_cast<uint32_t>(text[i + 1]) - 0xDC00);
            char_w = ((cp >= 0x1F300 && cp <= 0x1FAFF) || (cp >= 0x20000 && cp <= 0x2FA1F)) ? 2 : 1;
        } else if (is_wide_char(ch)) {
            char_w = 2;
        }

        if (accumulated + char_w > target_w) {
            break;
        }
        result.push_back(ch);
        if (is_surrogate) {
            result.push_back(text[++i]);
        }
        accumulated += char_w;
    }
    result.append(ellipsis);
    return result;
}

std::wstring pad_to_width(std::wstring_view text, size_t target_width, bool align_right) {
    std::wstring truncated = truncate_to_width(text, target_width, L"...");
    size_t cur_w = display_width(truncated);
    if (cur_w >= target_width) {
        return truncated;
    }
    size_t padding = target_width - cur_w;
    if (align_right) {
        return std::wstring(padding, L' ') + truncated;
    }
    return truncated + std::wstring(padding, L' ');
}

bool is_no_color() noexcept {
    wchar_t buf[2];
    DWORD res = GetEnvironmentVariableW(L"NO_COLOR", buf, 2);
    return res > 0;
}

std::wstring ansi_reset() {
    return is_no_color() ? L"" : L"\x1b[0m";
}
std::wstring ansi_bold() {
    return is_no_color() ? L"" : L"\x1b[1m";
}
std::wstring ansi_dim() {
    return is_no_color() ? L"" : L"\x1b[2m";
}
std::wstring ansi_invert() {
    return is_no_color() ? L"" : L"\x1b[7m";
}
std::wstring ansi_fg(int code) {
    if (is_no_color()) return L"";
    return L"\x1b[" + std::to_wstring(code) + L"m";
}
std::wstring ansi_bg(int code) {
    if (is_no_color()) return L"";
    return L"\x1b[" + std::to_wstring(code) + L"m";
}

bool is_console_interactive() noexcept {
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    HANDLE hIn = GetStdHandle(STD_INPUT_HANDLE);
    if (hOut == INVALID_HANDLE_VALUE || hIn == INVALID_HANDLE_VALUE) {
        return false;
    }
    DWORD out_mode = 0;
    if (!GetConsoleMode(hOut, &out_mode)) {
        return false;
    }
    DWORD in_mode = 0;
    if (!GetConsoleMode(hIn, &in_mode)) {
        return false;
    }
    return true;
}

class ConsoleScreenGuard {
public:
    ConsoleScreenGuard() {
        m_hOut = GetStdHandle(STD_OUTPUT_HANDLE);
        m_hIn = GetStdHandle(STD_INPUT_HANDLE);

        GetConsoleMode(m_hOut, &m_orig_out_mode);
        GetConsoleMode(m_hIn, &m_orig_in_mode);

        SetConsoleMode(m_hOut, m_orig_out_mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
        SetConsoleMode(m_hIn, ENABLE_WINDOW_INPUT | ENABLE_MOUSE_INPUT | ENABLE_EXTENDED_FLAGS);

        write_vt(L"\x1b[?1049h\x1b[?25l");
        s_active_guard = this;
        SetConsoleCtrlHandler(ctrl_handler, TRUE);
    }

    ~ConsoleScreenGuard() {
        restore();
    }

    void restore() {
        if (!m_restored) {
            m_restored = true;
            write_vt(L"\x1b[0m\x1b[?25h\x1b[?1049l");
            SetConsoleMode(m_hOut, m_orig_out_mode);
            SetConsoleMode(m_hIn, m_orig_in_mode);
            SetConsoleCtrlHandler(ctrl_handler, FALSE);
            if (s_active_guard == this) {
                s_active_guard = nullptr;
            }
        }
    }

    HANDLE output_handle() const noexcept { return m_hOut; }
    HANDLE input_handle() const noexcept { return m_hIn; }

private:
    void write_vt(const wchar_t* seq) {
        if (m_hOut != INVALID_HANDLE_VALUE) {
            DWORD written = 0;
            WriteConsoleW(m_hOut, seq, static_cast<DWORD>(wcslen(seq)), &written, nullptr);
        }
    }

    static BOOL WINAPI ctrl_handler(DWORD) {
        if (s_active_guard) {
            s_active_guard->restore();
        }
        return FALSE;
    }

    HANDLE m_hOut{INVALID_HANDLE_VALUE};
    HANDLE m_hIn{INVALID_HANDLE_VALUE};
    DWORD m_orig_out_mode{0};
    DWORD m_orig_in_mode{0};
    bool m_restored{false};

    static inline ConsoleScreenGuard* s_active_guard{nullptr};
};

class PreviewWorker {
public:
    PreviewWorker(TuiModel& model) : m_model(model), m_thread(&PreviewWorker::worker_loop, this) {}

    ~PreviewWorker() {
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_stop = true;
        }
        m_cv.notify_one();
        if (m_thread.joinable()) {
            m_thread.join();
        }
    }

    void request_preview(const TuiAppItem& app) {
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_pending_app = app;
            m_generation++;
            m_has_pending = true;
        }
        m_cv.notify_one();
    }

private:
    void worker_loop() {
        while (true) {
            TuiAppItem app;
            uint64_t gen = 0;
            {
                std::unique_lock<std::mutex> lock(m_mutex);
                m_cv.wait(lock, [this]() { return m_has_pending || m_stop; });
                if (m_stop) {
                    break;
                }
                app = m_pending_app;
                gen = m_generation;
                m_has_pending = false;
            }

            m_model.set_preview_calculating(true);

            PreviewPlan plan{};
            plan.ready = false;
            plan.calculating = true;

            Target target;
            target.name = app.name;
            target.root_path = app.root_path;
            target.is_uwp = (app.type == AppType::Store);
            target.uwp_package_full_name = app.uwp_package_full_name;

            if (!app.root_path.empty()) {
                auto procs = ProcessManager::find_target_processes(app.root_path);
                plan.process_count = procs.size();

                auto svcs = ServiceManager::find_target_services(app.root_path);
                plan.service_count = svcs.size();

                auto tasks = ServiceManager::find_target_tasks(app.root_path);
                plan.task_count = tasks.size();

                // Quick file count
                size_t file_cnt = 0;
                uint64_t total_bytes = 0;
                namespace fs = std::filesystem;
                std::error_code ec;
                for (auto it = fs::recursive_directory_iterator(app.root_path, fs::directory_options::skip_permission_denied, ec);
                     it != fs::recursive_directory_iterator(); it.increment(ec)) {
                    if (ec) {
                        ec.clear();
                        continue;
                    }
                    if (it->is_regular_file(ec)) {
                        file_cnt++;
                        total_bytes += it->file_size(ec);
                    }
                    if (file_cnt >= 20000 || m_generation != gen) {
                        break;
                    }
                }
                plan.file_count = file_cnt;
                plan.total_file_bytes = total_bytes;
            }

            std::vector<UserProfileInfo> profiles = ProfileManager::enumerate_profiles(false);
            auto all_apps = UserInterface::enumerate_installed_apps();
            auto scored = ConfidenceEngine::discover_artifacts(target, all_apps, profiles);

            plan.leftover_count = scored.size();
            plan.artifacts = std::move(scored);
            plan.calculating = false;
            plan.ready = true;

            {
                std::lock_guard<std::mutex> lock(m_mutex);
                if (m_generation == gen) {
                    m_model.set_preview_plan(plan);
                    m_model.set_preview_calculating(false);
                }
            }
        }
    }

    TuiModel& m_model;
    std::mutex m_mutex;
    std::condition_variable m_cv;
    TuiAppItem m_pending_app;
    uint64_t m_generation{0};
    bool m_has_pending{false};
    bool m_stop{false};
    std::thread m_thread;
};

static void render_list_screen(TuiModel& model, size_t width, size_t height, std::wstring& frame, size_t spinner_idx) {
    const wchar_t spinner_chars[] = {L'|', L'/', L'-', L'\\'};
    wchar_t spin = spinner_chars[spinner_idx % 4];

    // Top Bar
    std::wstring sort_name;
    switch (model.get_sort_mode()) {
        case SortMode::Size: sort_name = L"Size"; break;
        case SortMode::Name: sort_name = L"Name"; break;
        case SortMode::Date: sort_name = L"Date"; break;
    }

    std::wstring top_line = L" OBLITERATOR v0.1.0 │ Sort: [" + sort_name +
                            L"] (s/n/d) │ Total: " + std::to_wstring(model.get_filtered_count()) +
                            L" apps";
    if (model.is_filtering() || !model.get_filter_query().empty()) {
        top_line += L" │ Filter: \"" + model.get_filter_query() + L"\"";
    }
    frame += ansi_bold() + ansi_bg(44) + ansi_fg(97) + pad_to_width(top_line, width) + ansi_reset() + L"\n";

    // Divider
    frame += ansi_fg(90) + std::wstring(width, L'─') + ansi_reset() + L"\n";

    // Layout
    size_t content_height = (height > 4) ? (height - 4) : 1;
    size_t left_w = (width * 55) / 100;
    if (left_w < 45) left_w = 45;
    if (left_w + 30 > width && width > 40) left_w = width - 30;
    size_t right_w = (width > left_w + 1) ? (width - left_w - 1) : 0;

    // Header line inside main area
    std::wstring col_type = pad_to_width(L"Type", 6);
    size_t name_col_w = (left_w > 30) ? (left_w - 30) : 10;
    std::wstring col_name = pad_to_width(L"Application Name", name_col_w);
    std::wstring col_size = pad_to_width(L"Size", 10, true);
    std::wstring col_date = pad_to_width(L"Installed", 12, true);
    std::wstring left_header = col_type + L" " + col_name + L" " + col_size + L" " + col_date;
    left_header = pad_to_width(left_header, left_w);

    std::wstring right_header = pad_to_width(L" Application Details & Preliminary Plan", right_w);

    frame += ansi_bold() + ansi_fg(96) + left_header + ansi_fg(90) + L"│" + ansi_fg(93) + right_header + ansi_reset() + L"\n";

    // Compute visible list window
    const auto& filtered = model.get_filtered_indices();
    const auto& apps = model.get_all_apps();
    size_t visible_rows = (content_height > 1) ? (content_height - 1) : 1;

    size_t selected = model.get_selected_index();
    size_t scroll = model.get_scroll_offset();
    if (selected < scroll) {
        scroll = selected;
        model.set_scroll_offset(scroll);
    } else if (selected >= scroll + visible_rows) {
        scroll = selected - visible_rows + 1;
        model.set_scroll_offset(scroll);
    }

    const TuiAppItem* sel_app = model.get_selected_app();
    const auto& plan = model.get_preview_plan();

    for (size_t row = 0; row < visible_rows; ++row) {
        size_t item_idx = scroll + row;
        std::wstring left_cell;

        if (item_idx < filtered.size()) {
            size_t app_idx = filtered[item_idx];
            const auto& item = apps[app_idx];

            std::wstring t_str = pad_to_width(item.type_string(), 6);
            std::wstring n_str = pad_to_width(item.name, name_col_w);
            std::wstring s_str = (item.size_bytes > 0)
                                 ? FileWiper::format_bytes(item.size_bytes)
                                 : L"----";
            s_str = pad_to_width(s_str, 10, true);
            std::wstring d_str = pad_to_width(item.install_date, 12, true);

            left_cell = t_str + L" " + n_str + L" " + s_str + L" " + d_str;
            left_cell = pad_to_width(left_cell, left_w);

            if (item_idx == selected) {
                left_cell = ansi_invert() + ansi_bold() + left_cell + ansi_reset();
            }
        } else {
            left_cell = std::wstring(left_w, L' ');
        }

        // Right panel row
        std::wstring right_cell;
        if (sel_app) {
            switch (row) {
                case 0: right_cell = L" Name:      " + sel_app->name; break;
                case 1: right_cell = L" Publisher: " + (sel_app->publisher.empty() ? L"(Unknown)" : sel_app->publisher); break;
                case 2: right_cell = L" Type:      " + sel_app->type_string(); break;
                case 3: right_cell = L" Path:      " + (sel_app->root_path.empty() ? L"(Not found)" : sel_app->root_path); break;
                case 4: right_cell = L" Date:      " + sel_app->install_date; break;
                case 5: right_cell = std::wstring(right_w > 2 ? right_w - 2 : 1, L'─'); break;
                case 6:
                    if (plan.calculating) {
                        right_cell = std::wstring(L" [") + spin + L"] Calculating preliminary plan...";
                    } else if (plan.ready) {
                        right_cell = L" Preliminary Plan Summary:";
                    } else {
                        right_cell = L" Preliminary Plan: Idle";
                    }
                    break;
                case 7:
                    if (plan.ready) {
                        right_cell = L"  - Processes:  " + std::to_wstring(plan.process_count);
                    }
                    break;
                case 8:
                    if (plan.ready) {
                        right_cell = L"  - Services:   " + std::to_wstring(plan.service_count);
                    }
                    break;
                case 9:
                    if (plan.ready) {
                        right_cell = L"  - Tasks:      " + std::to_wstring(plan.task_count);
                    }
                    break;
                case 10:
                    if (plan.ready) {
                        right_cell = L"  - Files:      " + std::to_wstring(plan.file_count) +
                                     L" (" + FileWiper::format_bytes(plan.total_file_bytes) + L")";
                    }
                    break;
                case 11:
                    if (plan.ready) {
                        right_cell = L"  - Leftovers:  " + std::to_wstring(plan.leftover_count) + L" artifacts scored";
                    }
                    break;
                case 12:
                    if (plan.ready && !plan.artifacts.empty()) {
                        right_cell = ansi_fg(93) + L" Press [p] for artifact details & exclusions" + ansi_reset();
                    }
                    break;
                default:
                    right_cell = L"";
                    break;
            }
        }
        right_cell = pad_to_width(right_cell, right_w);

        frame += left_cell + ansi_fg(90) + L"│" + ansi_reset() + right_cell + L"\n";
    }

    // Bottom Divider
    frame += ansi_fg(90) + std::wstring(width, L'─') + ansi_reset() + L"\n";

    // Bottom Bar / Key hints
    std::wstring bottom_line;
    if (model.is_filtering()) {
        bottom_line = L" FILTER: " + model.get_filter_query() + L"_ │ [Enter] Apply │ [Esc] Cancel";
        frame += ansi_bg(100) + ansi_fg(97) + ansi_bold() + pad_to_width(bottom_line, width) + ansi_reset();
    } else {
        bottom_line = L" [↑/↓] Select  [s/n/d] Sort  [/] Filter  [p] Plan  [Enter] Obliterate  [Esc] Exit";
        frame += ansi_bg(236) + ansi_fg(97) + pad_to_width(bottom_line, width) + ansi_reset();
    }
}

static void render_plan_screen(TuiModel& model, size_t width, size_t height, std::wstring& frame) {
    const auto* app = model.get_selected_app();
    std::wstring app_name = app ? app->name : L"Selected Program";

    // Top Header
    std::wstring header = L" Artifact Plan Details: " + app_name + L" (Total: " +
                          std::to_wstring(model.get_plan_items().size()) + L")";
    frame += ansi_bold() + ansi_bg(44) + ansi_fg(97) + pad_to_width(header, width) + ansi_reset() + L"\n";
    frame += ansi_fg(90) + std::wstring(width, L'─') + ansi_reset() + L"\n";

    // Columns
    std::wstring col_check = pad_to_width(L"[X]", 5);
    std::wstring col_type = pad_to_width(L"Kind", 10);
    std::wstring col_score = pad_to_width(L"Score", 8);
    std::wstring col_id = pad_to_width(L"Target Identifier / Path / Reasons", (width > 26) ? (width - 26) : 10);
    frame += ansi_bold() + ansi_fg(96) + col_check + L" " + col_type + L" " + col_score + L" " + col_id + ansi_reset() + L"\n";

    size_t visible_rows = (height > 5) ? (height - 5) : 1;
    const auto& items = model.get_plan_items();
    size_t selected = model.get_plan_selected_index();
    size_t scroll = model.get_plan_scroll_offset();

    if (selected < scroll) {
        scroll = selected;
        model.set_plan_scroll_offset(scroll);
    } else if (selected >= scroll + visible_rows) {
        scroll = selected - visible_rows + 1;
        model.set_plan_scroll_offset(scroll);
    }

    for (size_t row = 0; row < visible_rows; ++row) {
        size_t idx = scroll + row;
        std::wstring line;
        if (idx < items.size()) {
            const auto& it = items[idx];
            std::wstring check = it.excluded ? L"[ ]" : L"[X]";
            std::wstring kind = pad_to_width(it.artifact.kind_string(), 10);

            std::wstring score_str = L"[" + std::to_wstring(it.artifact.score) + L"]";
            std::wstring color = (it.artifact.score >= 70) ? ansi_fg(92) :
                                ((it.artifact.score >= 40) ? ansi_fg(93) : ansi_fg(91));
            std::wstring formatted_score = pad_to_width(score_str, 8);

            std::wstring details = it.artifact.identifier;
            if (!it.artifact.reasons.empty()) {
                details += L" (" + it.artifact.reasons.front().description + L")";
            }
            if (it.excluded) {
                details += L" [EXCLUDED]";
            }
            size_t detail_w = (width > 26) ? (width - 26) : 10;
            details = pad_to_width(details, detail_w);

            line = check + L"  " + kind + L" " + color + formatted_score + ansi_reset() + L" " + details;
            line = pad_to_width(line, width);

            if (idx == selected) {
                line = ansi_invert() + ansi_bold() + line + ansi_reset();
            } else if (it.excluded) {
                line = ansi_dim() + line + ansi_reset();
            }
        } else {
            line = std::wstring(width, L' ');
        }
        frame += line + L"\n";
    }

    // Bottom
    frame += ansi_fg(90) + std::wstring(width, L'─') + ansi_reset() + L"\n";
    std::wstring bottom = L" [↑/↓] Navigate  [Space] Toggle Exclude  [Esc] Back to Main List";
    frame += ansi_bg(236) + ansi_fg(97) + pad_to_width(bottom, width) + ansi_reset();
}

static void render_confirm_screen(TuiModel& model, size_t width, size_t height, std::wstring& frame) {
    const auto* app = model.get_selected_app();
    const auto& plan = model.get_preview_plan();

    size_t box_w = 66;
    if (box_w > width) box_w = (width > 4) ? (width - 2) : width;
    size_t box_h = 16;
    size_t start_y = (height > box_h) ? ((height - box_h) / 2) : 0;
    size_t start_x = (width > box_w) ? ((width - box_w) / 2) : 0;

    std::vector<std::wstring> lines(height, std::wstring(width, L' '));

    auto draw_box_row = [&](size_t row_idx, const std::wstring& content) {
        if (row_idx >= height) return;
        std::wstring interior = pad_to_width(content, box_w - 2);
        std::wstring line = L"│" + interior + L"│";
        if (start_x + line.size() <= width) {
            lines[row_idx].replace(start_x, line.size(), line);
        }
    };

    if (start_y < height) {
        std::wstring top_border = L"┌" + std::wstring(box_w - 2, L'─') + L"┐";
        lines[start_y].replace(start_x, top_border.size(), top_border);
    }

    draw_box_row(start_y + 1, L"                       CONFIRM DELETION");
    draw_box_row(start_y + 2, L"");
    draw_box_row(start_y + 3, L" Target: " + (app ? app->name : L""));
    draw_box_row(start_y + 4, L" Path:   " + (app ? app->root_path : L""));
    draw_box_row(start_y + 5, L"");
    draw_box_row(start_y + 6, L" Planned Actions:");
    draw_box_row(start_y + 7, L"  - Terminate processes: " + std::to_wstring(plan.process_count));
    draw_box_row(start_y + 8, L"  - Delete services:     " + std::to_wstring(plan.service_count));
    draw_box_row(start_y + 9, L"  - Wipe files:          " + std::to_wstring(plan.file_count) +
                              L" (" + FileWiper::format_bytes(plan.total_file_bytes) + L")");
    draw_box_row(start_y + 10, L"  - Clean leftovers:     " + std::to_wstring(plan.leftover_count));
    draw_box_row(start_y + 11, L"");
    draw_box_row(start_y + 12, L" Type exact program name to confirm:");
    draw_box_row(start_y + 13, L" > " + model.get_confirm_input() + L"_");
    draw_box_row(start_y + 14, model.can_confirm()
        ? L" [MATCHED] Press [Enter] to Obliterate!  │  [Esc] Cancel"
        : L" [Enter] Obliterate (Disabled)       │  [Esc] Cancel");

    if (start_y + 15 < height) {
        std::wstring bot_border = L"└" + std::wstring(box_w - 2, L'─') + L"┘";
        lines[start_y + 15].replace(start_x, bot_border.size(), bot_border);
    }

    for (size_t y = 0; y < height; ++y) {
        if (y == start_y + 14 && model.can_confirm()) {
            frame += ansi_bold() + ansi_fg(92) + lines[y] + ansi_reset();
        } else {
            frame += lines[y];
        }
        if (y + 1 < height) {
            frame += L"\n";
        }
    }
}

static void render_executing_screen(TuiModel& model, size_t width, size_t height, std::wstring& frame) {
    const auto* app = model.get_selected_app();
    std::wstring app_name = app ? app->name : L"Selected Program";

    // Top Header
    std::wstring header = L" OBLITERATOR - Executing removal of: " + app_name;
    frame += ansi_bold() + ansi_bg(41) + ansi_fg(97) + pad_to_width(header, width) + ansi_reset() + L"\n";
    frame += ansi_fg(90) + std::wstring(width, L'─') + ansi_reset() + L"\n";

    // Phase and progress bar
    size_t phase = model.get_current_phase();
    size_t total_phases = model.get_total_phases();
    std::wstring phase_line = L" Phase [" + std::to_wstring(phase) + L"/" +
                              std::to_wstring(total_phases) + L"]: " + model.get_phase_name();
    frame += ansi_bold() + ansi_fg(93) + pad_to_width(phase_line, width) + ansi_reset() + L"\n";

    size_t bar_w = (width > 20) ? (width - 16) : 10;
    size_t pct = (total_phases > 0) ? (phase * 100 / total_phases) : 0;
    if (pct > 100) pct = 100;
    size_t filled = (bar_w * pct) / 100;
    std::wstring bar = L" [" + ansi_fg(92) + std::wstring(filled, L'=') +
                       ((filled < bar_w) ? L">" : L"") +
                       ansi_reset() + std::wstring(bar_w - filled - (filled < bar_w ? 1 : 0), L' ') +
                       L"] " + std::to_wstring(pct) + L"%";
    frame += pad_to_width(bar, width) + L"\n";
    frame += ansi_fg(90) + std::wstring(width, L'─') + ansi_reset() + L"\n";

    // Scrollable logs
    const auto& logs = model.get_execution_logs();
    size_t log_rows = (height > 7) ? (height - 7) : 1;
    size_t start_log = (logs.size() > log_rows) ? (logs.size() - log_rows) : 0;

    for (size_t r = 0; r < log_rows; ++r) {
        size_t l_idx = start_log + r;
        std::wstring line = (l_idx < logs.size()) ? (L"  " + logs[l_idx]) : L"";
        frame += pad_to_width(line, width) + L"\n";
    }

    // Bottom
    frame += ansi_fg(90) + std::wstring(width, L'─') + ansi_reset() + L"\n";
    std::wstring bottom = model.is_cancelling()
        ? L" CANCELLING... Waiting for active phase to conclude safely."
        : L" Execution in progress... Press [Esc] to cancel safely between phases.";
    frame += ansi_bg(236) + ansi_fg(model.is_cancelling() ? 91 : 97) + pad_to_width(bottom, width) + ansi_reset();
}

static void render_finished_screen(TuiModel& model, size_t width, size_t height, std::wstring& frame) {
    const auto& rep = model.get_final_report();

    // Top Header
    std::wstring header = L" OBLITERATOR - Operation Finished";
    int bg = rep.success ? 42 : 41;
    frame += ansi_bold() + ansi_bg(bg) + ansi_fg(97) + pad_to_width(header, width) + ansi_reset() + L"\n";
    frame += ansi_fg(90) + std::wstring(width, L'─') + ansi_reset() + L"\n";

    std::wstring exit_str = (rep.exit_code == 0) ? L"Success (0)" :
                           ((rep.exit_code == 2) ? L"Success - Reboot Required (2)" :
                           ((rep.exit_code == 3) ? L"Safety Violation (3)" : L"Error (1)"));

    std::vector<std::wstring> lines;
    lines.push_back(L" Target:               " + rep.target_name);
    lines.push_back(L" Exit Code:            " + exit_str);
    lines.push_back(L" Files deleted:        " + std::to_wstring(rep.files_deleted));
    lines.push_back(L" Directories deleted:  " + std::to_wstring(rep.directories_deleted));
    lines.push_back(L" Bytes freed:          " + FileWiper::format_bytes(rep.bytes_freed));
    lines.push_back(L" Registry keys wiped:  " + std::to_wstring(rep.total_reg_keys_deleted));
    lines.push_back(L" Processes killed:     " + std::to_wstring(rep.processes_killed));
    lines.push_back(L" Services deleted:     " + std::to_wstring(rep.services_deleted));
    lines.push_back(L" Tasks deleted:        " + std::to_wstring(rep.tasks_deleted));
    if (rep.reboot_required) {
        lines.push_back(L" Post-reboot resumption scheduled via RunOnce.");
    }

    size_t visible_rows = (height > 4) ? (height - 4) : 1;
    for (size_t r = 0; r < visible_rows; ++r) {
        std::wstring line = (r < lines.size()) ? lines[r] : L"";
        frame += pad_to_width(line, width) + L"\n";
    }

    // Bottom
    frame += ansi_fg(90) + std::wstring(width, L'─') + ansi_reset() + L"\n";
    std::wstring bottom = L" Finished! Press [Enter] or [Esc] to exit.";
    frame += ansi_bg(236) + ansi_fg(97) + pad_to_width(bottom, width) + ansi_reset();
}

int TuiRunner::run(CommandLineOptions options) {
    ConsoleScreenGuard guard;
    HANDLE hIn = guard.input_handle();
    HANDLE hOut = guard.output_handle();

    TuiModel model;
    auto installed_apps = UserInterface::enumerate_installed_apps();
    std::vector<TuiAppItem> items;
    items.reserve(installed_apps.size());
    for (const auto& a : installed_apps) {
        items.push_back({
            a.name,
            a.publisher,
            a.install_date,
            a.size_bytes,
            a.root_path,
            a.type,
            a.uninstall_string,
            a.uwp_package_full_name
        });
    }
    model.set_apps(std::move(items));

    PreviewWorker preview_worker(model);
    if (const auto* first_app = model.get_selected_app()) {
        preview_worker.request_preview(*first_app);
    }

    size_t last_selected_idx = 0;
    size_t spinner_idx = 0;
    bool running = true;
    std::thread execution_thread;

    while (running) {
        // Query window dimensions
        CONSOLE_SCREEN_BUFFER_INFO csbi{};
        size_t width = 100;
        size_t height = 30;
        if (GetConsoleScreenBufferInfo(hOut, &csbi)) {
            width = static_cast<size_t>(csbi.srWindow.Right - csbi.srWindow.Left + 1);
            height = static_cast<size_t>(csbi.srWindow.Bottom - csbi.srWindow.Top + 1);
        }
        if (width < 60) width = 60;
        if (height < 20) height = 20;

        // Render Frame
        std::wstring frame;
        frame.reserve(width * height * 4);
        frame += L"\x1b[H";

        switch (model.get_current_screen()) {
            case TuiScreen::List:
                render_list_screen(model, width, height, frame, spinner_idx);
                break;
            case TuiScreen::PlanDetails:
                render_plan_screen(model, width, height, frame);
                break;
            case TuiScreen::ConfirmDialog:
                render_confirm_screen(model, width, height, frame);
                break;
            case TuiScreen::Executing:
                render_executing_screen(model, width, height, frame);
                break;
            case TuiScreen::Finished:
                render_finished_screen(model, width, height, frame);
                break;
        }

        DWORD written = 0;
        WriteConsoleW(hOut, frame.data(), static_cast<DWORD>(frame.size()), &written, nullptr);

        // Check if selected app changed in list screen
        if (model.get_current_screen() == TuiScreen::List &&
            model.get_selected_index() != last_selected_idx) {
            last_selected_idx = model.get_selected_index();
            if (const auto* app = model.get_selected_app()) {
                preview_worker.request_preview(*app);
            }
        }

        // Wait for input with timeout so spinner & logs continue updating
        DWORD wait_res = WaitForSingleObject(hIn, 100);
        spinner_idx++;

        if (wait_res == WAIT_OBJECT_0) {
            DWORD num_read = 0;
            INPUT_RECORD ir[32];
            if (ReadConsoleInputW(hIn, ir, 32, &num_read) && num_read > 0) {
                for (DWORD i = 0; i < num_read; ++i) {
                    if (ir[i].EventType == WINDOW_BUFFER_SIZE_EVENT) {
                        // Resized, will re-render next loop iteration
                        continue;
                    }

                    if (ir[i].EventType == MOUSE_EVENT) {
                        if (model.get_current_screen() == TuiScreen::List && !model.is_filtering()) {
                            const auto& me = ir[i].Event.MouseEvent;
                            if (me.dwEventFlags == 0 && (me.dwButtonState & FROM_LEFT_1ST_BUTTON_PRESSED)) {
                                size_t clicked_y = static_cast<size_t>(me.dwMousePosition.Y);
                                size_t clicked_x = static_cast<size_t>(me.dwMousePosition.X);
                                size_t left_w = (width * 55) / 100;
                                if (clicked_y >= 3 && clicked_y < height - 2 && clicked_x < left_w) {
                                    size_t row_idx = clicked_y - 3;
                                    size_t target_idx = model.get_scroll_offset() + row_idx;
                                    model.select_index(target_idx);
                                }
                            }
                        }
                        continue;
                    }

                    if (ir[i].EventType != KEY_EVENT || !ir[i].Event.KeyEvent.bKeyDown) {
                        continue;
                    }

                    const auto& ke = ir[i].Event.KeyEvent;
                    WORD vk = ke.wVirtualKeyCode;
                    wchar_t ch = ke.uChar.UnicodeChar;

                    // Screen: List
                    if (model.get_current_screen() == TuiScreen::List) {
                        if (model.is_filtering()) {
                            if (vk == VK_ESCAPE) {
                                model.end_filter(false);
                            } else if (vk == VK_RETURN) {
                                model.end_filter(true);
                            } else if (vk == VK_BACK) {
                                model.filter_backspace();
                            } else if (ch >= 32) {
                                model.filter_char(ch);
                            }
                        } else {
                            if (vk == VK_UP) {
                                model.move_selection_up();
                            } else if (vk == VK_DOWN) {
                                model.move_selection_down();
                            } else if (vk == VK_PRIOR) {
                                model.page_up(10);
                            } else if (vk == VK_NEXT) {
                                model.page_down(10);
                            } else if (vk == VK_HOME) {
                                model.move_home();
                            } else if (vk == VK_END) {
                                model.move_end();
                            } else if (ch == L's' || ch == L'S') {
                                model.set_sort_mode(SortMode::Size);
                            } else if (ch == L'n' || ch == L'N') {
                                model.set_sort_mode(SortMode::Name);
                            } else if (ch == L'd' || ch == L'D') {
                                model.set_sort_mode(SortMode::Date);
                            } else if (ch == L'/') {
                                model.start_filter();
                            } else if (ch == L'p' || ch == L'P') {
                                model.open_plan_view();
                            } else if (vk == VK_RETURN) {
                                model.open_confirm_dialog();
                            } else if (vk == VK_ESCAPE) {
                                running = false;
                            }
                        }
                    }
                    // Screen: PlanDetails
                    else if (model.get_current_screen() == TuiScreen::PlanDetails) {
                        if (vk == VK_UP) {
                            model.move_plan_up();
                        } else if (vk == VK_DOWN) {
                            model.move_plan_down();
                        } else if (vk == VK_SPACE) {
                            model.toggle_current_plan_item();
                        } else if (vk == VK_ESCAPE) {
                            model.close_plan_view();
                        }
                    }
                    // Screen: ConfirmDialog
                    else if (model.get_current_screen() == TuiScreen::ConfirmDialog) {
                        if (vk == VK_ESCAPE) {
                            model.close_confirm_dialog();
                        } else if (vk == VK_BACK) {
                            model.confirm_input_backspace();
                        } else if (vk == VK_RETURN) {
                            if (model.can_confirm()) {
                                model.start_execution();
                                // Spawn execution thread
                                const auto* app = model.get_selected_app();
                                if (app) {
                                    Target target;
                                    target.name = app->name;
                                    target.root_path = app->root_path;
                                    target.is_uwp = (app->type == AppType::Store);
                                    target.uwp_package_full_name = app->uwp_package_full_name;

                                    std::vector<ScoredArtifact> excluded;
                                    for (const auto& item : model.get_plan_items()) {
                                        if (item.excluded) {
                                            excluded.push_back(item.artifact);
                                        }
                                    }

                                    execution_thread = std::thread([&model, target, options, excluded]() {
                                        FinalReport rep = execute_obliteration(
                                            target,
                                            options,
                                            excluded,
                                            [&model](size_t ph, const std::wstring& nm) {
                                                model.set_phase(ph, nm);
                                            },
                                            [&model](const std::wstring& line) {
                                                model.add_execution_log(line);
                                            },
                                            [&model]() {
                                                return model.is_cancelling();
                                            }
                                        );
                                        model.finish_execution(rep);
                                    });
                                }
                            }
                        } else if (ch >= 32) {
                            model.confirm_input_char(ch);
                        }
                    }
                    // Screen: Executing
                    else if (model.get_current_screen() == TuiScreen::Executing) {
                        if (vk == VK_ESCAPE) {
                            model.cancel_execution();
                        }
                    }
                    // Screen: Finished
                    else if (model.get_current_screen() == TuiScreen::Finished) {
                        if (vk == VK_RETURN || vk == VK_ESCAPE) {
                            running = false;
                        }
                    }
                }
            }
        }
    }

    if (execution_thread.joinable()) {
        execution_thread.join();
    }

    return model.get_final_report().exit_code;
}

} // namespace obliterator
