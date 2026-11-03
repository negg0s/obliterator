#include "obliterator/tui_model.hpp"

#include <algorithm>
#include <cwctype>

namespace obliterator {

static std::wstring to_lower(std::wstring_view str) {
    std::wstring result;
    result.reserve(str.size());
    for (wchar_t ch : str) {
        result.push_back(static_cast<wchar_t>(std::towlower(ch)));
    }
    return result;
}

void TuiModel::set_apps(std::vector<TuiAppItem> apps) {
    m_all_apps = std::move(apps);
    update_filtered_list();
    m_selected_index = 0;
    m_scroll_offset = 0;
}

const TuiAppItem* TuiModel::get_selected_app() const noexcept {
    if (m_filtered_indices.empty() || m_selected_index >= m_filtered_indices.size()) {
        return nullptr;
    }
    size_t app_idx = m_filtered_indices[m_selected_index];
    if (app_idx >= m_all_apps.size()) {
        return nullptr;
    }
    return &m_all_apps[app_idx];
}

void TuiModel::select_index(size_t index) noexcept {
    if (m_filtered_indices.empty()) {
        m_selected_index = 0;
        m_scroll_offset = 0;
        return;
    }
    if (index >= m_filtered_indices.size()) {
        index = m_filtered_indices.size() - 1;
    }
    m_selected_index = index;
}

void TuiModel::move_selection_up() noexcept {
    if (m_filtered_indices.empty()) {
        return;
    }
    if (m_selected_index > 0) {
        m_selected_index--;
        if (m_selected_index < m_scroll_offset) {
            m_scroll_offset = m_selected_index;
        }
    }
}

void TuiModel::move_selection_down() noexcept {
    if (m_filtered_indices.empty()) {
        return;
    }
    if (m_selected_index + 1 < m_filtered_indices.size()) {
        m_selected_index++;
    }
}

void TuiModel::page_up(size_t page_size) noexcept {
    if (m_filtered_indices.empty() || page_size == 0) {
        return;
    }
    if (m_selected_index > page_size) {
        m_selected_index -= page_size;
    } else {
        m_selected_index = 0;
    }
    if (m_selected_index < m_scroll_offset) {
        m_scroll_offset = m_selected_index;
    }
}

void TuiModel::page_down(size_t page_size) noexcept {
    if (m_filtered_indices.empty() || page_size == 0) {
        return;
    }
    m_selected_index += page_size;
    if (m_selected_index >= m_filtered_indices.size()) {
        m_selected_index = m_filtered_indices.size() - 1;
    }
}

void TuiModel::move_home() noexcept {
    m_selected_index = 0;
    m_scroll_offset = 0;
}

void TuiModel::move_end() noexcept {
    if (!m_filtered_indices.empty()) {
        m_selected_index = m_filtered_indices.size() - 1;
    }
}

void TuiModel::set_sort_mode(SortMode mode) {
    if (m_sort_mode != mode) {
        m_sort_mode = mode;
        sort_filtered_list();
    }
}

void TuiModel::start_filter() noexcept {
    m_is_filtering = true;
}

void TuiModel::filter_char(wchar_t ch) {
    m_filter_query.push_back(ch);
    update_filtered_list();
}

void TuiModel::filter_backspace() {
    if (!m_filter_query.empty()) {
        m_filter_query.pop_back();
        update_filtered_list();
    }
}

void TuiModel::end_filter(bool accept) {
    m_is_filtering = false;
    if (!accept) {
        m_filter_query.clear();
        update_filtered_list();
    }
}

void TuiModel::update_filtered_list() {
    m_filtered_indices.clear();
    const std::wstring query = to_lower(m_filter_query);

    for (size_t i = 0; i < m_all_apps.size(); ++i) {
        if (query.empty()) {
            m_filtered_indices.push_back(i);
            continue;
        }

        const auto& app = m_all_apps[i];
        if (to_lower(app.name).find(query) != std::wstring::npos ||
            to_lower(app.publisher).find(query) != std::wstring::npos ||
            to_lower(app.root_path).find(query) != std::wstring::npos) {
            m_filtered_indices.push_back(i);
        }
    }

    sort_filtered_list();

    if (m_filtered_indices.empty()) {
        m_selected_index = 0;
        m_scroll_offset = 0;
    } else if (m_selected_index >= m_filtered_indices.size()) {
        m_selected_index = m_filtered_indices.size() - 1;
    }
}

void TuiModel::sort_filtered_list() {
    std::sort(m_filtered_indices.begin(), m_filtered_indices.end(), [this](size_t a_idx, size_t b_idx) {
        const auto& a = m_all_apps[a_idx];
        const auto& b = m_all_apps[b_idx];

        switch (m_sort_mode) {
            case SortMode::Size:
                if (a.size_bytes != b.size_bytes) {
                    return a.size_bytes > b.size_bytes;
                }
                return _wcsicmp(a.name.c_str(), b.name.c_str()) < 0;

            case SortMode::Name:
                return _wcsicmp(a.name.c_str(), b.name.c_str()) < 0;

            case SortMode::Date:
                if (a.install_date != b.install_date) {
                    return a.install_date > b.install_date;
                }
                return _wcsicmp(a.name.c_str(), b.name.c_str()) < 0;
        }
        return false;
    });
}

void TuiModel::open_plan_view() {
    m_current_screen = TuiScreen::PlanDetails;
    m_plan_selected_index = 0;
    m_plan_scroll_offset = 0;
    m_plan_items.clear();
    for (const auto& art : m_preview_plan.artifacts) {
        m_plan_items.push_back({art, false});
    }
}

void TuiModel::close_plan_view() noexcept {
    m_current_screen = TuiScreen::List;
}

void TuiModel::move_plan_up() noexcept {
    if (m_plan_items.empty()) {
        return;
    }
    if (m_plan_selected_index > 0) {
        m_plan_selected_index--;
        if (m_plan_selected_index < m_plan_scroll_offset) {
            m_plan_scroll_offset = m_plan_selected_index;
        }
    }
}

void TuiModel::move_plan_down() noexcept {
    if (m_plan_items.empty()) {
        return;
    }
    if (m_plan_selected_index + 1 < m_plan_items.size()) {
        m_plan_selected_index++;
    }
}

void TuiModel::toggle_plan_item_exclusion(size_t idx) {
    if (idx < m_plan_items.size()) {
        m_plan_items[idx].excluded = !m_plan_items[idx].excluded;
    }
}

void TuiModel::toggle_current_plan_item() {
    if (m_plan_selected_index < m_plan_items.size()) {
        m_plan_items[m_plan_selected_index].excluded = !m_plan_items[m_plan_selected_index].excluded;
    }
}

void TuiModel::set_plan_items(const std::vector<ScoredArtifact>& artifacts) {
    m_plan_items.clear();
    for (const auto& art : artifacts) {
        m_plan_items.push_back({art, false});
    }
    m_plan_selected_index = 0;
    m_plan_scroll_offset = 0;
}

void TuiModel::open_confirm_dialog() {
    const auto* app = get_selected_app();
    if (!app) {
        return;
    }
    m_confirm_expected = app->name;
    m_confirm_input.clear();
    m_current_screen = TuiScreen::ConfirmDialog;
}

void TuiModel::close_confirm_dialog() noexcept {
    m_current_screen = TuiScreen::List;
    m_confirm_input.clear();
}

void TuiModel::confirm_input_char(wchar_t ch) {
    m_confirm_input.push_back(ch);
}

void TuiModel::confirm_input_backspace() {
    if (!m_confirm_input.empty()) {
        m_confirm_input.pop_back();
    }
}

bool TuiModel::can_confirm() const noexcept {
    return (!m_confirm_expected.empty()) &&
           (_wcsicmp(m_confirm_input.c_str(), m_confirm_expected.c_str()) == 0);
}

void TuiModel::start_execution() noexcept {
    m_current_screen = TuiScreen::Executing;
    m_is_cancelling = false;
    m_current_phase = 0;
    m_phase_name = L"Initializing";
    m_execution_logs.clear();
}

void TuiModel::cancel_execution() noexcept {
    m_is_cancelling = true;
}

void TuiModel::add_execution_log(const std::wstring& line) {
    m_execution_logs.push_back(line);
}

void TuiModel::set_phase(size_t phase, const std::wstring& name) noexcept {
    m_current_phase = phase;
    m_phase_name = name;
}

void TuiModel::finish_execution(const FinalReport& report) noexcept {
    m_final_report = report;
    m_current_screen = TuiScreen::Finished;
}

} // namespace obliterator
