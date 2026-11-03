#pragma once

#include "obliterator/app_type.hpp"
#include "obliterator/confidence_engine.hpp"
#include "obliterator/plan.hpp"
#include "obliterator/report.hpp"

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace obliterator {

enum class SortMode {
    Size,
    Name,
    Date
};

enum class TuiScreen {
    List,
    PlanDetails,
    ConfirmDialog,
    Executing,
    Finished
};

struct TuiAppItem {
    std::wstring name;
    std::wstring publisher;
    std::wstring install_date;
    uint64_t size_bytes{0};
    std::wstring root_path;
    AppType type{AppType::Win32};
    std::wstring uninstall_string;
    std::wstring uwp_package_full_name;

    [[nodiscard]] std::wstring type_string() const {
        switch (type) {
            case AppType::Win32: return L"Win32";
            case AppType::Msi: return L"MSI";
            case AppType::Store: return L"Store";
            case AppType::Portable: return L"Portable";
        }
        return L"Win32";
    }
};

struct PreviewPlan {
    bool ready{false};
    bool calculating{false};
    size_t process_count{0};
    size_t service_count{0};
    size_t task_count{0};
    size_t file_count{0};
    uint64_t total_file_bytes{0};
    size_t registry_key_count{0};
    size_t leftover_count{0};
    std::vector<ScoredArtifact> artifacts;
};

struct PlanItemView {
    ScoredArtifact artifact;
    bool excluded{false};
};

class TuiModel {
public:
    TuiModel() = default;

    void set_apps(std::vector<TuiAppItem> apps);
    [[nodiscard]] const std::vector<TuiAppItem>& get_all_apps() const noexcept { return m_all_apps; }
    [[nodiscard]] const std::vector<size_t>& get_filtered_indices() const noexcept { return m_filtered_indices; }
    [[nodiscard]] size_t get_filtered_count() const noexcept { return m_filtered_indices.size(); }

    [[nodiscard]] const TuiAppItem* get_selected_app() const noexcept;
    [[nodiscard]] size_t get_selected_index() const noexcept { return m_selected_index; }
    [[nodiscard]] size_t get_scroll_offset() const noexcept { return m_scroll_offset; }

    void set_scroll_offset(size_t offset) noexcept { m_scroll_offset = offset; }
    void select_index(size_t index) noexcept;
    void move_selection_up() noexcept;
    void move_selection_down() noexcept;
    void page_up(size_t page_size) noexcept;
    void page_down(size_t page_size) noexcept;
    void move_home() noexcept;
    void move_end() noexcept;

    // Sorting
    void set_sort_mode(SortMode mode);
    [[nodiscard]] SortMode get_sort_mode() const noexcept { return m_sort_mode; }

    // Live filtering
    void start_filter() noexcept;
    void filter_char(wchar_t ch);
    void filter_backspace();
    void end_filter(bool accept);
    [[nodiscard]] bool is_filtering() const noexcept { return m_is_filtering; }
    [[nodiscard]] const std::wstring& get_filter_query() const noexcept { return m_filter_query; }

    // Screen navigation
    [[nodiscard]] TuiScreen get_current_screen() const noexcept { return m_current_screen; }
    void set_current_screen(TuiScreen screen) noexcept { m_current_screen = screen; }

    // Plan Details View
    void open_plan_view();
    void close_plan_view() noexcept;
    void move_plan_up() noexcept;
    void move_plan_down() noexcept;
    void toggle_plan_item_exclusion(size_t idx);
    void toggle_current_plan_item();
    [[nodiscard]] const std::vector<PlanItemView>& get_plan_items() const noexcept { return m_plan_items; }
    [[nodiscard]] size_t get_plan_selected_index() const noexcept { return m_plan_selected_index; }
    [[nodiscard]] size_t get_plan_scroll_offset() const noexcept { return m_plan_scroll_offset; }
    void set_plan_scroll_offset(size_t offset) noexcept { m_plan_scroll_offset = offset; }
    void set_plan_items(const std::vector<ScoredArtifact>& artifacts);

    // Confirmation Dialog
    void open_confirm_dialog();
    void close_confirm_dialog() noexcept;
    void confirm_input_char(wchar_t ch);
    void confirm_input_backspace();
    [[nodiscard]] const std::wstring& get_confirm_input() const noexcept { return m_confirm_input; }
    [[nodiscard]] const std::wstring& get_confirm_expected() const noexcept { return m_confirm_expected; }
    [[nodiscard]] bool can_confirm() const noexcept;

    // Execution & Progress
    void start_execution() noexcept;
    void cancel_execution() noexcept;
    [[nodiscard]] bool is_cancelling() const noexcept { return m_is_cancelling; }
    void add_execution_log(const std::wstring& line);
    [[nodiscard]] const std::vector<std::wstring>& get_execution_logs() const noexcept { return m_execution_logs; }
    void set_phase(size_t phase, const std::wstring& name) noexcept;
    [[nodiscard]] size_t get_current_phase() const noexcept { return m_current_phase; }
    [[nodiscard]] size_t get_total_phases() const noexcept { return m_total_phases; }
    [[nodiscard]] const std::wstring& get_phase_name() const noexcept { return m_phase_name; }

    void finish_execution(const FinalReport& report) noexcept;
    [[nodiscard]] const FinalReport& get_final_report() const noexcept { return m_final_report; }

    // Background preview plan
    [[nodiscard]] const PreviewPlan& get_preview_plan() const noexcept { return m_preview_plan; }
    void set_preview_plan(const PreviewPlan& plan) noexcept { m_preview_plan = plan; }
    void set_preview_calculating(bool calculating) noexcept { m_preview_plan.calculating = calculating; }

private:
    void update_filtered_list();
    void sort_filtered_list();

    std::vector<TuiAppItem> m_all_apps;
    std::vector<size_t> m_filtered_indices;
    size_t m_selected_index{0};
    size_t m_scroll_offset{0};

    SortMode m_sort_mode{SortMode::Size};
    std::wstring m_filter_query;
    bool m_is_filtering{false};

    TuiScreen m_current_screen{TuiScreen::List};

    PreviewPlan m_preview_plan;
    std::vector<PlanItemView> m_plan_items;
    size_t m_plan_selected_index{0};
    size_t m_plan_scroll_offset{0};

    std::wstring m_confirm_input;
    std::wstring m_confirm_expected;

    bool m_is_cancelling{false};
    size_t m_current_phase{0};
    size_t m_total_phases{9};
    std::wstring m_phase_name;
    std::vector<std::wstring> m_execution_logs;
    FinalReport m_final_report;
};

} // namespace obliterator
