#pragma once

#include "obliterator/cli.hpp"
#include "obliterator/tui_model.hpp"

#include <string>
#include <string_view>

namespace obliterator {

bool is_wide_char(wchar_t ch) noexcept;
size_t display_width(std::wstring_view text) noexcept;
std::wstring truncate_to_width(std::wstring_view text, size_t max_width, std::wstring_view ellipsis = L"...");
std::wstring pad_to_width(std::wstring_view text, size_t target_width, bool align_right = false);

bool is_no_color() noexcept;
std::wstring ansi_reset();
std::wstring ansi_bold();
std::wstring ansi_dim();
std::wstring ansi_invert();
std::wstring ansi_fg(int code);
std::wstring ansi_bg(int code);

bool is_console_interactive() noexcept;

class TuiRunner {
public:
    static int run(CommandLineOptions options);
};

} // namespace obliterator
