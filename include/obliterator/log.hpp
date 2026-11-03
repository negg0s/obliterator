#pragma once

#include <string_view>

namespace obliterator {

enum class LogLevel {
    Debug,
    Info,
    Warn,
    Error
};

class Logger {
public:
    static void set_verbose(bool enabled) noexcept;
    static bool is_verbose() noexcept;

    static void log(LogLevel level, std::string_view message);
    static void log(LogLevel level, std::wstring_view message);

    static void debug(std::string_view message);
    static void debug(std::wstring_view message);

    static void info(std::string_view message);
    static void info(std::wstring_view message);

    static void warn(std::string_view message);
    static void warn(std::wstring_view message);

    static void error(std::string_view message);
    static void error(std::wstring_view message);
};

} // namespace obliterator
