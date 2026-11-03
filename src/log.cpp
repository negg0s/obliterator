#include "obliterator/log.hpp"

#include <atomic>
#include <iostream>

namespace obliterator {

static std::atomic<bool> g_verbose{false};
static std::atomic<bool> g_json_mode{false};

void Logger::set_verbose(bool enabled) noexcept {
    g_verbose.store(enabled, std::memory_order_relaxed);
}

bool Logger::is_verbose() noexcept {
    return g_verbose.load(std::memory_order_relaxed);
}

void Logger::set_json_mode(bool enabled) noexcept {
    g_json_mode.store(enabled, std::memory_order_relaxed);
}

bool Logger::is_json_mode() noexcept {
    return g_json_mode.load(std::memory_order_relaxed);
}

void Logger::log(LogLevel level, std::string_view message) {
    if (level == LogLevel::Debug && !is_verbose()) {
        return;
    }

    std::ostream& stream = (is_json_mode() || level == LogLevel::Error) ? std::cerr : std::cout;

    switch (level) {
    case LogLevel::Debug:
        stream << "[DEBUG] ";
        break;
    case LogLevel::Info:
        stream << "[INFO]  ";
        break;
    case LogLevel::Warn:
        stream << "[WARN]  ";
        break;
    case LogLevel::Error:
        stream << "[ERROR] ";
        break;
    }

    stream << message << '\n';
}

void Logger::log(LogLevel level, std::wstring_view message) {
    if (level == LogLevel::Debug && !is_verbose()) {
        return;
    }

    std::wostream& stream = (is_json_mode() || level == LogLevel::Error) ? std::wcerr : std::wcout;

    switch (level) {
    case LogLevel::Debug:
        stream << L"[DEBUG] ";
        break;
    case LogLevel::Info:
        stream << L"[INFO]  ";
        break;
    case LogLevel::Warn:
        stream << L"[WARN]  ";
        break;
    case LogLevel::Error:
        stream << L"[ERROR] ";
        break;
    }

    stream << message << L'\n';
}

void Logger::debug(std::string_view message) {
    log(LogLevel::Debug, message);
}

void Logger::debug(std::wstring_view message) {
    log(LogLevel::Debug, message);
}

void Logger::info(std::string_view message) {
    log(LogLevel::Info, message);
}

void Logger::info(std::wstring_view message) {
    log(LogLevel::Info, message);
}

void Logger::warn(std::string_view message) {
    log(LogLevel::Warn, message);
}

void Logger::warn(std::wstring_view message) {
    log(LogLevel::Warn, message);
}

void Logger::error(std::string_view message) {
    log(LogLevel::Error, message);
}

void Logger::error(std::wstring_view message) {
    log(LogLevel::Error, message);
}

} // namespace obliterator
