#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include <string>

namespace obliterator {

class Win32Error {
public:
    Win32Error() noexcept : m_code(0) {}
    Win32Error(DWORD code, std::wstring message) noexcept
        : m_code(code), m_message(std::move(message)) {}

    [[nodiscard]] DWORD code() const noexcept {
        return m_code;
    }

    [[nodiscard]] const std::wstring& message() const noexcept {
        return m_message;
    }

    [[nodiscard]] std::string to_string() const;

    [[nodiscard]] static Win32Error last() noexcept;
    [[nodiscard]] static Win32Error from_code(DWORD code) noexcept;

private:
    DWORD m_code;
    std::wstring m_message;
};

} // namespace obliterator
