#include "obliterator/error.hpp"

#include <vector>

namespace obliterator {

static std::wstring format_system_message(DWORD code) noexcept {
    LPWSTR buffer = nullptr;
    const DWORD flags = FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
                        FORMAT_MESSAGE_IGNORE_INSERTS;

    const DWORD length = FormatMessageW(flags, nullptr, code,
                                        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                                        reinterpret_cast<LPWSTR>(&buffer), 0, nullptr);

    if (length == 0 || buffer == nullptr) {
        return L"Win32 error " + std::to_wstring(code);
    }

    std::wstring message(buffer, length);
    LocalFree(buffer);

    while (!message.empty() &&
           (message.back() == L'\r' || message.back() == L'\n' || message.back() == L' ')) {
        message.pop_back();
    }

    return message;
}

Win32Error Win32Error::last() noexcept {
    return from_code(GetLastError());
}

Win32Error Win32Error::from_code(DWORD code) noexcept {
    return Win32Error(code, format_system_message(code));
}

std::string Win32Error::to_string() const {
    if (m_message.empty()) {
        return "Win32 error " + std::to_string(m_code);
    }

    const int needed = WideCharToMultiByte(CP_UTF8, 0, m_message.c_str(),
                                           static_cast<int>(m_message.size()),
                                           nullptr, 0, nullptr, nullptr);
    if (needed <= 0) {
        return "Win32 error " + std::to_string(m_code);
    }

    std::string utf8(static_cast<size_t>(needed), '\0');
    WideCharToMultiByte(CP_UTF8, 0, m_message.c_str(), static_cast<int>(m_message.size()),
                        utf8.data(), needed, nullptr, nullptr);

    return utf8 + " (code " + std::to_string(m_code) + ")";
}

} // namespace obliterator
