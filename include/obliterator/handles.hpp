#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

namespace obliterator {

class UniqueHandle {
public:
    constexpr UniqueHandle() noexcept : m_handle(INVALID_HANDLE_VALUE) {}

    explicit UniqueHandle(HANDLE h) noexcept : m_handle(h) {}

    ~UniqueHandle() noexcept {
        reset();
    }

    UniqueHandle(const UniqueHandle&) = delete;
    UniqueHandle& operator=(const UniqueHandle&) = delete;

    UniqueHandle(UniqueHandle&& other) noexcept : m_handle(other.m_handle) {
        other.m_handle = INVALID_HANDLE_VALUE;
    }

    UniqueHandle& operator=(UniqueHandle&& other) noexcept {
        if (this != &other) {
            reset();
            m_handle = other.m_handle;
            other.m_handle = INVALID_HANDLE_VALUE;
        }
        return *this;
    }

    [[nodiscard]] bool is_valid() const noexcept {
        return m_handle != nullptr && m_handle != INVALID_HANDLE_VALUE;
    }

    [[nodiscard]] explicit operator bool() const noexcept {
        return is_valid();
    }

    [[nodiscard]] HANDLE get() const noexcept {
        return m_handle;
    }

    [[nodiscard]] HANDLE release() noexcept {
        HANDLE h = m_handle;
        m_handle = INVALID_HANDLE_VALUE;
        return h;
    }

    void reset(HANDLE h = INVALID_HANDLE_VALUE) noexcept {
        if (m_handle != h) {
            if (is_valid()) {
                CloseHandle(m_handle);
            }
            m_handle = h;
        }
    }

    [[nodiscard]] HANDLE* put() noexcept {
        reset();
        return &m_handle;
    }

private:
    HANDLE m_handle;
};

class UniqueHKey {
public:
    constexpr UniqueHKey() noexcept : m_key(nullptr) {}

    explicit UniqueHKey(HKEY k) noexcept : m_key(k) {}

    ~UniqueHKey() noexcept {
        reset();
    }

    UniqueHKey(const UniqueHKey&) = delete;
    UniqueHKey& operator=(const UniqueHKey&) = delete;

    UniqueHKey(UniqueHKey&& other) noexcept : m_key(other.m_key) {
        other.m_key = nullptr;
    }

    UniqueHKey& operator=(UniqueHKey&& other) noexcept {
        if (this != &other) {
            reset();
            m_key = other.m_key;
            other.m_key = nullptr;
        }
        return *this;
    }

    [[nodiscard]] bool is_valid() const noexcept {
        return m_key != nullptr;
    }

    [[nodiscard]] explicit operator bool() const noexcept {
        return is_valid();
    }

    [[nodiscard]] HKEY get() const noexcept {
        return m_key;
    }

    [[nodiscard]] HKEY release() noexcept {
        HKEY k = m_key;
        m_key = nullptr;
        return k;
    }

    void reset(HKEY k = nullptr) noexcept {
        if (m_key != k) {
            if (m_key != nullptr) {
                RegCloseKey(m_key);
            }
            m_key = k;
        }
    }

    [[nodiscard]] HKEY* put() noexcept {
        reset();
        return &m_key;
    }

private:
    HKEY m_key;
};

class UniqueScHandle {
public:
    constexpr UniqueScHandle() noexcept : m_handle(nullptr) {}

    explicit UniqueScHandle(SC_HANDLE h) noexcept : m_handle(h) {}

    ~UniqueScHandle() noexcept {
        reset();
    }

    UniqueScHandle(const UniqueScHandle&) = delete;
    UniqueScHandle& operator=(const UniqueScHandle&) = delete;

    UniqueScHandle(UniqueScHandle&& other) noexcept : m_handle(other.m_handle) {
        other.m_handle = nullptr;
    }

    UniqueScHandle& operator=(UniqueScHandle&& other) noexcept {
        if (this != &other) {
            reset();
            m_handle = other.m_handle;
            other.m_handle = nullptr;
        }
        return *this;
    }

    [[nodiscard]] bool is_valid() const noexcept {
        return m_handle != nullptr;
    }

    [[nodiscard]] explicit operator bool() const noexcept {
        return is_valid();
    }

    [[nodiscard]] SC_HANDLE get() const noexcept {
        return m_handle;
    }

    [[nodiscard]] SC_HANDLE release() noexcept {
        SC_HANDLE h = m_handle;
        m_handle = nullptr;
        return h;
    }

    void reset(SC_HANDLE h = nullptr) noexcept {
        if (m_handle != h) {
            if (m_handle != nullptr) {
                CloseServiceHandle(m_handle);
            }
            m_handle = h;
        }
    }

    [[nodiscard]] SC_HANDLE* put() noexcept {
        reset();
        return &m_handle;
    }

private:
    SC_HANDLE m_handle;
};

} // namespace obliterator
