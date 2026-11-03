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

// RAII wrapper for FindFirstFile / FindNextFile handles.
// These handles MUST be closed with FindClose, never CloseHandle.
class UniqueFindHandle {
public:
    constexpr UniqueFindHandle() noexcept : m_handle(INVALID_HANDLE_VALUE) {}

    explicit UniqueFindHandle(HANDLE h) noexcept : m_handle(h) {}

    ~UniqueFindHandle() noexcept {
        reset();
    }

    UniqueFindHandle(const UniqueFindHandle&) = delete;
    UniqueFindHandle& operator=(const UniqueFindHandle&) = delete;

    UniqueFindHandle(UniqueFindHandle&& other) noexcept : m_handle(other.m_handle) {
        other.m_handle = INVALID_HANDLE_VALUE;
    }

    UniqueFindHandle& operator=(UniqueFindHandle&& other) noexcept {
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
                FindClose(m_handle);
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

template <typename T>
class ComPtr {
public:
    constexpr ComPtr() noexcept : m_ptr(nullptr) {}
    explicit ComPtr(T* ptr) noexcept : m_ptr(ptr) {}
    ~ComPtr() noexcept { reset(); }

    ComPtr(const ComPtr&) = delete;
    ComPtr& operator=(const ComPtr&) = delete;

    ComPtr(ComPtr&& other) noexcept : m_ptr(other.m_ptr) { other.m_ptr = nullptr; }
    ComPtr& operator=(ComPtr&& other) noexcept {
        if (this != &other) {
            reset();
            m_ptr = other.m_ptr;
            other.m_ptr = nullptr;
        }
        return *this;
    }

    void reset() noexcept {
        if (m_ptr != nullptr) {
            m_ptr->Release();
            m_ptr = nullptr;
        }
    }

    [[nodiscard]] T* get() const noexcept { return m_ptr; }
    [[nodiscard]] T* operator->() const noexcept { return m_ptr; }
    [[nodiscard]] explicit operator bool() const noexcept { return m_ptr != nullptr; }
    [[nodiscard]] T** put() noexcept {
        reset();
        return &m_ptr;
    }
    [[nodiscard]] void** put_void() noexcept {
        reset();
        return reinterpret_cast<void**>(&m_ptr);
    }

private:
    T* m_ptr;
};

class Wow64FsRedirectionGuard {
public:
    Wow64FsRedirectionGuard() noexcept {
        PVOID old_val = nullptr;
        if (Wow64DisableWow64FsRedirection(&old_val)) {
            m_disabled = true;
            m_old_value = old_val;
        }
    }

    ~Wow64FsRedirectionGuard() noexcept {
        revert();
    }

    Wow64FsRedirectionGuard(const Wow64FsRedirectionGuard&) = delete;
    Wow64FsRedirectionGuard& operator=(const Wow64FsRedirectionGuard&) = delete;

    Wow64FsRedirectionGuard(Wow64FsRedirectionGuard&& other) noexcept
        : m_disabled(other.m_disabled), m_old_value(other.m_old_value) {
        other.m_disabled = false;
        other.m_old_value = nullptr;
    }

    Wow64FsRedirectionGuard& operator=(Wow64FsRedirectionGuard&& other) noexcept {
        if (this != &other) {
            revert();
            m_disabled = other.m_disabled;
            m_old_value = other.m_old_value;
            other.m_disabled = false;
            other.m_old_value = nullptr;
        }
        return *this;
    }

    void revert() noexcept {
        if (m_disabled) {
            Wow64RevertWow64FsRedirection(m_old_value);
            m_disabled = false;
            m_old_value = nullptr;
        }
    }

    [[nodiscard]] bool is_disabled() const noexcept {
        return m_disabled;
    }

private:
    bool m_disabled{false};
    PVOID m_old_value{nullptr};
};

} // namespace obliterator
