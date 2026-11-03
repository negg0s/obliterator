#pragma once

#include "obliterator/error.hpp"

#include <optional>
#include <type_traits>
#include <utility>
#include <variant>

namespace obliterator {

template <typename T, typename E = Win32Error>
class Result {
public:
    static_assert(!std::is_same_v<T, E>, "Result value and error types must differ");

    Result(T val) noexcept(std::is_nothrow_move_constructible_v<T>)
        : m_storage(std::in_place_index<0>, std::move(val)) {}

    Result(E err) noexcept(std::is_nothrow_move_constructible_v<E>)
        : m_storage(std::in_place_index<1>, std::move(err)) {}

    [[nodiscard]] bool has_value() const noexcept {
        return m_storage.index() == 0;
    }

    [[nodiscard]] explicit operator bool() const noexcept {
        return has_value();
    }

    [[nodiscard]] const T& value() const noexcept {
        return std::get<0>(m_storage);
    }

    [[nodiscard]] T& value() noexcept {
        return std::get<0>(m_storage);
    }

    [[nodiscard]] const T* operator->() const noexcept {
        return &value();
    }

    [[nodiscard]] T* operator->() noexcept {
        return &value();
    }

    [[nodiscard]] const T& operator*() const noexcept {
        return value();
    }

    [[nodiscard]] T& operator*() noexcept {
        return value();
    }

    [[nodiscard]] const E& error() const noexcept {
        return std::get<1>(m_storage);
    }

    [[nodiscard]] E& error() noexcept {
        return std::get<1>(m_storage);
    }

private:
    std::variant<T, E> m_storage;
};

template <typename E>
class Result<void, E> {
public:
    Result() noexcept = default;

    Result(E err) noexcept(std::is_nothrow_move_constructible_v<E>)
        : m_error(std::move(err)) {}

    [[nodiscard]] bool has_value() const noexcept {
        return !m_error.has_value();
    }

    [[nodiscard]] explicit operator bool() const noexcept {
        return has_value();
    }

    [[nodiscard]] const E& error() const noexcept {
        return *m_error;
    }

    [[nodiscard]] E& error() noexcept {
        return *m_error;
    }

    [[nodiscard]] static Result<void, E> success() noexcept {
        return Result<void, E>();
    }

private:
    std::optional<E> m_error;
};

} // namespace obliterator
