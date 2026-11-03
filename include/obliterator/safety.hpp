#pragma once

#include "obliterator/result.hpp"

#include <string>
#include <vector>

namespace obliterator {

struct ProtectedPath {
    std::wstring path;
    std::wstring description;
};

class SafetyValidator {
public:
    static std::vector<ProtectedPath> get_protected_paths();
    static std::wstring normalize_path(const std::wstring& raw_path);
    static Result<void> validate_path(const std::wstring& raw_path);
    static bool is_drive_root(const std::wstring& normalized_path);
    static bool is_protected_path(const std::wstring& raw_path);
};

} // namespace obliterator
