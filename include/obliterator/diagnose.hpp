#pragma once

#include "obliterator/result.hpp"

#include <string>

namespace obliterator {

class SystemDiagnostics {
public:
    static Result<std::wstring> collect_report();
    static Result<void> write_report_to_file(const std::wstring& file_path);
    static std::wstring sanitize_pii(const std::wstring& input);
};

} // namespace obliterator
