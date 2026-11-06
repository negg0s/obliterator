#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include "obliterator/cli.hpp"
#include "obliterator/report.hpp"

#include <string>
#include <vector>

namespace obliterator {

struct BatchTargetResult {
    std::wstring target_name;
    bool success{false};
    bool reboot_required{false};
    int exit_code{0};
    uint64_t bytes_freed{0};
    size_t files_deleted{0};
    size_t keys_deleted{0};
    std::wstring error_message;
};

struct BatchSummary {
    size_t total_targets{0};
    size_t succeeded{0};
    size_t failed{0};
    size_t reboot_required{0};
    uint64_t total_bytes_freed{0};
    std::vector<BatchTargetResult> results;

    void print_text() const;
    void print_json() const;
};

class BatchProcessor {
public:
    // Parses target lines from a plaintext or JSON batch file
    static Result<std::vector<std::wstring>> parse_batch_file(const std::wstring& file_path);

    // Executes uninstallation for all targets in the batch file
    static int run(const CommandLineOptions& options);
};

} // namespace obliterator
