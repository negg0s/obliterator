#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include "obliterator/result.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace obliterator {

struct VolumeSpaceDelta {
    std::wstring drive;
    uint64_t initial_free_bytes{0};
    uint64_t final_free_bytes{0};
    int64_t freed_bytes{0};
    uint64_t total_bytes{0};
};

class VolumeManager {
public:
    // Enumerates all fixed disk drives (e.g. "C:", "D:")
    static std::vector<std::wstring> get_fixed_drives();

    // Extracts normalized drive letter ("C:") or volume root from any path
    static std::wstring get_path_drive(const std::wstring& path);

    // Determines if two paths reside on the exact same drive volume
    static bool is_same_volume(const std::wstring& path1, const std::wstring& path2);

    // Queries available free bytes and total bytes for a path or drive
    static Result<uint64_t> get_free_bytes(const std::wstring& drive_or_path, uint64_t* out_total = nullptr);

    // Takes a snapshot of free and total space for all fixed drives
    static std::vector<VolumeSpaceDelta> snapshot_volumes();

    // Re-checks volumes and computes bytes freed delta
    static std::vector<VolumeSpaceDelta> compute_deltas(const std::vector<VolumeSpaceDelta>& initial_snapshot);
};

} // namespace obliterator
