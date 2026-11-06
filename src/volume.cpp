#include "obliterator/volume.hpp"
#include "obliterator/error.hpp"
#include "obliterator/path.hpp"

#include <cwctype>
#include <vector>

namespace obliterator {

std::vector<std::wstring> VolumeManager::get_fixed_drives() {
    std::vector<std::wstring> drives;
    const DWORD len = GetLogicalDriveStringsW(0, nullptr);
    if (len == 0) {
        return drives;
    }

    std::vector<wchar_t> buffer(len + 1, L'\0');
    if (GetLogicalDriveStringsW(len, buffer.data()) == 0) {
        return drives;
    }

    const wchar_t* p = buffer.data();
    while (*p != L'\0') {
        std::wstring root(p);
        if (GetDriveTypeW(root.c_str()) == DRIVE_FIXED) {
            // Normalize to "C:" without trailing backslash
            std::wstring clean = root;
            while (!clean.empty() && (clean.back() == L'\\' || clean.back() == L'/')) {
                clean.pop_back();
            }
            drives.push_back(std::move(clean));
        }
        p += wcslen(p) + 1;
    }
    return drives;
}

std::wstring VolumeManager::get_path_drive(const std::wstring& path) {
    std::wstring p = path;
    if (p.starts_with(L"\\\\?\\") || p.starts_with(L"\\??\\")) {
        p.erase(0, 4);
    }

    if (p.size() >= 2 && iswalpha(p[0]) && p[1] == L':') {
        std::wstring drive;
        drive.push_back(static_cast<wchar_t>(towupper(p[0])));
        drive.push_back(L':');
        return drive;
    }

    // Attempt volume path name for UNC or volume GUID paths
    wchar_t vol_path[MAX_PATH]{};
    if (GetVolumePathNameW(path.c_str(), vol_path, MAX_PATH)) {
        std::wstring res(vol_path);
        while (!res.empty() && (res.back() == L'\\' || res.back() == L'/')) {
            res.pop_back();
        }
        return res;
    }

    return {};
}

bool VolumeManager::is_same_volume(const std::wstring& path1, const std::wstring& path2) {
    const std::wstring d1 = get_path_drive(path1);
    const std::wstring d2 = get_path_drive(path2);
    if (!d1.empty() && !d2.empty()) {
        return _wcsicmp(d1.c_str(), d2.c_str()) == 0;
    }

    wchar_t v1[MAX_PATH]{};
    wchar_t v2[MAX_PATH]{};
    if (GetVolumePathNameW(path1.c_str(), v1, MAX_PATH) &&
        GetVolumePathNameW(path2.c_str(), v2, MAX_PATH)) {
        return _wcsicmp(v1, v2) == 0;
    }
    return false;
}

Result<uint64_t> VolumeManager::get_free_bytes(const std::wstring& drive_or_path, uint64_t* out_total) {
    std::wstring root = drive_or_path;
    if (root.size() == 2 && iswalpha(root[0]) && root[1] == L':') {
        root += L"\\";
    }

    ULARGE_INTEGER free_bytes_available{};
    ULARGE_INTEGER total_number_of_bytes{};
    ULARGE_INTEGER total_number_of_free_bytes{};

    if (!GetDiskFreeSpaceExW(root.c_str(), &free_bytes_available, &total_number_of_bytes, &total_number_of_free_bytes)) {
        return Win32Error::from_code(GetLastError());
    }

    if (out_total) {
        *out_total = total_number_of_bytes.QuadPart;
    }
    return free_bytes_available.QuadPart;
}

std::vector<VolumeSpaceDelta> VolumeManager::snapshot_volumes() {
    std::vector<VolumeSpaceDelta> snapshots;
    const auto drives = get_fixed_drives();
    snapshots.reserve(drives.size());

    for (const auto& d : drives) {
        uint64_t total = 0;
        auto free_res = get_free_bytes(d, &total);
        if (free_res) {
            VolumeSpaceDelta delta;
            delta.drive = d;
            delta.initial_free_bytes = free_res.value();
            delta.final_free_bytes = delta.initial_free_bytes;
            delta.freed_bytes = 0;
            delta.total_bytes = total;
            snapshots.push_back(std::move(delta));
        }
    }
    return snapshots;
}

std::vector<VolumeSpaceDelta> VolumeManager::compute_deltas(const std::vector<VolumeSpaceDelta>& initial_snapshot) {
    std::vector<VolumeSpaceDelta> result = initial_snapshot;
    for (auto& item : result) {
        uint64_t total = 0;
        auto free_res = get_free_bytes(item.drive, &total);
        if (free_res) {
            item.final_free_bytes = free_res.value();
            item.freed_bytes = static_cast<int64_t>(item.final_free_bytes) - static_cast<int64_t>(item.initial_free_bytes);
            item.total_bytes = total;
        }
    }
    return result;
}

} // namespace obliterator
