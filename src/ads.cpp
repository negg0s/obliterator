#include "obliterator/ads.hpp"
#include "obliterator/handles.hpp"
#include "obliterator/log.hpp"
#include "obliterator/path.hpp"

#include <windows.h>

namespace obliterator {

static std::wstring to_extended_path(const std::wstring& path) {
    if (path.starts_with(L"\\\\?\\")) {
        return path;
    }
    if (path.starts_with(L"\\\\")) {
        return L"\\\\?\\UNC" + path.substr(1);
    }
    return L"\\\\?\\" + path;
}

std::vector<FileStreamInfo> AdsHelper::enumerate_streams(const std::wstring& path) {
    std::vector<FileStreamInfo> streams;
    if (path.empty()) {
        return streams;
    }

    const std::wstring norm_path = to_extended_path(path);
    WIN32_FIND_STREAM_DATA find_data{};
    HANDLE hFind = FindFirstStreamW(norm_path.c_str(), FindStreamInfoStandard, &find_data, 0);
    if (hFind == INVALID_HANDLE_VALUE) {
        return streams;
    }

    do {
        const std::wstring sname = find_data.cStreamName;
        // Skip default unnamed primary data stream "::$DATA"
        if (sname != L"::$DATA") {
            FileStreamInfo info;
            info.stream_name = sname;
            info.stream_size = static_cast<uint64_t>(find_data.StreamSize.QuadPart);
            streams.push_back(std::move(info));
        }
    } while (FindNextStreamW(hFind, &find_data));

    FindClose(hFind);
    return streams;
}

size_t AdsHelper::purge_alternate_streams(const std::wstring& path) {
    if (path.empty()) {
        return 0;
    }

    const auto streams = enumerate_streams(path);
    if (streams.empty()) {
        return 0;
    }

    size_t purged = 0;
    const std::wstring norm_path = to_extended_path(path);

    for (const auto& s : streams) {
        // Construct the full stream path: \\?\C:\path\file.ext:StreamName:$DATA
        const std::wstring stream_full_path = norm_path + s.stream_name;
        if (DeleteFileW(stream_full_path.c_str())) {
            Logger::debug(L"Purged alternate data stream: " + path + s.stream_name);
            purged++;
        } else {
            Logger::debug(L"Failed to delete alternate data stream: " + path + s.stream_name);
        }
    }

    return purged;
}

} // namespace obliterator
