#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace obliterator {

struct FileStreamInfo {
    std::wstring stream_name;
    uint64_t stream_size = 0;
};

class AdsHelper {
public:
    static std::vector<FileStreamInfo> enumerate_streams(const std::wstring& path);
    static size_t purge_alternate_streams(const std::wstring& path);
};

} // namespace obliterator
