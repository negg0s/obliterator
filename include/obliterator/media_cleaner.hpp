#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include "obliterator/target.hpp"

#include <string>
#include <vector>

namespace obliterator {

struct MediaCleanReport {
    size_t directshow_filters_removed{0};
    size_t mf_transforms_removed{0};
    size_t bytestream_handlers_removed{0};
    std::vector<std::wstring> details;
};

class MediaCleaner {
public:
    static MediaCleanReport clean_media_artifacts(const Target& target, bool dry_run);

private:
    static bool matches_target(const std::wstring& name, const Target& target);
    static bool path_references_target(const std::wstring& path, const Target& target);
    static bool inspect_inproc_server(HKEY root, const std::wstring& clsid_str, const Target& target);
};

} // namespace obliterator
